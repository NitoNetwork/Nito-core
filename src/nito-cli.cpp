// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/nito-config.h>
#endif

#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <common/url.h>
#include <compat/compat.h>
#include <compat/stdin.h>
#include <policy/feerate.h>
#include <rpc/client.h>
#include <rpc/mining.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <functional>
#include <initializer_list>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>

#ifndef WIN32
#include <unistd.h>
#endif

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include <support/events.h>

// The server returns time values from a mockable system clock, but it is not
// trivial to get the mocked time from the server, nor is it needed for now, so
// just use a plain system_clock.
using CliClock = std::chrono::system_clock;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;
UrlDecodeFn* const URL_DECODE = urlDecode;

static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;
static constexpr int DEFAULT_WAIT_CLIENT_TIMEOUT = 0;
static const bool DEFAULT_NAMED=false;
static const int CONTINUE_EXECUTION=-1;
static constexpr int8_t UNKNOWN_NETWORK{-1};
// See GetNetworkName() in netbase.cpp
static constexpr std::array NETWORKS{"not_publicly_routable", "ipv4", "ipv6", "onion", "i2p", "cjdns", "internal"};
static constexpr std::array NETWORK_SHORT_NAMES{"npr", "ipv4", "ipv6", "onion", "i2p", "cjdns", "int"};
static constexpr std::array UNREACHABLE_NETWORK_IDS{/*not_publicly_routable*/0, /*internal*/6};

/** Default number of blocks to generate for RPC generatetoaddress. */
static const std::string DEFAULT_NBLOCKS = "1";

/** Default -color setting. */
static const std::string DEFAULT_COLOR_SETTING{"auto"};

static void SetupCliArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);

    const auto defaultBaseParams = CreateBaseChainParams(ChainType::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(ChainType::TESTNET);
    const auto signetBaseParams = CreateBaseChainParams(ChainType::SIGNET);
    const auto regtestBaseParams = CreateBaseChainParams(ChainType::REGTEST);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-conf=<file>", strprintf("Specify configuration file. Relative paths will be prefixed by datadir location. (default: %s)", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-generate",
                   strprintf("Generate blocks, equivalent to RPC getnewaddress followed by RPC generatetoaddress. Optional positional integer "
                             "arguments are number of blocks to generate (default: %s) and maximum iterations to try (default: %s), equivalent to "
                             "RPC generatetoaddress nblocks and maxtries arguments. Example: nito-cli -generate 4 1000",
                             DEFAULT_NBLOCKS, DEFAULT_MAX_TRIES),
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-addrinfo", "Get the number of addresses known to the node, per network and total, after filtering for quality and recency. The total number of addresses known to the node may be higher.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-getinfo", "Get general information from the remote server. Note that unlike server-side RPC calls, the output of -getinfo is the result of multiple non-atomic requests. Some entries in the output may represent results from different states (e.g. wallet balance may be as of a different block from the chain state reported)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-netinfo", "Get network peer connection information from the remote server. An optional integer argument from 0 to 4 can be passed for different peers listings (default: 0). Pass \"help\" for detailed help documentation.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    SetupChainParamsBaseOptions(argsman);
    argsman.AddArg("-color=<when>", strprintf("Color setting for CLI output (default: %s). Valid values: always, auto (add color codes when standard output is connected to a terminal and OS is not WIN32), never.", DEFAULT_COLOR_SETTING), ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-named", strprintf("Pass named instead of positional arguments (default: %s)", DEFAULT_NAMED), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcclienttimeout=<n>", strprintf("Timeout in seconds during HTTP requests, or 0 for no timeout. (default: %d)", DEFAULT_HTTP_CLIENT_TIMEOUT), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcconnect=<ip>", strprintf("Send commands to node running on <ip> (default: %s)", DEFAULT_RPCCONNECT), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpccookiefile=<loc>", "Location of the auth cookie. Relative paths will be prefixed by a net-specific datadir location. (default: data dir)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcpassword=<pw>", "Password for JSON-RPC connections", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcport=<port>", strprintf("Connect to JSON-RPC on <port> (default: %u, testnet: %u, signet: %u, regtest: %u)", defaultBaseParams->RPCPort(), testnetBaseParams->RPCPort(), signetBaseParams->RPCPort(), regtestBaseParams->RPCPort()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcuser=<user>", "Username for JSON-RPC connections", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcwait", "Wait for RPC server to start", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcwaittimeout=<n>", strprintf("Timeout in seconds to wait for the RPC server to start, or 0 for no timeout. (default: %d)", DEFAULT_WAIT_CLIENT_TIMEOUT), ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcwallet=<walletname>", "Send RPC for non-default wallet on RPC server (needs to exactly match corresponding -wallet option passed to nitod). This changes the RPC endpoint used, e.g. http://127.0.0.1:8332/wallet/<walletname>", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-stdin", "Read extra arguments from standard input without terminal echo, one per line until EOF/Ctrl-D. This compatibility mode is intended for protected automation; human terminal use should prefer -named -interactive for supported sensitive RPCs. When combined with -stdinrpcpass, the first line from standard input is used for the RPC password.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-interactive", "Guide the documented sensitive or high-impact RPCs through human-readable choices, hidden private-authority entry, and explicit confirmation. Use with -named. Protected values are never placed in command-line arguments. This finite mode covers recovery, signing, descriptor-bearing, disclosure, backup, and backup-changing wallet operations; it is not a prompt wrapper for every RPC. It cannot be combined with -stdin or -stdinwalletpassphrase.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-stdinrpcpass", "Read RPC password from standard input as a single line. When combined with -stdin, the first line from standard input is used for the RPC password. When combined with -stdinwalletpassphrase, -stdinrpcpass consumes the first line, and -stdinwalletpassphrase consumes the second.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-stdinwalletpassphrase", "Read wallet passphrase from standard input as a single line for protected automation and compatibility. Human terminal use should prefer -named -interactive walletpassphrase. When combined with -stdin, the first line from standard input is used for the wallet passphrase.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
}

/** libevent event log callback */
static void libevent_log_cb(int severity, const char *msg)
{
    // Ignore everything other than errors
    if (severity >= EVENT_LOG_ERR) {
        throw std::runtime_error(strprintf("libevent error: %s", msg));
    }
}

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

//
// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
//
static int AppInitRPC(int argc, char* argv[])
{
    SetupCliArgs(gArgs);
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }
    if (argc < 2 || HelpRequested(gArgs) || gArgs.IsArgSet("-version")) {
        std::string strUsage = PACKAGE_NAME " RPC client version " + FormatFullVersion() + "\n";

        if (gArgs.IsArgSet("-version")) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "Usage:  nito-cli [options] <command> [params]  Send command to " PACKAGE_NAME "\n"
                "or:     nito-cli [options] -named <command> [name=value]...  Send command to " PACKAGE_NAME " (with named arguments)\n"
                "or:     nito-cli [options] help                List commands\n"
                "or:     nito-cli [options] help <command>      Get help for a command\n";
            strUsage += "\n" + gArgs.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);
        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    if (!CheckDataDirOption(gArgs)) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", gArgs.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    if (!gArgs.ReadConfigFiles(error, true)) {
        tfm::format(std::cerr, "Error reading configuration file: %s\n", error);
        return EXIT_FAILURE;
    }
    // Check for chain settings (BaseParams() calls are only valid after this clause)
    try {
        SelectBaseParams(gArgs.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }
    return CONTINUE_EXECUTION;
}


/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply() = default;

    int status{0};
    int error{-1};
    std::string body;
};

static std::string http_errorstring(int code)
{
    switch(code) {
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == nullptr) {
        /* If req is nullptr, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}

/** Class that handles the conversion from a command-line to a JSON-RPC request,
 * as well as converting back to a JSON object that can be shown as result.
 */
class BaseRequestHandler
{
public:
    virtual ~BaseRequestHandler() = default;
    virtual UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) = 0;
    virtual UniValue ProcessReply(const UniValue &batch_in) = 0;
};

/** Process addrinfo requests */
class AddrinfoRequestHandler : public BaseRequestHandler
{
private:
    int8_t NetworkStringToId(const std::string& str) const
    {
        for (size_t i = 0; i < NETWORKS.size(); ++i) {
            if (str == NETWORKS[i]) return i;
        }
        return UNKNOWN_NETWORK;
    }

public:
    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        if (!args.empty()) {
            throw std::runtime_error("-addrinfo takes no arguments");
        }
        UniValue params{RPCConvertValues("getnodeaddresses", std::vector<std::string>{{"0"}})};
        return JSONRPCRequestObj("getnodeaddresses", params, 1);
    }

    UniValue ProcessReply(const UniValue& reply) override
    {
        if (!reply["error"].isNull()) return reply;
        const std::vector<UniValue>& nodes{reply["result"].getValues()};
        if (!nodes.empty() && nodes.at(0)["network"].isNull()) {
            throw std::runtime_error("-addrinfo requires nitod server to be running v22.0 and up");
        }
        // Count the number of peers known to our node, by network.
        std::array<uint64_t, NETWORKS.size()> counts{{}};
        for (const UniValue& node : nodes) {
            std::string network_name{node["network"].get_str()};
            const int8_t network_id{NetworkStringToId(network_name)};
            if (network_id == UNKNOWN_NETWORK) continue;
            ++counts.at(network_id);
        }
        // Prepare result to return to user.
        UniValue result{UniValue::VOBJ}, addresses{UniValue::VOBJ};
        uint64_t total{0}; // Total address count
        for (size_t i = 1; i < NETWORKS.size() - 1; ++i) {
            addresses.pushKV(NETWORKS[i], counts.at(i));
            total += counts.at(i);
        }
        addresses.pushKV("total", total);
        result.pushKV("addresses_known", addresses);
        return JSONRPCReplyObj(result, NullUniValue, 1);
    }
};

/** Process getinfo requests */
class GetinfoRequestHandler: public BaseRequestHandler
{
public:
    const int ID_NETWORKINFO = 0;
    const int ID_BLOCKCHAININFO = 1;
    const int ID_WALLETINFO = 2;
    const int ID_BALANCES = 3;

    /** Create a simulated `getinfo` request. */
    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        if (!args.empty()) {
            throw std::runtime_error("-getinfo takes no arguments");
        }
        UniValue result(UniValue::VARR);
        result.push_back(JSONRPCRequestObj("getnetworkinfo", NullUniValue, ID_NETWORKINFO));
        result.push_back(JSONRPCRequestObj("getblockchaininfo", NullUniValue, ID_BLOCKCHAININFO));
        result.push_back(JSONRPCRequestObj("getwalletinfo", NullUniValue, ID_WALLETINFO));
        result.push_back(JSONRPCRequestObj("getbalances", NullUniValue, ID_BALANCES));
        return result;
    }

    /** Collect values from the batch and form a simulated `getinfo` reply. */
    UniValue ProcessReply(const UniValue &batch_in) override
    {
        UniValue result(UniValue::VOBJ);
        const std::vector<UniValue> batch = JSONRPCProcessBatchReply(batch_in);
        // Errors in getnetworkinfo() and getblockchaininfo() are fatal, pass them on;
        // getwalletinfo() and getbalances() are allowed to fail if there is no wallet.
        if (!batch[ID_NETWORKINFO]["error"].isNull()) {
            return batch[ID_NETWORKINFO];
        }
        if (!batch[ID_BLOCKCHAININFO]["error"].isNull()) {
            return batch[ID_BLOCKCHAININFO];
        }
        result.pushKV("version", batch[ID_NETWORKINFO]["result"]["version"]);
        result.pushKV("blocks", batch[ID_BLOCKCHAININFO]["result"]["blocks"]);
        result.pushKV("headers", batch[ID_BLOCKCHAININFO]["result"]["headers"]);
        result.pushKV("verificationprogress", batch[ID_BLOCKCHAININFO]["result"]["verificationprogress"]);
        result.pushKV("timeoffset", batch[ID_NETWORKINFO]["result"]["timeoffset"]);

        UniValue connections(UniValue::VOBJ);
        connections.pushKV("in", batch[ID_NETWORKINFO]["result"]["connections_in"]);
        connections.pushKV("out", batch[ID_NETWORKINFO]["result"]["connections_out"]);
        connections.pushKV("total", batch[ID_NETWORKINFO]["result"]["connections"]);
        result.pushKV("connections", connections);

        result.pushKV("networks", batch[ID_NETWORKINFO]["result"]["networks"]);
        result.pushKV("difficulty", batch[ID_BLOCKCHAININFO]["result"]["difficulty"]);
        result.pushKV("chain", UniValue(batch[ID_BLOCKCHAININFO]["result"]["chain"]));
        if (!batch[ID_WALLETINFO]["result"].isNull()) {
            result.pushKV("has_wallet", true);
            result.pushKV("keypoolsize", batch[ID_WALLETINFO]["result"]["keypoolsize"]);
            result.pushKV("walletname", batch[ID_WALLETINFO]["result"]["walletname"]);
            if (!batch[ID_WALLETINFO]["result"]["unlocked_until"].isNull()) {
                result.pushKV("unlocked_until", batch[ID_WALLETINFO]["result"]["unlocked_until"]);
            }
            result.pushKV("paytxfee", batch[ID_WALLETINFO]["result"]["paytxfee"]);
        }
        if (!batch[ID_BALANCES]["result"].isNull()) {
            result.pushKV("balance", batch[ID_BALANCES]["result"]["mine"]["trusted"]);
        }
        result.pushKV("relayfee", batch[ID_NETWORKINFO]["result"]["relayfee"]);
        result.pushKV("warnings", batch[ID_NETWORKINFO]["result"]["warnings"]);
        return JSONRPCReplyObj(result, NullUniValue, 1);
    }
};

/** Process netinfo requests */
class NetinfoRequestHandler : public BaseRequestHandler
{
private:
    static constexpr uint8_t MAX_DETAIL_LEVEL{4};
    std::array<std::array<uint16_t, NETWORKS.size() + 1>, 3> m_counts{{{}}}; //!< Peer counts by (in/out/total, networks/total)
    uint8_t m_block_relay_peers_count{0};
    uint8_t m_manual_peers_count{0};
    int8_t NetworkStringToId(const std::string& str) const
    {
        for (size_t i = 0; i < NETWORKS.size(); ++i) {
            if (str == NETWORKS[i]) return i;
        }
        return UNKNOWN_NETWORK;
    }
    uint8_t m_details_level{0}; //!< Optional user-supplied arg to set dashboard details level
    bool DetailsRequested() const { return m_details_level > 0 && m_details_level < 5; }
    bool IsAddressSelected() const { return m_details_level == 2 || m_details_level == 4; }
    bool IsVersionSelected() const { return m_details_level == 3 || m_details_level == 4; }
    bool m_is_asmap_on{false};
    size_t m_max_addr_length{0};
    size_t m_max_addr_processed_length{5};
    size_t m_max_addr_rate_limited_length{6};
    size_t m_max_age_length{5};
    size_t m_max_id_length{2};
    struct Peer {
        std::string addr;
        std::string sub_version;
        std::string conn_type;
        std::string network;
        std::string age;
        std::string transport_protocol_type;
        double min_ping;
        double ping;
        int64_t addr_processed;
        int64_t addr_rate_limited;
        int64_t last_blck;
        int64_t last_recv;
        int64_t last_send;
        int64_t last_trxn;
        int id;
        int mapped_as;
        int version;
        bool is_addr_relay_enabled;
        bool is_bip152_hb_from;
        bool is_bip152_hb_to;
        bool is_outbound;
        bool is_tx_relay;
        bool operator<(const Peer& rhs) const { return std::tie(is_outbound, min_ping) < std::tie(rhs.is_outbound, rhs.min_ping); }
    };
    std::vector<Peer> m_peers;
    std::string ChainToString() const
    {
        switch (gArgs.GetChainType()) {
        case ChainType::TESTNET:
            return " testnet";
        case ChainType::SIGNET:
            return " signet";
        case ChainType::REGTEST:
            return " regtest";
        case ChainType::MAIN:
            return "";
        }
        assert(false);
    }
    std::string PingTimeToString(double seconds) const
    {
        if (seconds < 0) return "";
        const double milliseconds{round(1000 * seconds)};
        return milliseconds > 999999 ? "-" : ToString(milliseconds);
    }
    std::string ConnectionTypeForNetinfo(const std::string& conn_type) const
    {
        if (conn_type == "outbound-full-relay") return "full";
        if (conn_type == "block-relay-only") return "block";
        if (conn_type == "manual" || conn_type == "feeler") return conn_type;
        if (conn_type == "addr-fetch") return "addr";
        return "";
    }

public:
    static constexpr int ID_PEERINFO = 0;
    static constexpr int ID_NETWORKINFO = 1;

    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        if (!args.empty()) {
            uint8_t n{0};
            if (ParseUInt8(args.at(0), &n)) {
                m_details_level = std::min(n, MAX_DETAIL_LEVEL);
            } else {
                throw std::runtime_error(strprintf("invalid -netinfo argument: %s\nFor more information, run: nito-cli -netinfo help", args.at(0)));
            }
        }
        UniValue result(UniValue::VARR);
        result.push_back(JSONRPCRequestObj("getpeerinfo", NullUniValue, ID_PEERINFO));
        result.push_back(JSONRPCRequestObj("getnetworkinfo", NullUniValue, ID_NETWORKINFO));
        return result;
    }

    UniValue ProcessReply(const UniValue& batch_in) override
    {
        const std::vector<UniValue> batch{JSONRPCProcessBatchReply(batch_in)};
        if (!batch[ID_PEERINFO]["error"].isNull()) return batch[ID_PEERINFO];
        if (!batch[ID_NETWORKINFO]["error"].isNull()) return batch[ID_NETWORKINFO];

        const UniValue& networkinfo{batch[ID_NETWORKINFO]["result"]};
        if (networkinfo["version"].getInt<int>() < 209900) {
            throw std::runtime_error("-netinfo requires nitod server to be running v0.21.0 and up");
        }
        const int64_t time_now{TicksSinceEpoch<std::chrono::seconds>(CliClock::now())};

        // Count peer connection totals, and if DetailsRequested(), store peer data in a vector of structs.
        for (const UniValue& peer : batch[ID_PEERINFO]["result"].getValues()) {
            const std::string network{peer["network"].get_str()};
            const int8_t network_id{NetworkStringToId(network)};
            if (network_id == UNKNOWN_NETWORK) continue;
            const bool is_outbound{!peer["inbound"].get_bool()};
            const bool is_tx_relay{peer["relaytxes"].isNull() ? true : peer["relaytxes"].get_bool()};
            const std::string conn_type{peer["connection_type"].get_str()};
            ++m_counts.at(is_outbound).at(network_id);      // in/out by network
            ++m_counts.at(is_outbound).at(NETWORKS.size()); // in/out overall
            ++m_counts.at(2).at(network_id);                // total by network
            ++m_counts.at(2).at(NETWORKS.size());           // total overall
            if (conn_type == "block-relay-only") ++m_block_relay_peers_count;
            if (conn_type == "manual") ++m_manual_peers_count;
            if (DetailsRequested()) {
                // Push data for this peer to the peers vector.
                const int peer_id{peer["id"].getInt<int>()};
                const int mapped_as{peer["mapped_as"].isNull() ? 0 : peer["mapped_as"].getInt<int>()};
                const int version{peer["version"].getInt<int>()};
                const int64_t addr_processed{peer["addr_processed"].isNull() ? 0 : peer["addr_processed"].getInt<int64_t>()};
                const int64_t addr_rate_limited{peer["addr_rate_limited"].isNull() ? 0 : peer["addr_rate_limited"].getInt<int64_t>()};
                const int64_t conn_time{peer["conntime"].getInt<int64_t>()};
                const int64_t last_blck{peer["last_block"].getInt<int64_t>()};
                const int64_t last_recv{peer["lastrecv"].getInt<int64_t>()};
                const int64_t last_send{peer["lastsend"].getInt<int64_t>()};
                const int64_t last_trxn{peer["last_transaction"].getInt<int64_t>()};
                const double min_ping{peer["minping"].isNull() ? -1 : peer["minping"].get_real()};
                const double ping{peer["pingtime"].isNull() ? -1 : peer["pingtime"].get_real()};
                const std::string addr{peer["addr"].get_str()};
                const std::string age{conn_time == 0 ? "" : ToString((time_now - conn_time) / 60)};
                const std::string sub_version{peer["subver"].get_str()};
                const std::string transport{peer["transport_protocol_type"].isNull() ? "v1" : peer["transport_protocol_type"].get_str()};
                const bool is_addr_relay_enabled{peer["addr_relay_enabled"].isNull() ? false : peer["addr_relay_enabled"].get_bool()};
                const bool is_bip152_hb_from{peer["bip152_hb_from"].get_bool()};
                const bool is_bip152_hb_to{peer["bip152_hb_to"].get_bool()};
                m_peers.push_back({addr, sub_version, conn_type, NETWORK_SHORT_NAMES[network_id], age, transport, min_ping, ping, addr_processed, addr_rate_limited, last_blck, last_recv, last_send, last_trxn, peer_id, mapped_as, version, is_addr_relay_enabled, is_bip152_hb_from, is_bip152_hb_to, is_outbound, is_tx_relay});
                m_max_addr_length = std::max(addr.length() + 1, m_max_addr_length);
                m_max_addr_processed_length = std::max(ToString(addr_processed).length(), m_max_addr_processed_length);
                m_max_addr_rate_limited_length = std::max(ToString(addr_rate_limited).length(), m_max_addr_rate_limited_length);
                m_max_age_length = std::max(age.length(), m_max_age_length);
                m_max_id_length = std::max(ToString(peer_id).length(), m_max_id_length);
                m_is_asmap_on |= (mapped_as != 0);
            }
        }

        // Generate report header.
        std::string result{strprintf("%s client %s%s - server %i%s\n\n", PACKAGE_NAME, FormatFullVersion(), ChainToString(), networkinfo["protocolversion"].getInt<int>(), networkinfo["subversion"].get_str())};

        // Report detailed peer connections list sorted by direction and minimum ping time.
        if (DetailsRequested() && !m_peers.empty()) {
            std::sort(m_peers.begin(), m_peers.end());
            result += strprintf("<->   type   net  v  mping   ping send recv  txn  blk  hb %*s%*s%*s ",
                                m_max_addr_processed_length, "addrp",
                                m_max_addr_rate_limited_length, "addrl",
                                m_max_age_length, "age");
            if (m_is_asmap_on) result += " asmap ";
            result += strprintf("%*s %-*s%s\n", m_max_id_length, "id", IsAddressSelected() ? m_max_addr_length : 0, IsAddressSelected() ? "address" : "", IsVersionSelected() ? "version" : "");
            for (const Peer& peer : m_peers) {
                std::string version{ToString(peer.version) + peer.sub_version};
                result += strprintf(
                    "%3s %6s %5s %2s%7s%7s%5s%5s%5s%5s  %2s %*s%*s%*s%*i %*s %-*s%s\n",
                    peer.is_outbound ? "out" : "in",
                    ConnectionTypeForNetinfo(peer.conn_type),
                    peer.network,
                    peer.transport_protocol_type.starts_with('v') ? peer.transport_protocol_type[1] : ' ',
                    PingTimeToString(peer.min_ping),
                    PingTimeToString(peer.ping),
                    peer.last_send ? ToString(time_now - peer.last_send) : "",
                    peer.last_recv ? ToString(time_now - peer.last_recv) : "",
                    peer.last_trxn ? ToString((time_now - peer.last_trxn) / 60) : peer.is_tx_relay ? "" : "*",
                    peer.last_blck ? ToString((time_now - peer.last_blck) / 60) : "",
                    strprintf("%s%s", peer.is_bip152_hb_to ? "." : " ", peer.is_bip152_hb_from ? "*" : " "),
                    m_max_addr_processed_length, // variable spacing
                    peer.addr_processed ? ToString(peer.addr_processed) : peer.is_addr_relay_enabled ? "" : ".",
                    m_max_addr_rate_limited_length, // variable spacing
                    peer.addr_rate_limited ? ToString(peer.addr_rate_limited) : "",
                    m_max_age_length, // variable spacing
                    peer.age,
                    m_is_asmap_on ? 7 : 0, // variable spacing
                    m_is_asmap_on && peer.mapped_as ? ToString(peer.mapped_as) : "",
                    m_max_id_length, // variable spacing
                    peer.id,
                    IsAddressSelected() ? m_max_addr_length : 0, // variable spacing
                    IsAddressSelected() ? peer.addr : "",
                    IsVersionSelected() && version != "0" ? version : "");
            }
            result += strprintf("                        ms     ms  sec  sec  min  min                %*s\n\n", m_max_age_length, "min");
        }

        // Report peer connection totals by type.
        result += "     ";
        std::vector<int8_t> reachable_networks;
        for (const UniValue& network : networkinfo["networks"].getValues()) {
            if (network["reachable"].get_bool()) {
                const std::string& network_name{network["name"].get_str()};
                const int8_t network_id{NetworkStringToId(network_name)};
                if (network_id == UNKNOWN_NETWORK) continue;
                result += strprintf("%8s", network_name); // column header
                reachable_networks.push_back(network_id);
            }
        };

        for (const size_t network_id : UNREACHABLE_NETWORK_IDS) {
            if (m_counts.at(2).at(network_id) == 0) continue;
            result += strprintf("%8s", NETWORK_SHORT_NAMES.at(network_id)); // column header
            reachable_networks.push_back(network_id);
        }

        result += "   total   block";
        if (m_manual_peers_count) result += "  manual";

        const std::array rows{"in", "out", "total"};
        for (size_t i = 0; i < rows.size(); ++i) {
            result += strprintf("\n%-5s", rows[i]); // row header
            for (int8_t n : reachable_networks) {
                result += strprintf("%8i", m_counts.at(i).at(n)); // network peers count
            }
            result += strprintf("   %5i", m_counts.at(i).at(NETWORKS.size())); // total peers count
            if (i == 1) { // the outbound row has two extra columns for block relay and manual peer counts
                result += strprintf("   %5i", m_block_relay_peers_count);
                if (m_manual_peers_count) result += strprintf("   %5i", m_manual_peers_count);
            }
        }

        // Report local addresses, ports, and scores.
        result += "\n\nLocal addresses";
        const std::vector<UniValue>& local_addrs{networkinfo["localaddresses"].getValues()};
        if (local_addrs.empty()) {
            result += ": n/a\n";
        } else {
            size_t max_addr_size{0};
            for (const UniValue& addr : local_addrs) {
                max_addr_size = std::max(addr["address"].get_str().length() + 1, max_addr_size);
            }
            for (const UniValue& addr : local_addrs) {
                result += strprintf("\n%-*s    port %6i    score %6i", max_addr_size, addr["address"].get_str(), addr["port"].getInt<int>(), addr["score"].getInt<int>());
            }
        }

        return JSONRPCReplyObj(UniValue{result}, NullUniValue, 1);
    }

    const std::string m_help_doc{
        "-netinfo level|\"help\" \n\n"
        "Returns a network peer connections dashboard with information from the remote server.\n"
        "This human-readable interface will change regularly and is not intended to be a stable API.\n"
        "Under the hood, -netinfo fetches the data by calling getpeerinfo and getnetworkinfo.\n"
        + strprintf("An optional integer argument from 0 to %d can be passed for different peers listings; %d to 255 are parsed as %d.\n", MAX_DETAIL_LEVEL, MAX_DETAIL_LEVEL, MAX_DETAIL_LEVEL) +
        "Pass \"help\" to see this detailed help documentation.\n"
        "If more than one argument is passed, only the first one is read and parsed.\n"
        "Suggestion: use with the Linux watch(1) command for a live dashboard; see example below.\n\n"
        "Arguments:\n"
        + strprintf("1. level (integer 0-%d, optional)  Specify the info level of the peers dashboard (default 0):\n", MAX_DETAIL_LEVEL) +
        "                                  0 - Peer counts for each reachable network as well as for block relay peers\n"
        "                                      and manual peers, and the list of local addresses and ports\n"
        "                                  1 - Like 0 but preceded by a peers listing (without address and version columns)\n"
        "                                  2 - Like 1 but with an address column\n"
        "                                  3 - Like 1 but with a version column\n"
        "                                  4 - Like 1 but with both address and version columns\n"
        "2. help (string \"help\", optional) Print this help documentation instead of the dashboard.\n\n"
        "Result:\n\n"
        + strprintf("* The peers listing in levels 1-%d displays all of the peers sorted by direction and minimum ping time:\n\n", MAX_DETAIL_LEVEL) +
        "  Column   Description\n"
        "  ------   -----------\n"
        "  <->      Direction\n"
        "           \"in\"  - inbound connections are those initiated by the peer\n"
        "           \"out\" - outbound connections are those initiated by us\n"
        "  type     Type of peer connection\n"
        "           \"full\"   - full relay, the default\n"
        "           \"block\"  - block relay; like full relay but does not relay transactions or addresses\n"
        "           \"manual\" - peer we manually added using RPC addnode or the -addnode/-connect config options\n"
        "           \"feeler\" - short-lived connection for testing addresses\n"
        "           \"addr\"   - address fetch; short-lived connection for requesting addresses\n"
        "  net      Network the peer connected through (\"ipv4\", \"ipv6\", \"onion\", \"i2p\", \"cjdns\", or \"npr\" (not publicly routable))\n"
        "  v        Version of transport protocol used for the connection\n"
        "  mping    Minimum observed ping time, in milliseconds (ms)\n"
        "  ping     Last observed ping time, in milliseconds (ms)\n"
        "  send     Time since last message sent to the peer, in seconds\n"
        "  recv     Time since last message received from the peer, in seconds\n"
        "  txn      Time since last novel transaction received from the peer and accepted into our mempool, in minutes\n"
        "           \"*\" - we do not relay transactions to this peer (relaytxes is false)\n"
        "  blk      Time since last novel block passing initial validity checks received from the peer, in minutes\n"
        "  hb       High-bandwidth BIP152 compact block relay\n"
        "           \".\" (to)   - we selected the peer as a high-bandwidth peer\n"
        "           \"*\" (from) - the peer selected us as a high-bandwidth peer\n"
        "  addrp    Total number of addresses processed, excluding those dropped due to rate limiting\n"
        "           \".\" - we do not relay addresses to this peer (addr_relay_enabled is false)\n"
        "  addrl    Total number of addresses dropped due to rate limiting\n"
        "  age      Duration of connection to the peer, in minutes\n"
        "  asmap    Mapped AS (Autonomous System) number in the BGP route to the peer, used for diversifying\n"
        "           peer selection (only displayed if the -asmap config option is set)\n"
        "  id       Peer index, in increasing order of peer connections since node startup\n"
        "  address  IP address and port of the peer\n"
        "  version  Peer version and subversion concatenated, e.g. \"70016/Satoshi:21.0.0/\"\n\n"
        "* The peer counts table displays the number of peers for each reachable network as well as\n"
        "  the number of block relay peers and manual peers.\n\n"
        "* The local addresses table lists each local address broadcast by the node, the port, and the score.\n\n"
        "Examples:\n\n"
        "Peer counts table of reachable networks and list of local addresses\n"
        "> nito-cli -netinfo\n\n"
        "The same, preceded by a peers listing without address and version columns\n"
        "> nito-cli -netinfo 1\n\n"
        "Full dashboard\n"
        + strprintf("> nito-cli -netinfo %d\n\n", MAX_DETAIL_LEVEL) +
        "Full live dashboard, adjust --interval or --no-title as needed (Linux)\n"
        + strprintf("> watch --interval 1 --no-title nito-cli -netinfo %d\n\n", MAX_DETAIL_LEVEL) +
        "See this help\n"
        "> nito-cli -netinfo help\n"};
};

/** Process RPC generatetoaddress request. */
class GenerateToAddressRequestHandler : public BaseRequestHandler
{
public:
    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        address_str = args.at(1);
        UniValue params{RPCConvertValues("generatetoaddress", args)};
        return JSONRPCRequestObj("generatetoaddress", params, 1);
    }

    UniValue ProcessReply(const UniValue &reply) override
    {
        UniValue result(UniValue::VOBJ);
        result.pushKV("address", address_str);
        result.pushKV("blocks", reply.get_obj()["result"]);
        return JSONRPCReplyObj(result, NullUniValue, 1);
    }
protected:
    std::string address_str;
};

/** Process default single requests */
class DefaultRequestHandler: public BaseRequestHandler {
public:
    UniValue PrepareRequest(const std::string& method, const std::vector<std::string>& args) override
    {
        UniValue params;
        if(gArgs.GetBoolArg("-named", DEFAULT_NAMED)) {
            params = RPCConvertNamedValues(method, args);
        } else {
            params = RPCConvertValues(method, args);
        }
        return JSONRPCRequestObj(method, params, 1);
    }

    UniValue ProcessReply(const UniValue &reply) override
    {
        return reply.get_obj();
    }
};

static UniValue CallRPC(BaseRequestHandler* rh, const std::string& strMethod, const std::vector<std::string>& args, const std::optional<std::string>& rpcwallet = {})
{
    std::string host;
    // In preference order, we choose the following for the port:
    //     1. -rpcport
    //     2. port in -rpcconnect (ie following : in ipv4 or ]: in ipv6)
    //     3. default port for chain
    uint16_t port{BaseParams().RPCPort()};
    SplitHostPort(gArgs.GetArg("-rpcconnect", DEFAULT_RPCCONNECT), port, host);
    port = static_cast<uint16_t>(gArgs.GetIntArg("-rpcport", port));

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);

    // Set connection timeout
    {
        const int timeout = gArgs.GetIntArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT);
        if (timeout > 0) {
            evhttp_connection_set_timeout(evcon.get(), timeout);
        } else {
            // Indefinite request timeouts are not possible in libevent-http, so we
            // set the timeout to a very long time period instead.

            constexpr int YEAR_IN_SECONDS = 31556952; // Average length of year in Gregorian calendar
            evhttp_connection_set_timeout(evcon.get(), 5 * YEAR_IN_SECONDS);
        }
    }

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == nullptr) {
        throw std::runtime_error("create http request failed");
    }

    evhttp_request_set_error_cb(req.get(), http_error_cb);

    // Get credentials
    std::string strRPCUserColonPass;
    bool failedToGetAuthCookie = false;
    if (gArgs.GetArg("-rpcpassword", "") == "") {
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetAuthCookie(&strRPCUserColonPass)) {
            failedToGetAuthCookie = true;
        }
    } else {
        strRPCUserColonPass = gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", "");
    }

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Content-Type", "application/json");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = rh->PrepareRequest(strMethod, args).write() + "\n";
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    // check if we should use a special wallet endpoint
    std::string endpoint = "/";
    if (rpcwallet) {
        char* encodedURI = evhttp_uriencode(rpcwallet->data(), rpcwallet->size(), false);
        if (encodedURI) {
            endpoint = "/wallet/" + std::string(encodedURI);
            free(encodedURI);
        } else {
            throw CConnectionFailed("uri-encode failed");
        }
    }
    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, endpoint.c_str());
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0) {
        std::string responseErrorMessage;
        if (response.error != -1) {
            responseErrorMessage = strprintf(" (error code %d - \"%s\")", response.error, http_errorstring(response.error));
        }
        throw CConnectionFailed(strprintf("Could not connect to the server %s:%d%s\n\nMake sure the nitod server is running and that you are connecting to the correct RPC port.", host, port, responseErrorMessage));
    } else if (response.status == HTTP_UNAUTHORIZED) {
        if (failedToGetAuthCookie) {
            throw std::runtime_error(strprintf(
                "Could not locate RPC credentials. No authentication cookie could be found, and RPC password is not set.  See -rpcpassword and -stdinrpcpass.  Configuration file: (%s)",
                fs::PathToString(gArgs.GetConfigFilePath())));
        } else {
            throw std::runtime_error("Authorization failed: Incorrect rpcuser or rpcpassword");
        }
    } else if (response.status == HTTP_SERVICE_UNAVAILABLE) {
        throw std::runtime_error(strprintf("Server response: %s", response.body));
    } else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    UniValue reply = rh->ProcessReply(valReply);
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

/**
 * ConnectAndCallRPC wraps CallRPC with -rpcwait and an exception handler.
 *
 * @param[in] rh         Pointer to RequestHandler.
 * @param[in] strMethod  Reference to const string method to forward to CallRPC.
 * @param[in] rpcwallet  Reference to const optional string wallet name to forward to CallRPC.
 * @returns the RPC response as a UniValue object.
 * @throws a CConnectionFailed std::runtime_error if connection failed or RPC server still in warmup.
 */
static UniValue ConnectAndCallRPC(BaseRequestHandler* rh, const std::string& strMethod, const std::vector<std::string>& args, const std::optional<std::string>& rpcwallet = {})
{
    UniValue response(UniValue::VOBJ);
    // Execute and handle connection failures with -rpcwait.
    const bool fWait = gArgs.GetBoolArg("-rpcwait", false);
    const int timeout = gArgs.GetIntArg("-rpcwaittimeout", DEFAULT_WAIT_CLIENT_TIMEOUT);
    const auto deadline{std::chrono::steady_clock::now() + 1s * timeout};

    do {
        try {
            response = CallRPC(rh, strMethod, args, rpcwallet);
            if (fWait) {
                const UniValue& error = response.find_value("error");
                if (!error.isNull() && error["code"].getInt<int>() == RPC_IN_WARMUP) {
                    throw CConnectionFailed("server in warmup");
                }
            }
            break; // Connection succeeded, no need to retry.
        } catch (const CConnectionFailed& e) {
            if (fWait && (timeout <= 0 || std::chrono::steady_clock::now() < deadline)) {
                UninterruptibleSleep(1s);
            } else {
                throw CConnectionFailed(strprintf("timeout on transient error: %s", e.what()));
            }
        }
    } while (fWait);
    return response;
}

/** Parse UniValue result to update the message to print to std::cout. */
static void ParseResult(const UniValue& result, std::string& strPrint)
{
    if (result.isNull()) return;
    strPrint = result.isStr() ? result.get_str() : result.write(2);
}

/** Parse UniValue error to update the message to print to std::cerr and the code to return. */
static void ParseError(const UniValue& error, std::string& strPrint, int& nRet)
{
    if (error.isObject()) {
        const UniValue& err_code = error.find_value("code");
        const UniValue& err_msg = error.find_value("message");
        if (!err_code.isNull()) {
            strPrint = "error code: " + err_code.getValStr() + "\n";
        }
        if (err_msg.isStr()) {
            strPrint += ("error message:\n" + err_msg.get_str());
        }
        if (err_code.isNum() && err_code.getInt<int>() == RPC_WALLET_NOT_SPECIFIED) {
            strPrint += "\nTry adding \"-rpcwallet=<filename>\" option to nito-cli command line.";
        }
    } else {
        strPrint = "error: " + error.write();
    }
    nRet = abs(error["code"].getInt<int>());
}

/**
 * GetWalletBalances calls listwallets; if more than one wallet is loaded, it then
 * fetches mine.trusted balances for each loaded wallet and pushes them to `result`.
 *
 * @param result  Reference to UniValue object the wallet names and balances are pushed to.
 */
static void GetWalletBalances(UniValue& result)
{
    DefaultRequestHandler rh;
    const UniValue listwallets = ConnectAndCallRPC(&rh, "listwallets", /* args=*/{});
    if (!listwallets.find_value("error").isNull()) return;
    const UniValue& wallets = listwallets.find_value("result");
    if (wallets.size() <= 1) return;

    UniValue balances(UniValue::VOBJ);
    for (const UniValue& wallet : wallets.getValues()) {
        const std::string& wallet_name = wallet.get_str();
        const UniValue getbalances = ConnectAndCallRPC(&rh, "getbalances", /* args=*/{}, wallet_name);
        const UniValue& balance = getbalances.find_value("result")["mine"]["trusted"];
        balances.pushKV(wallet_name, balance);
    }
    result.pushKV("balances", balances);
}

/**
 * GetProgressBar constructs a progress bar with 5% intervals.
 *
 * @param[in]   progress      The proportion of the progress bar to be filled between 0 and 1.
 * @param[out]  progress_bar  String representation of the progress bar.
 */
static void GetProgressBar(double progress, std::string& progress_bar)
{
    if (progress < 0 || progress > 1) return;

    static constexpr double INCREMENT{0.05};
    static const std::string COMPLETE_BAR{"\u2592"};
    static const std::string INCOMPLETE_BAR{"\u2591"};

    for (int i = 0; i < progress / INCREMENT; ++i) {
        progress_bar += COMPLETE_BAR;
    }

    for (int i = 0; i < (1 - progress) / INCREMENT; ++i) {
        progress_bar += INCOMPLETE_BAR;
    }
}

/**
 * ParseGetInfoResult takes in -getinfo result in UniValue object and parses it
 * into a user friendly UniValue string to be printed on the console.
 * @param[out] result  Reference to UniValue result containing the -getinfo output.
 */
static void ParseGetInfoResult(UniValue& result)
{
    if (!result.find_value("error").isNull()) return;

    std::string RESET, GREEN, BLUE, YELLOW, MAGENTA, CYAN;
    bool should_colorize = false;

#ifndef WIN32
    if (isatty(fileno(stdout))) {
        // By default, only print colored text if OS is not WIN32 and stdout is connected to a terminal.
        should_colorize = true;
    }
#endif

    if (gArgs.IsArgSet("-color")) {
        const std::string color{gArgs.GetArg("-color", DEFAULT_COLOR_SETTING)};
        if (color == "always") {
            should_colorize = true;
        } else if (color == "never") {
            should_colorize = false;
        } else if (color != "auto") {
            throw std::runtime_error("Invalid value for -color option. Valid values: always, auto, never.");
        }
    }

    if (should_colorize) {
        RESET = "\x1B[0m";
        GREEN = "\x1B[32m";
        BLUE = "\x1B[34m";
        YELLOW = "\x1B[33m";
        MAGENTA = "\x1B[35m";
        CYAN = "\x1B[36m";
    }

    std::string result_string = strprintf("%sChain: %s%s\n", BLUE, result["chain"].getValStr(), RESET);
    result_string += strprintf("Blocks: %s\n", result["blocks"].getValStr());
    result_string += strprintf("Headers: %s\n", result["headers"].getValStr());

    const double ibd_progress{result["verificationprogress"].get_real()};
    std::string ibd_progress_bar;
    // Display the progress bar only if IBD progress is less than 99%
    if (ibd_progress < 0.99) {
      GetProgressBar(ibd_progress, ibd_progress_bar);
      // Add padding between progress bar and IBD progress
      ibd_progress_bar += " ";
    }

    result_string += strprintf("Verification progress: %s%.4f%%\n", ibd_progress_bar, ibd_progress * 100);
    result_string += strprintf("Difficulty: %s\n\n", result["difficulty"].getValStr());

    result_string += strprintf(
        "%sNetwork: in %s, out %s, total %s%s\n",
        GREEN,
        result["connections"]["in"].getValStr(),
        result["connections"]["out"].getValStr(),
        result["connections"]["total"].getValStr(),
        RESET);
    result_string += strprintf("Version: %s\n", result["version"].getValStr());
    result_string += strprintf("Time offset (s): %s\n", result["timeoffset"].getValStr());

    // proxies
    std::map<std::string, std::vector<std::string>> proxy_networks;
    std::vector<std::string> ordered_proxies;

    for (const UniValue& network : result["networks"].getValues()) {
        const std::string proxy = network["proxy"].getValStr();
        if (proxy.empty()) continue;
        // Add proxy to ordered_proxy if has not been processed
        if (proxy_networks.find(proxy) == proxy_networks.end()) ordered_proxies.push_back(proxy);

        proxy_networks[proxy].push_back(network["name"].getValStr());
    }

    std::vector<std::string> formatted_proxies;
    formatted_proxies.reserve(ordered_proxies.size());
    for (const std::string& proxy : ordered_proxies) {
        formatted_proxies.emplace_back(strprintf("%s (%s)", proxy, Join(proxy_networks.find(proxy)->second, ", ")));
    }
    result_string += strprintf("Proxies: %s\n", formatted_proxies.empty() ? "n/a" : Join(formatted_proxies, ", "));

    result_string += strprintf("Min tx relay fee rate (%s/kvB): %s\n\n", CURRENCY_UNIT, result["relayfee"].getValStr());

    if (!result["has_wallet"].isNull()) {
        const std::string walletname = result["walletname"].getValStr();
        result_string += strprintf("%sWallet: %s%s\n", MAGENTA, walletname.empty() ? "\"\"" : walletname, RESET);

        result_string += strprintf("Keypool size: %s\n", result["keypoolsize"].getValStr());
        if (!result["unlocked_until"].isNull()) {
            result_string += strprintf("Unlocked until: %s\n", result["unlocked_until"].getValStr());
        }
        result_string += strprintf("Transaction fee rate (-paytxfee) (%s/kvB): %s\n\n", CURRENCY_UNIT, result["paytxfee"].getValStr());
    }
    if (!result["balance"].isNull()) {
        result_string += strprintf("%sBalance:%s %s\n\n", CYAN, RESET, result["balance"].getValStr());
    }

    if (!result["balances"].isNull()) {
        result_string += strprintf("%sBalances%s\n", CYAN, RESET);

        size_t max_balance_length{10};

        for (const std::string& wallet : result["balances"].getKeys()) {
            max_balance_length = std::max(result["balances"][wallet].getValStr().length(), max_balance_length);
        }

        for (const std::string& wallet : result["balances"].getKeys()) {
            result_string += strprintf("%*s %s\n",
                                       max_balance_length,
                                       result["balances"][wallet].getValStr(),
                                       wallet.empty() ? "\"\"" : wallet);
        }
        result_string += "\n";
    }

    const std::string warnings{result["warnings"].getValStr()};
    result_string += strprintf("%sWarnings:%s %s", YELLOW, RESET, warnings.empty() ? "(none)" : warnings);

    result.setStr(result_string);
}

/**
 * Call RPC getnewaddress.
 * @returns getnewaddress response as a UniValue object.
 */
static UniValue GetNewAddress()
{
    std::optional<std::string> wallet_name{};
    if (gArgs.IsArgSet("-rpcwallet")) wallet_name = gArgs.GetArg("-rpcwallet", "");
    DefaultRequestHandler rh;
    return ConnectAndCallRPC(&rh, "getnewaddress", /* args=*/{}, wallet_name);
}

/**
 * Check bounds and set up args for RPC generatetoaddress params: nblocks, address, maxtries.
 * @param[in] address  Reference to const string address to insert into the args.
 * @param     args     Reference to vector of string args to modify.
 */
static void SetGenerateToAddressArgs(const std::string& address, std::vector<std::string>& args)
{
    if (args.size() > 2) throw std::runtime_error("too many arguments (maximum 2 for nblocks and maxtries)");
    if (args.size() == 0) {
        args.emplace_back(DEFAULT_NBLOCKS);
    } else if (args.at(0) == "0") {
        throw std::runtime_error("the first argument (number of blocks to generate, default: " + DEFAULT_NBLOCKS + ") must be an integer value greater than zero");
    }
    args.emplace(args.begin() + 1, address);
}

static int CommandLineRPC(int argc, char *argv[])
{
    std::string strPrint;
    int nRet = 0;
    try {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0])) {
            argc--;
            argv++;
        }
        std::string rpcPass;
        if (gArgs.GetBoolArg("-stdinrpcpass", false)) {
            NO_STDIN_ECHO();
            if (!StdinReady()) {
                fputs("RPC password> ", stderr);
                fflush(stderr);
            }
            if (!std::getline(std::cin, rpcPass)) {
                throw std::runtime_error("-stdinrpcpass specified but failed to read from standard input");
            }
            if (StdinTerminal()) {
                fputc('\n', stdout);
            }
            gArgs.ForceSetArg("-rpcpassword", rpcPass);
        }
        std::vector<std::string> args = std::vector<std::string>(&argv[1], &argv[argc]);
        if (gArgs.GetBoolArg("-interactive", false)) {
            if (gArgs.GetBoolArg("-stdin", false) || gArgs.GetBoolArg("-stdinwalletpassphrase", false)) {
                throw std::runtime_error("-interactive cannot be combined with -stdin or -stdinwalletpassphrase");
            }
            if (!gArgs.GetBoolArg("-named", false) || args.empty()) {
                throw std::runtime_error("-interactive requires -named and a supported RPC");
            }

            const std::string interactive_method{args[0]};
            static const std::set<std::string> supported_interactive_methods{
                "createwallet",
                "migratewallet",
                "upgradeorchardwallet",
                "sethdseed",
                "encryptwallet",
                "walletpassphrase",
                "walletpassphrasechange",
                "importprivkey",
                "importmulti",
                "importdescriptors",
                "signmessagewithprivkey",
                "signrawtransactionwithkey",
                "descriptorprocesspsbt",
                "getdescriptorinfo",
                "deriveaddresses",
                "utxoupdatepsbt",
                "scantxoutset",
                "scanblocks",
                "generatetodescriptor",
                "generateblock",
                "pruneblockchain",
                "preciousblock",
                "invalidateblock",
                "reconsiderblock",
                "loadtxoutset",
                "signmessage",
                "signrawtransactionwithwallet",
                "walletprocesspsbt",
                "fundrawtransaction",
                "send",
                "sendall",
                "walletcreatefundedpsbt",
                "dumpprivkey",
                "dumpmnemonic",
                "getprivateviewkey",
                "getprivatenoteproof",
                "checkprivatenoteproof",
                "listdescriptors",
                "getprivatekeymaninfo",
                "dumpwallet",
                "backupwallet",
                "importwallet",
                "restorewallet",
                "upgradewallet",
                "newkeypool",
                "keypoolrefill",
                "addmultisigaddress",
                "importaddress",
                "importpubkey",
            };
            if (!supported_interactive_methods.count(interactive_method)) {
                throw std::runtime_error("-interactive is not supported for this RPC; use it only with a documented sensitive or high-impact RPC");
            }

            const auto has_named_argument = [&](const std::string& name) {
                return std::any_of(args.begin() + 1, args.end(), [&](const std::string& arg) {
                    return arg == name || arg.rfind(name + "=", 0) == 0;
                });
            };
            const auto get_named_argument = [&](const std::string& name) -> std::optional<std::string> {
                std::optional<std::string> value;
                const std::string prefix{name + "="};
                for (auto it = args.begin() + 1; it != args.end(); ++it) {
                    if (it->rfind(prefix, 0) != 0) continue;
                    if (value) throw std::runtime_error(strprintf("Duplicate named argument: %s", name));
                    value = it->substr(prefix.size());
                }
                return value;
            };
            const auto get_named_bool = [&](const std::string& name, bool default_value) {
                const std::optional<std::string> value{get_named_argument(name)};
                if (!value) return default_value;
                if (*value == "true") return true;
                if (*value == "false") return false;
                throw std::runtime_error(strprintf("%s must be true or false with -interactive", name));
            };
            const auto require_named_string = [&](const std::string& name) {
                const std::optional<std::string> value{get_named_argument(name)};
                if (!value || value->empty()) {
                    throw std::runtime_error(strprintf("%s must be provided and non-empty with -interactive %s", name, interactive_method));
                }
                return *value;
            };
            const auto ensure_only_named_arguments = [&](std::initializer_list<const char*> allowed_names) {
                std::set<std::string> allowed;
                for (const char* name : allowed_names) allowed.emplace(name);
                std::set<std::string> seen;
                for (auto it = args.begin() + 1; it != args.end(); ++it) {
                    const size_t separator{it->find('=')};
                    if (separator == std::string::npos || separator == 0) {
                        throw std::runtime_error("Every argument after the RPC name must use name=value syntax with -interactive");
                    }
                    const std::string name{it->substr(0, separator)};
                    if (!allowed.count(name)) {
                        throw std::runtime_error(strprintf("Unknown named argument for -interactive %s: %s", interactive_method, name));
                    }
                    if (!seen.emplace(name).second) {
                        throw std::runtime_error(strprintf("Duplicate named argument: %s", name));
                    }
                }
            };
            const auto reject_named_arguments = [&](std::initializer_list<const char*> names) {
                for (const char* name : names) {
                    if (has_named_argument(name)) {
                        throw std::runtime_error(strprintf("Do not provide %s on the command line with -interactive", name));
                    }
                }
            };

            if (interactive_method == "createwallet") {
                ensure_only_named_arguments({"wallet_name", "disable_private_keys", "blank", "passphrase", "avoid_reuse", "descriptors", "load_on_startup", "external_signer", "bip39_passphrase"});
                reject_named_arguments({"passphrase", "bip39_passphrase"});
                const std::optional<std::string> wallet_name{get_named_argument("wallet_name")};
                if (!wallet_name || wallet_name->empty()) {
                    throw std::runtime_error("wallet_name must be provided and non-empty with -interactive createwallet");
                }
                const bool disable_private_keys{get_named_bool("disable_private_keys", false)};
                const bool blank{get_named_bool("blank", false)};
                const bool descriptors{get_named_bool("descriptors", true)};
                const bool external_signer{get_named_bool("external_signer", false)};
                get_named_bool("avoid_reuse", false);
                if (const std::optional<std::string> load_on_startup{get_named_argument("load_on_startup")};
                    load_on_startup && *load_on_startup != "true" && *load_on_startup != "false" && *load_on_startup != "null") {
                    throw std::runtime_error("load_on_startup must be true, false, or null with -interactive");
                }
                if (external_signer && (!disable_private_keys || !descriptors)) {
                    throw std::runtime_error("external_signer=true requires disable_private_keys=true and descriptors=true");
                }
            } else if (interactive_method == "migratewallet") {
                ensure_only_named_arguments({"wallet_name", "passphrase"});
                reject_named_arguments({"passphrase"});
                const std::optional<std::string> wallet_name{get_named_argument("wallet_name")};
                const bool rpc_wallet_set{gArgs.IsArgSet("-rpcwallet")};
                if (!rpc_wallet_set && !wallet_name) {
                    throw std::runtime_error("migratewallet requires -rpcwallet=<wallet> or wallet_name=<wallet>");
                }
                if (rpc_wallet_set && wallet_name && *wallet_name != gArgs.GetArg("-rpcwallet", "")) {
                    throw std::runtime_error("-rpcwallet and wallet_name must identify the same wallet");
                }
            } else if (interactive_method == "upgradeorchardwallet") {
                ensure_only_named_arguments({"mnemonic", "bip39_passphrase"});
                reject_named_arguments({"mnemonic", "bip39_passphrase"});
            } else if (interactive_method == "sethdseed") {
                ensure_only_named_arguments({"newkeypool", "seed", "bip39_passphrase"});
                reject_named_arguments({"seed", "bip39_passphrase"});
                get_named_bool("newkeypool", true);
            } else if (interactive_method == "encryptwallet") {
                ensure_only_named_arguments({"passphrase"});
                reject_named_arguments({"passphrase"});
            } else if (interactive_method == "walletpassphrase") {
                ensure_only_named_arguments({"passphrase", "timeout"});
                reject_named_arguments({"passphrase"});
                const std::string timeout{require_named_string("timeout")};
                int64_t timeout_value;
                if (!ParseInt64(timeout, &timeout_value) || timeout_value < 0) {
                    throw std::runtime_error("timeout must be a non-negative integer with -interactive walletpassphrase");
                }
            } else if (interactive_method == "walletpassphrasechange") {
                ensure_only_named_arguments({"oldpassphrase", "newpassphrase"});
                reject_named_arguments({"oldpassphrase", "newpassphrase"});
            } else if (interactive_method == "importprivkey") {
                ensure_only_named_arguments({"privkey", "label", "rescan"});
                reject_named_arguments({"privkey"});
                get_named_bool("rescan", true);
            } else if (interactive_method == "importmulti") {
                ensure_only_named_arguments({"requests", "options"});
                reject_named_arguments({"requests"});
            } else if (interactive_method == "importdescriptors") {
                ensure_only_named_arguments({"requests"});
                reject_named_arguments({"requests"});
            } else if (interactive_method == "signmessagewithprivkey") {
                ensure_only_named_arguments({"privkey", "message"});
                reject_named_arguments({"privkey"});
                if (!get_named_argument("message")) {
                    throw std::runtime_error("message must be provided with -interactive signmessagewithprivkey");
                }
            } else if (interactive_method == "signrawtransactionwithkey") {
                ensure_only_named_arguments({"hexstring", "privkeys", "prevtxs", "sighashtype"});
                reject_named_arguments({"privkeys"});
                require_named_string("hexstring");
            } else if (interactive_method == "descriptorprocesspsbt") {
                ensure_only_named_arguments({"psbt", "descriptors", "sighashtype", "bip32derivs", "finalize"});
                reject_named_arguments({"descriptors"});
                require_named_string("psbt");
                get_named_bool("bip32derivs", true);
                get_named_bool("finalize", true);
            } else if (interactive_method == "getdescriptorinfo") {
                ensure_only_named_arguments({"descriptor"});
                reject_named_arguments({"descriptor"});
            } else if (interactive_method == "deriveaddresses") {
                ensure_only_named_arguments({"descriptor", "range"});
                reject_named_arguments({"descriptor"});
            } else if (interactive_method == "utxoupdatepsbt") {
                ensure_only_named_arguments({"psbt", "descriptors"});
                reject_named_arguments({"descriptors"});
                require_named_string("psbt");
            } else if (interactive_method == "scantxoutset") {
                ensure_only_named_arguments({"action", "scanobjects"});
                reject_named_arguments({"scanobjects"});
                if (require_named_string("action") != "start") {
                    throw std::runtime_error("-interactive scantxoutset is only for action=start; use the ordinary RPC form for status or abort");
                }
            } else if (interactive_method == "scanblocks") {
                ensure_only_named_arguments({"action", "scanobjects", "start_height", "stop_height", "filtertype", "options"});
                reject_named_arguments({"scanobjects"});
                if (require_named_string("action") != "start") {
                    throw std::runtime_error("-interactive scanblocks is only for action=start; use the ordinary RPC form for status or abort");
                }
            } else if (interactive_method == "generatetodescriptor") {
                ensure_only_named_arguments({"num_blocks", "descriptor", "maxtries"});
                reject_named_arguments({"descriptor"});
                require_named_string("num_blocks");
            } else if (interactive_method == "generateblock") {
                ensure_only_named_arguments({"output", "transactions", "submit"});
                reject_named_arguments({"output"});
                require_named_string("transactions");
                get_named_bool("submit", true);
            } else if (interactive_method == "pruneblockchain") {
                ensure_only_named_arguments({"height"});
                const std::string height{require_named_string("height")};
                int64_t parsed_height;
                if (!ParseInt64(height, &parsed_height) || parsed_height < 0) {
                    throw std::runtime_error("height must be a non-negative integer with -interactive pruneblockchain");
                }
            } else if (interactive_method == "preciousblock" ||
                       interactive_method == "invalidateblock" ||
                       interactive_method == "reconsiderblock") {
                ensure_only_named_arguments({"blockhash"});
                const std::string blockhash{require_named_string("blockhash")};
                if (blockhash.size() != 64 || !IsHex(blockhash)) {
                    throw std::runtime_error(strprintf("blockhash must be a 64-character hexadecimal hash with -interactive %s", interactive_method));
                }
            } else if (interactive_method == "loadtxoutset") {
                ensure_only_named_arguments({"path"});
                require_named_string("path");
            } else if (interactive_method == "signmessage") {
                ensure_only_named_arguments({"address", "message"});
                require_named_string("address");
                if (!get_named_argument("message")) {
                    throw std::runtime_error("message must be provided with -interactive signmessage");
                }
            } else if (interactive_method == "signrawtransactionwithwallet") {
                ensure_only_named_arguments({"hexstring", "prevtxs", "sighashtype"});
                require_named_string("hexstring");
            } else if (interactive_method == "walletprocesspsbt") {
                ensure_only_named_arguments({"psbt", "sign", "sighashtype", "bip32derivs", "finalize", "private_intent_hash"});
                require_named_string("psbt");
                get_named_bool("sign", true);
                get_named_bool("bip32derivs", true);
                get_named_bool("finalize", true);
            } else if (interactive_method == "fundrawtransaction") {
                ensure_only_named_arguments({"hexstring", "options", "iswitness"});
                reject_named_arguments({"options"});
                require_named_string("hexstring");
                if (has_named_argument("iswitness")) get_named_bool("iswitness", false);
            } else if (interactive_method == "send") {
                ensure_only_named_arguments({"outputs", "conf_target", "estimate_mode", "fee_rate", "options"});
                reject_named_arguments({"options"});
                require_named_string("outputs");
            } else if (interactive_method == "sendall") {
                ensure_only_named_arguments({"recipients", "conf_target", "estimate_mode", "fee_rate", "options"});
                reject_named_arguments({"options"});
                require_named_string("recipients");
            } else if (interactive_method == "walletcreatefundedpsbt") {
                ensure_only_named_arguments({"inputs", "outputs", "locktime", "options", "bip32derivs"});
                reject_named_arguments({"options"});
                require_named_string("outputs");
                get_named_bool("bip32derivs", true);
            } else if (interactive_method == "dumpprivkey") {
                ensure_only_named_arguments({"address"});
                require_named_string("address");
            } else if (interactive_method == "dumpmnemonic") {
                ensure_only_named_arguments({});
            } else if (interactive_method == "getprivateviewkey") {
                ensure_only_named_arguments({"address"});
                require_named_string("address");
            } else if (interactive_method == "getprivatenoteproof") {
                ensure_only_named_arguments({"cmx"});
                const std::string cmx{require_named_string("cmx")};
                if (cmx.size() != 64 || !IsHex(cmx)) {
                    throw std::runtime_error("cmx must be a 64-character hexadecimal private note commitment");
                }
            } else if (interactive_method == "checkprivatenoteproof") {
                ensure_only_named_arguments({"proof"});
                reject_named_arguments({"proof"});
            } else if (interactive_method == "listdescriptors") {
                ensure_only_named_arguments({"private"});
                reject_named_arguments({"private"});
            } else if (interactive_method == "getprivatekeymaninfo") {
                ensure_only_named_arguments({"include_private"});
                reject_named_arguments({"include_private"});
            } else if (interactive_method == "dumpwallet") {
                ensure_only_named_arguments({"filename"});
                require_named_string("filename");
            } else if (interactive_method == "backupwallet") {
                ensure_only_named_arguments({"destination"});
                require_named_string("destination");
            } else if (interactive_method == "importwallet") {
                ensure_only_named_arguments({"filename"});
                require_named_string("filename");
            } else if (interactive_method == "restorewallet") {
                ensure_only_named_arguments({"wallet_name", "backup_file", "load_on_startup"});
                require_named_string("wallet_name");
                require_named_string("backup_file");
                if (const std::optional<std::string> load_on_startup{get_named_argument("load_on_startup")};
                    load_on_startup && *load_on_startup != "true" && *load_on_startup != "false" && *load_on_startup != "null") {
                    throw std::runtime_error("load_on_startup must be true, false, or null with -interactive restorewallet");
                }
            } else if (interactive_method == "upgradewallet") {
                ensure_only_named_arguments({"version"});
                if (const std::optional<std::string> version{get_named_argument("version")}; version) {
                    int64_t version_value;
                    if (!ParseInt64(*version, &version_value)) {
                        throw std::runtime_error("version must be an integer with -interactive upgradewallet");
                    }
                }
            } else if (interactive_method == "newkeypool") {
                ensure_only_named_arguments({});
            } else if (interactive_method == "keypoolrefill") {
                ensure_only_named_arguments({"newsize"});
                if (const std::optional<std::string> newsize{get_named_argument("newsize")}; newsize) {
                    int64_t parsed_newsize;
                    if (!ParseInt64(*newsize, &parsed_newsize) || parsed_newsize < 0) {
                        throw std::runtime_error("newsize must be a non-negative integer with -interactive keypoolrefill");
                    }
                }
            } else if (interactive_method == "addmultisigaddress") {
                ensure_only_named_arguments({"nrequired", "keys", "label", "address_type"});
                const std::string nrequired{require_named_string("nrequired")};
                int64_t parsed_nrequired;
                if (!ParseInt64(nrequired, &parsed_nrequired) || parsed_nrequired <= 0) {
                    throw std::runtime_error("nrequired must be a positive integer with -interactive addmultisigaddress");
                }
                require_named_string("keys");
            } else if (interactive_method == "importaddress") {
                ensure_only_named_arguments({"address", "label", "rescan", "p2sh"});
                require_named_string("address");
                get_named_bool("rescan", true);
                get_named_bool("p2sh", false);
            } else if (interactive_method == "importpubkey") {
                ensure_only_named_arguments({"pubkey", "label", "rescan"});
                require_named_string("pubkey");
                get_named_bool("rescan", true);
            }

            // Fail before asking for secrets when the RPC server or credentials
            // are unavailable. The requested wallet RPC remains the only
            // state-changing call.
            DefaultRequestHandler preflight_handler;
            const UniValue preflight_reply{ConnectAndCallRPC(&preflight_handler, "getblockchaininfo", {})};
            const UniValue& preflight_error{preflight_reply.find_value("error")};
            if (!preflight_error.isNull()) {
                const UniValue& message{preflight_error.find_value("message")};
                throw std::runtime_error(message.isStr() ? "RPC preflight failed: " + message.get_str() : "RPC preflight failed");
            }

            const auto read_choice = [](const char* prompt) {
                while (true) {
                    if (StdinTerminal()) {
                        fputs(prompt, stderr);
                        fflush(stderr);
                    }
                    std::string value;
                    if (!std::getline(std::cin, value)) {
                        throw std::runtime_error("-interactive failed to read from standard input");
                    }
                    value = ToLower(TrimString(value));
                    if (value.empty() || value == "n" || value == "no") return false;
                    if (value == "y" || value == "yes") return true;
                    if (StdinTerminal()) {
                        fputs("Please answer y or n.\n", stderr);
                        fflush(stderr);
                    }
                }
            };
            const auto read_secret = [](const char* prompt) {
                std::optional<NoechoInst> no_echo;
                if (StdinTerminal()) {
                    no_echo.emplace();
                    fputs(prompt, stderr);
                    fflush(stderr);
                }
                std::string value;
                if (!std::getline(std::cin, value)) {
                    throw std::runtime_error("-interactive failed to read from standard input");
                }
                if (StdinTerminal()) fputc('\n', stderr);
                return value;
            };
            const auto read_confirmed_secret = [&](const char* prompt, const char* confirmation_prompt, const char* empty_error, const char* mismatch_error) {
                const std::string value{read_secret(prompt)};
                const std::string confirmation{read_secret(confirmation_prompt)};
                if (value.empty()) throw std::runtime_error(empty_error);
                if (value != confirmation) throw std::runtime_error(mismatch_error);
                return value;
            };
            const auto require_confirmation = [&](const char* prompt, const char* cancellation_error) {
                if (!read_choice(prompt)) throw std::runtime_error(cancellation_error);
            };
            const auto read_json_array_secret = [&](const char* prompt, const char* invalid_error, bool allow_empty = false) {
                const std::string input{read_secret(prompt)};
                UniValue parsed;
                if (input.empty() || !parsed.read(input) || !parsed.isArray() || (!allow_empty && parsed.empty())) {
                    throw std::runtime_error(invalid_error);
                }
                return input;
            };
            const auto read_optional_json_array_secret = [&](const char* prompt, const char* invalid_error) -> std::optional<std::string> {
                const std::string input{read_secret(prompt)};
                if (input.empty()) return std::nullopt;
                UniValue parsed;
                if (!parsed.read(input) || !parsed.isArray()) {
                    throw std::runtime_error(invalid_error);
                }
                return input;
            };
            const auto read_optional_json_object_secret = [&](const char* prompt, const char* invalid_error) -> std::optional<std::string> {
                const std::string input{read_secret(prompt)};
                if (input.empty()) return std::nullopt;
                UniValue parsed;
                if (!parsed.read(input) || !parsed.isObject()) {
                    throw std::runtime_error(invalid_error);
                }
                return input;
            };
            const auto read_optional_json_object_or_bool_secret = [&](const char* prompt, const char* invalid_error) -> std::optional<std::string> {
                const std::string input{read_secret(prompt)};
                if (input.empty()) return std::nullopt;
                UniValue parsed;
                if (!parsed.read(input) || (!parsed.isObject() && !parsed.isBool())) {
                    throw std::runtime_error(invalid_error);
                }
                return input;
            };

            if (interactive_method == "createwallet") {
                const bool disable_private_keys{get_named_bool("disable_private_keys", false)};
                const bool blank{get_named_bool("blank", false)};
                const bool descriptors{get_named_bool("descriptors", true)};
                const bool external_signer{get_named_bool("external_signer", false)};
                if (read_choice("Encrypt wallet.dat with a passphrase? [y/N] ")) {
                    const std::string wallet_passphrase{read_confirmed_secret(
                        "Wallet encryption passphrase> ",
                        "Confirm wallet encryption passphrase> ",
                        "Wallet encryption passphrase must not be empty when encryption is selected",
                        "Wallet encryption passphrases do not match")};
                    args.push_back("passphrase=" + wallet_passphrase);
                }

                const bool bip39_available{descriptors && !blank && !disable_private_keys && !external_signer};
                if (bip39_available && read_choice("Protect the recovery phrase with a BIP39 passphrase? [y/N] ")) {
                    const std::string bip39_passphrase{read_confirmed_secret(
                        "BIP39 passphrase (distinct and never stored)> ",
                        "Confirm BIP39 passphrase> ",
                        "BIP39 passphrase must not be empty when BIP39 protection is selected",
                        "BIP39 passphrases do not match")};
                    args.push_back("bip39_passphrase=" + bip39_passphrase);
                } else if (!bip39_available && StdinTerminal()) {
                    fputs("BIP39 recovery protection is not applicable to this wallet configuration.\n", stderr);
                }
            } else if (interactive_method == "migratewallet") {
                require_confirmation(
                    "Migrate this legacy wallet to descriptors and create the required backup? [y/N] ",
                    "Wallet migration cancelled before any change");
                if (read_choice("Is this wallet encrypted? [y/N] ")) {
                    const std::string wallet_passphrase{read_secret("Current wallet encryption passphrase> ")};
                    if (wallet_passphrase.empty()) {
                        throw std::runtime_error("Current wallet encryption passphrase must not be empty for encrypted migration");
                    }
                    args.push_back("passphrase=" + wallet_passphrase);
                }
            } else if (interactive_method == "upgradeorchardwallet") {
                if (read_choice("Restore Orchard from an existing recovery phrase? [y/N] ")) {
                    const std::string mnemonic{read_confirmed_secret(
                        "Orchard recovery phrase> ",
                        "Confirm Orchard recovery phrase> ",
                        "Orchard recovery phrase must not be empty when restoration is selected",
                        "Orchard recovery phrases do not match")};
                    args.push_back("mnemonic=" + mnemonic);
                }
                if (read_choice("Protect the Orchard recovery phrase with a BIP39 passphrase? [y/N] ")) {
                    const std::string bip39_passphrase{read_confirmed_secret(
                        "BIP39 passphrase (distinct and never stored)> ",
                        "Confirm BIP39 passphrase> ",
                        "BIP39 passphrase must not be empty when BIP39 protection is selected",
                        "BIP39 passphrases do not match")};
                    args.push_back("bip39_passphrase=" + bip39_passphrase);
                }
                require_confirmation(
                    "Create the required backup and add Orchard to this wallet? [y/N] ",
                    "Orchard wallet upgrade cancelled before any change");
            } else if (interactive_method == "sethdseed") {
                bool legacy_wif{false};
                if (read_choice("Supply an existing recovery seed instead of generating a new random BIP39 phrase? [y/N] ")) {
                    legacy_wif = read_choice("Is the existing seed a legacy WIF HD seed? [y/N] ");
                    if (legacy_wif) {
                        const std::string wif_seed{read_confirmed_secret(
                            "Legacy WIF HD seed> ",
                            "Confirm legacy WIF HD seed> ",
                            "Legacy WIF HD seed must not be empty",
                            "Legacy WIF HD seeds do not match")};
                        args.push_back("seed=" + wif_seed);
                    } else {
                        const std::string mnemonic{read_confirmed_secret(
                            "BIP39 recovery phrase> ",
                            "Confirm BIP39 recovery phrase> ",
                            "BIP39 recovery phrase must not be empty",
                            "BIP39 recovery phrases do not match")};
                        args.push_back("seed=" + mnemonic);
                    }
                }
                if (!legacy_wif && read_choice("Protect this BIP39 seed with a separate BIP39 passphrase? [y/N] ")) {
                    const std::string bip39_passphrase{read_confirmed_secret(
                        "BIP39 passphrase (distinct and never stored)> ",
                        "Confirm BIP39 passphrase> ",
                        "BIP39 passphrase must not be empty when BIP39 protection is selected",
                        "BIP39 passphrases do not match")};
                    args.push_back("bip39_passphrase=" + bip39_passphrase);
                }
                require_confirmation(
                    "Initialize or replace this wallet's HD seed now? A new backup is required. [y/N] ",
                    "Wallet recovery cancelled before any change");
            } else if (interactive_method == "encryptwallet") {
                require_confirmation(
                    "Encrypt wallet.dat? A new backup is required immediately afterwards. Continue? [y/N] ",
                    "Wallet encryption cancelled before any change");
                const std::string wallet_passphrase{read_confirmed_secret(
                    "New wallet encryption passphrase> ",
                    "Confirm new wallet encryption passphrase> ",
                    "New wallet encryption passphrase must not be empty",
                    "New wallet encryption passphrases do not match")};
                args.push_back("passphrase=" + wallet_passphrase);
            } else if (interactive_method == "walletpassphrase") {
                const std::string wallet_passphrase{read_secret("Wallet encryption passphrase> ")};
                if (wallet_passphrase.empty()) {
                    throw std::runtime_error("Wallet encryption passphrase must not be empty");
                }
                args.push_back("passphrase=" + wallet_passphrase);
            } else if (interactive_method == "walletpassphrasechange") {
                const std::string old_passphrase{read_secret("Current wallet encryption passphrase> ")};
                if (old_passphrase.empty()) {
                    throw std::runtime_error("Current wallet encryption passphrase must not be empty");
                }
                const std::string new_passphrase{read_confirmed_secret(
                    "New wallet encryption passphrase> ",
                    "Confirm new wallet encryption passphrase> ",
                    "New wallet encryption passphrase must not be empty",
                    "New wallet encryption passphrases do not match")};
                require_confirmation(
                    "Change the wallet encryption passphrase now? A new backup is required afterwards. [y/N] ",
                    "Wallet passphrase change cancelled before any change");
                args.push_back("oldpassphrase=" + old_passphrase);
                args.push_back("newpassphrase=" + new_passphrase);
            } else if (interactive_method == "importprivkey") {
                const std::string private_key{read_secret("Private key to import> ")};
                if (private_key.empty()) throw std::runtime_error("Private key must not be empty");
                require_confirmation(
                    "Import this private key into the selected wallet? A new backup is required. [y/N] ",
                    "Private-key import cancelled before any change");
                args.push_back("privkey=" + private_key);
            } else if (interactive_method == "importmulti") {
                const std::string requests{read_json_array_secret(
                    "Import requests JSON array (input hidden because it may contain private keys)> ",
                    "Import requests must be a non-empty JSON array")};
                require_confirmation(
                    "Import these legacy-wallet requests now? A new backup is required. [y/N] ",
                    "Multi-import cancelled before any change");
                args.push_back("requests=" + requests);
            } else if (interactive_method == "importdescriptors") {
                const std::string requests{read_json_array_secret(
                    "Descriptor import requests JSON array (input hidden because it may contain xprv data)> ",
                    "Descriptor import requests must be a non-empty JSON array")};
                require_confirmation(
                    "Import these descriptors now? A new backup is required. [y/N] ",
                    "Descriptor import cancelled before any change");
                args.push_back("requests=" + requests);
            } else if (interactive_method == "signmessagewithprivkey") {
                const std::string private_key{read_secret("Private key for message signing> ")};
                if (private_key.empty()) throw std::runtime_error("Private key must not be empty");
                require_confirmation(
                    "Sign the supplied message with this private key? [y/N] ",
                    "Message signing cancelled before any signature was created");
                args.push_back("privkey=" + private_key);
            } else if (interactive_method == "signrawtransactionwithkey") {
                UniValue private_keys{UniValue::VARR};
                while (true) {
                    const std::string private_key{read_secret(private_keys.empty()
                        ? "Private key for transaction signing (leave empty to use none)> "
                        : "Another private key (leave empty to finish)> ")};
                    if (private_key.empty()) {
                        break;
                    }
                    private_keys.push_back(private_key);
                }
                require_confirmation(
                    "Process the supplied raw transaction with the entered private keys? [y/N] ",
                    "Transaction signing cancelled before any signature was created");
                args.push_back("privkeys=" + private_keys.write());
            } else if (interactive_method == "descriptorprocesspsbt") {
                const std::string descriptors{read_json_array_secret(
                    "Signing descriptors JSON array (input hidden because it may contain xprv data)> ",
                    "Signing descriptors must be a JSON array",
                    /*allow_empty=*/true)};
                require_confirmation(
                    "Process and sign the supplied PSBT with these descriptors? [y/N] ",
                    "Descriptor PSBT signing cancelled before any signature was created");
                args.push_back("descriptors=" + descriptors);
            } else if (interactive_method == "getdescriptorinfo") {
                const std::string descriptor{read_secret("Descriptor to analyse (input hidden because it may contain xprv data)> ")};
                if (descriptor.empty()) throw std::runtime_error("Descriptor must not be empty");
                args.push_back("descriptor=" + descriptor);
            } else if (interactive_method == "deriveaddresses") {
                const std::string descriptor{read_secret("Descriptor to derive (input hidden because it may contain xprv data)> ")};
                if (descriptor.empty()) throw std::runtime_error("Descriptor must not be empty");
                args.push_back("descriptor=" + descriptor);
            } else if (interactive_method == "utxoupdatepsbt") {
                if (const std::optional<std::string> descriptors{read_optional_json_array_secret(
                        "Descriptor JSON array (optional; input hidden because it may contain xprv data, leave empty to omit)> ",
                        "Descriptors must be a JSON array")}; descriptors) {
                    args.push_back("descriptors=" + *descriptors);
                }
            } else if (interactive_method == "scantxoutset" || interactive_method == "scanblocks") {
                const std::string scan_objects{read_json_array_secret(
                    "Scan objects JSON array (input hidden because descriptors may contain xprv data)> ",
                    "Scan objects must be a non-empty JSON array")};
                args.push_back("scanobjects=" + scan_objects);
            } else if (interactive_method == "generatetodescriptor") {
                const std::string descriptor{read_secret("Mining descriptor (input hidden because it may contain xprv data)> ")};
                if (descriptor.empty()) throw std::runtime_error("Mining descriptor must not be empty");
                require_confirmation(
                    "Generate the requested blocks to this descriptor? [y/N] ",
                    "Descriptor mining cancelled before any block was generated");
                args.push_back("descriptor=" + descriptor);
            } else if (interactive_method == "generateblock") {
                const std::string output{read_secret("Block output address or descriptor (input hidden because a descriptor may contain xprv data)> ")};
                if (output.empty()) throw std::runtime_error("Block output address or descriptor must not be empty");
                require_confirmation(
                    "Generate the requested block with this output and transaction set? [y/N] ",
                    "Block generation cancelled before any block was generated");
                args.push_back("output=" + output);
            } else if (interactive_method == "pruneblockchain") {
                require_confirmation(
                    "Permanently delete eligible block files up to the requested height? [y/N] ",
                    "Blockchain pruning cancelled before any block file was deleted");
            } else if (interactive_method == "preciousblock") {
                require_confirmation(
                    "Prefer this block among equal-work alternatives until restart or another override? [y/N] ",
                    "Precious-block selection cancelled before chainstate changed");
            } else if (interactive_method == "invalidateblock") {
                require_confirmation(
                    "Permanently mark this block and its descendants invalid and reorganize chainstate if needed? [y/N] ",
                    "Block invalidation cancelled before chainstate changed");
            } else if (interactive_method == "reconsiderblock") {
                require_confirmation(
                    "Remove invalidity status from this block, its ancestors and descendants and reconsider activation? [y/N] ",
                    "Block reconsideration cancelled before chainstate changed");
            } else if (interactive_method == "loadtxoutset") {
                require_confirmation(
                    "Load and activate the requested UTXO snapshot as a second chainstate? [y/N] ",
                    "UTXO snapshot loading cancelled before chainstate changed");
            } else if (interactive_method == "signmessage") {
                require_confirmation(
                    "Sign the supplied message with the selected wallet address? [y/N] ",
                    "Wallet message signing cancelled before any signature was created");
            } else if (interactive_method == "signrawtransactionwithwallet") {
                require_confirmation(
                    "Sign the supplied raw transaction with keys from the selected wallet? [y/N] ",
                    "Wallet transaction signing cancelled before any signature was created");
            } else if (interactive_method == "walletprocesspsbt") {
                if (get_named_bool("sign", true)) {
                    require_confirmation(
                        "Process and sign the supplied PSBT with keys from the selected wallet? [y/N] ",
                        "Wallet PSBT signing cancelled before any signature was created");
                } else {
                    require_confirmation(
                        "Process the supplied PSBT without signing? [y/N] ",
                        "Wallet PSBT processing cancelled before any change");
                }
            } else if (interactive_method == "fundrawtransaction") {
                if (const std::optional<std::string> options{read_optional_json_object_or_bool_secret(
                        "Funding options JSON object or legacy boolean (optional; input hidden because solving_data may contain xprv data, leave empty to omit)> ",
                        "Funding options must be a JSON object or boolean")}; options) {
                    args.push_back("options=" + *options);
                }
                require_confirmation(
                    "Fund the supplied raw transaction with the selected wallet? [y/N] ",
                    "Raw transaction funding cancelled before any wallet change");
            } else if (interactive_method == "send") {
                if (const std::optional<std::string> options{read_optional_json_object_secret(
                        "Send options JSON object (optional; input hidden because solving_data may contain xprv data, leave empty to omit)> ",
                        "Send options must be a JSON object")}; options) {
                    args.push_back("options=" + *options);
                }
                require_confirmation(
                    "Create, sign, and process this wallet payment using the supplied outputs and options? [y/N] ",
                    "Wallet payment cancelled before any transaction was created");
            } else if (interactive_method == "sendall") {
                if (const std::optional<std::string> options{read_optional_json_object_secret(
                        "Send-all options JSON object (optional; input hidden because solving_data may contain xprv data, leave empty to omit)> ",
                        "Send-all options must be a JSON object")}; options) {
                    args.push_back("options=" + *options);
                }
                require_confirmation(
                    "Spend the selected wallet's confirmed UTXOs using these recipients and options? [y/N] ",
                    "Wallet send-all cancelled before any transaction was created");
            } else if (interactive_method == "walletcreatefundedpsbt") {
                if (const std::optional<std::string> options{read_optional_json_object_secret(
                        "PSBT funding options JSON object (optional; input hidden because solving_data may contain xprv data, leave empty to omit)> ",
                        "PSBT funding options must be a JSON object")}; options) {
                    args.push_back("options=" + *options);
                }
                require_confirmation(
                    "Create and fund this PSBT with the selected wallet? [y/N] ",
                    "Wallet PSBT funding cancelled before any wallet change");
            } else if (interactive_method == "dumpprivkey") {
                require_confirmation(
                    "Reveal this address's private key on standard output? [y/N] ",
                    "Private-key disclosure cancelled");
            } else if (interactive_method == "dumpmnemonic") {
                require_confirmation(
                    "Reveal the wallet recovery phrase on standard output? [y/N] ",
                    "Recovery-phrase disclosure cancelled");
            } else if (interactive_method == "getprivateviewkey") {
                require_confirmation(
                    "Reveal a branch-wide Orchard full viewing key on standard output? [y/N] ",
                    "Viewing-key disclosure cancelled");
            } else if (interactive_method == "getprivatenoteproof") {
                require_confirmation(
                    "Reveal this private note's amount, recipient, and opening proof on standard output? [y/N] ",
                    "Private-note proof disclosure cancelled");
            } else if (interactive_method == "checkprivatenoteproof") {
                const std::string proof{read_secret("Private note proof to verify (input hidden because it discloses note details)> ")};
                if (proof.empty()) throw std::runtime_error("Private note proof must not be empty");
                args.push_back("proof=" + proof);
            } else if (interactive_method == "listdescriptors") {
                if (read_choice("Include private descriptors in the output? This reveals private keys. [y/N] ")) {
                    args.push_back("private=true");
                } else {
                    args.push_back("private=false");
                }
            } else if (interactive_method == "getprivatekeymaninfo") {
                if (read_choice("Include private Orchard descriptors in the output? This reveals recovery authority. [y/N] ")) {
                    args.push_back("include_private=true");
                } else {
                    args.push_back("include_private=false");
                }
            } else if (interactive_method == "dumpwallet") {
                require_confirmation(
                    "Write all legacy-wallet private keys to the requested server-side file? [y/N] ",
                    "Wallet dump cancelled before any file was written");
            } else if (interactive_method == "backupwallet") {
                require_confirmation(
                    "Write a complete wallet backup to the requested server-side destination? [y/N] ",
                    "Wallet backup cancelled before any file was written");
            } else if (interactive_method == "importwallet") {
                require_confirmation(
                    "Import all keys and scripts from this server-side wallet dump? A new backup is required afterwards. [y/N] ",
                    "Wallet dump import cancelled before any wallet change");
            } else if (interactive_method == "restorewallet") {
                require_confirmation(
                    "Restore and load a wallet from the requested private backup file? [y/N] ",
                    "Wallet restore cancelled before any wallet was created");
            } else if (interactive_method == "upgradewallet") {
                require_confirmation(
                    "Upgrade this wallet version now? A new backup may be required afterwards. [y/N] ",
                    "Wallet version upgrade cancelled before any change");
            } else if (interactive_method == "newkeypool") {
                require_confirmation(
                    "Clear and regenerate this wallet's entire keypool? A new backup may be required. [y/N] ",
                    "Keypool regeneration cancelled before any change");
            } else if (interactive_method == "keypoolrefill") {
                require_confirmation(
                    "Generate keys to refill this wallet's keypool? Back up a non-HD wallet afterwards. [y/N] ",
                    "Keypool refill cancelled before any change");
            } else if (interactive_method == "addmultisigaddress") {
                require_confirmation(
                    "Add this multisignature address to the selected legacy wallet? A new backup is required. [y/N] ",
                    "Multisignature-address creation cancelled before any wallet change");
            } else if (interactive_method == "importaddress") {
                require_confirmation(
                    "Import this watch-only address or script into the selected legacy wallet? A new backup is required. [y/N] ",
                    "Watch-only address import cancelled before any wallet change");
            } else if (interactive_method == "importpubkey") {
                require_confirmation(
                    "Import this watch-only public key into the selected legacy wallet? A new backup is required. [y/N] ",
                    "Public-key import cancelled before any wallet change");
            }
        }
        if (gArgs.GetBoolArg("-stdinwalletpassphrase", false)) {
            NO_STDIN_ECHO();
            std::string walletPass;
            if (args.size() < 1 || args[0].substr(0, 16) != "walletpassphrase") {
                throw std::runtime_error("-stdinwalletpassphrase is only applicable for walletpassphrase(change)");
            }
            if (!StdinReady()) {
                fputs("Wallet passphrase> ", stderr);
                fflush(stderr);
            }
            if (!std::getline(std::cin, walletPass)) {
                throw std::runtime_error("-stdinwalletpassphrase specified but failed to read from standard input");
            }
            if (StdinTerminal()) {
                fputc('\n', stdout);
            }
            args.insert(args.begin() + 1, walletPass);
        }
        if (gArgs.GetBoolArg("-stdin", false)) {
            // Read one arg per line from stdin and append
            std::optional<NoechoInst> no_echo;
            if (StdinTerminal()) no_echo.emplace();
            std::string line;
            while (std::getline(std::cin, line)) {
                args.push_back(line);
            }
            if (StdinTerminal()) {
                fputc('\n', stdout);
            }
        }
        std::unique_ptr<BaseRequestHandler> rh;
        std::string method;
        if (gArgs.IsArgSet("-getinfo")) {
            rh.reset(new GetinfoRequestHandler());
        } else if (gArgs.GetBoolArg("-netinfo", false)) {
            if (!args.empty() && args.at(0) == "help") {
                tfm::format(std::cout, "%s\n", NetinfoRequestHandler().m_help_doc);
                return 0;
            }
            rh.reset(new NetinfoRequestHandler());
        } else if (gArgs.GetBoolArg("-generate", false)) {
            const UniValue getnewaddress{GetNewAddress()};
            const UniValue& error{getnewaddress.find_value("error")};
            if (error.isNull()) {
                SetGenerateToAddressArgs(getnewaddress.find_value("result").get_str(), args);
                rh.reset(new GenerateToAddressRequestHandler());
            } else {
                ParseError(error, strPrint, nRet);
            }
        } else if (gArgs.GetBoolArg("-addrinfo", false)) {
            rh.reset(new AddrinfoRequestHandler());
        } else {
            rh.reset(new DefaultRequestHandler());
            if (args.size() < 1) {
                throw std::runtime_error("too few parameters (need at least command)");
            }
            method = args[0];
            args.erase(args.begin()); // Remove trailing method name from arguments vector
        }
        if (nRet == 0) {
            // Perform RPC call
            std::optional<std::string> wallet_name{};
            if (gArgs.IsArgSet("-rpcwallet")) wallet_name = gArgs.GetArg("-rpcwallet", "");
            const UniValue reply = ConnectAndCallRPC(rh.get(), method, args, wallet_name);

            // Parse reply
            UniValue result = reply.find_value("result");
            const UniValue& error = reply.find_value("error");
            if (error.isNull()) {
                if (gArgs.GetBoolArg("-getinfo", false)) {
                    if (!gArgs.IsArgSet("-rpcwallet")) {
                        GetWalletBalances(result); // fetch multiwallet balances and append to result
                    }
                    ParseGetInfoResult(result);
                }

                ParseResult(result, strPrint);
            } else {
                ParseError(error, strPrint, nRet);
            }
        }
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
        nRet = EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "CommandLineRPC()");
        throw;
    }

    if (strPrint != "") {
        tfm::format(nRet == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }
    return nRet;
}

MAIN_FUNCTION
{
#ifdef WIN32
    common::WinCmdLineArgs winArgs;
    std::tie(argc, argv) = winArgs.get();
#endif
    SetupEnvironment();
    if (!SetupNetworking()) {
        tfm::format(std::cerr, "Error: Initializing networking failed\n");
        return EXIT_FAILURE;
    }
    event_set_log_callback(&libevent_log_cb);

    try {
        int ret = AppInitRPC(argc, argv);
        if (ret != CONTINUE_EXECUTION)
            return ret;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRPC()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitRPC()");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    try {
        ret = CommandLineRPC(argc, argv);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "CommandLineRPC()");
    } catch (...) {
        PrintExceptionContinue(nullptr, "CommandLineRPC()");
    }
    return ret;
}
