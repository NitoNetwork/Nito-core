// Copyright (c) 2011-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <chainparams.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <primitives/private_transaction.h>
#include <rpc/util.h>
#include <script/script.h>
#include <streams.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <wallet/coincontrol.h>
#include <wallet/private_notes.h>
#include <wallet/private_wallet.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <algorithm>
#include <limits>

namespace wallet {
namespace {
using interfaces::FoundBlock;

static constexpr int PRIVATE_NOTE_PROOF_VERSION = 1;
static constexpr const char* PRIVATE_NOTE_PROOF_TYPE = "nito-private-note-proof";

static void EnsureAvailableBalanceReady(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (wallet.IsAvailableBalanceSyncPending()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This restored wallet is still synchronizing. Balance and UTXOs are available after chain synchronization finishes.");
    }
}

class CPrivateNoteDisclosureProof
{
public:
    int nVersion{PRIVATE_NOTE_PROOF_VERSION};
    uint256 txid;
    uint256 block_hash;
    int32_t block_height{-1};
    uint32_t action_index{0};
    uint64_t commitment_index{std::numeric_limits<uint64_t>::max()};
    CAmount value{0};
    uint256 cmx;
    std::vector<unsigned char> recipient_raw;
    std::vector<unsigned char> rho;
    std::vector<unsigned char> rseed;

    SERIALIZE_METHODS(CPrivateNoteDisclosureProof, obj)
    {
        READWRITE(obj.nVersion, obj.txid, obj.block_hash, obj.block_height,
                  obj.action_index, obj.commitment_index, obj.value, obj.cmx,
                  obj.recipient_raw, obj.rho, obj.rseed);
    }
};

struct PrivateBalanceSnapshot {
    CAmount trusted{0};
    CAmount untrusted{0};
    CAmount total_unspent{0};
    int64_t notes_count{0};
    int spendable_notes{0};
};

bool PrivateNoteTxIsActive(const CWallet& wallet, const CPrivateWalletNote& note) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const auto it = wallet.mapWallet.find(note.txid);
    if (it != wallet.mapWallet.end()) {
        const CWalletTx& wtx = it->second;
        if (wtx.state<TxStateInMempool>()) return true;

        const auto* confirmed = wtx.state<TxStateConfirmed>();
        if (confirmed == nullptr) return false;
        if (confirmed->confirmed_block_hash != note.block_hash || confirmed->confirmed_block_height != note.block_height) return false;
    }

    if (!note.IsConfirmed()) return false;
    if (!wallet.HaveChain()) return false;

    bool active{false};
    int height{-1};
    return wallet.chain().findBlock(note.block_hash, FoundBlock().inActiveChain(active).height(height)) &&
           active && height == note.block_height;
}

PrivateBalanceSnapshot GetPrivateBalanceSnapshot(CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    wallet.RefreshPrivateCommitmentIndexes();
    PrivateBalanceSnapshot snapshot;
    for (const auto& [cmx, note] : wallet.mapPrivateNotes) {
        if (note.spent || note.value <= 0) continue;
        if (!PrivateNoteTxIsActive(wallet, note)) continue;
        ++snapshot.notes_count;
        snapshot.total_unspent += note.value;
        // The active-chain test above already verified this note's block.
        if (note.IsConfirmed() && wallet.GetLastBlockHeight() >= note.block_height && note.IsSpendable()) {
            snapshot.trusted += note.value;
            ++snapshot.spendable_notes;
        } else {
            snapshot.untrusted += note.value;
        }
    }
    return snapshot;
}

std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> RawPrivateAddressArray(const std::vector<unsigned char>& raw)
{
    if (raw.size() != NITO_ORCHARD_RAW_ADDRESS_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Private note proof has an invalid raw recipient size");
    }
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> out{};
    std::copy(raw.begin(), raw.end(), out.begin());
    return out;
}

std::string ProofToHex(const CPrivateNoteDisclosureProof& proof)
{
    DataStream stream{};
    stream << proof;
    return HexStr(stream);
}

CPrivateNoteDisclosureProof ProofFromHex(const UniValue& value)
{
    DataStream stream{ParseHexV(value, "proof")};
    CPrivateNoteDisclosureProof proof;
    try {
        stream >> proof;
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Private note proof decode failed: %s", e.what()));
    }
    if (proof.nVersion != PRIVATE_NOTE_PROOF_VERSION) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unsupported private note proof version: %d", proof.nVersion));
    }
    if (proof.recipient_raw.size() != NITO_ORCHARD_RAW_ADDRESS_SIZE ||
        proof.rho.size() != NITO_ORCHARD_RHO_SIZE ||
        proof.rseed.size() != NITO_ORCHARD_RSEED_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Private note proof has invalid Orchard field sizes");
    }
    if (proof.value <= 0 || !MoneyRange(proof.value)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Private note proof amount is out of range");
    }
    return proof;
}

uint256 ProofId(const CPrivateNoteDisclosureProof& proof)
{
    DataStream stream{};
    stream << proof;
    return Hash(stream);
}

UniValue PrivateNoteProofDetails(const CPrivateNoteDisclosureProof& proof, const CChainParams& params)
{
    UniValue details(UniValue::VOBJ);
    details.pushKV("type", PRIVATE_NOTE_PROOF_TYPE);
    details.pushKV("version", proof.nVersion);
    details.pushKV("proof_id", ProofId(proof).GetHex());
    details.pushKV("txid", proof.txid.GetHex());
    details.pushKV("action_index", static_cast<uint64_t>(proof.action_index));
    details.pushKV("blockhash", proof.block_hash.GetHex());
    details.pushKV("blockheight", proof.block_height);
    details.pushKV("commitment_index", proof.commitment_index == std::numeric_limits<uint64_t>::max() ? int64_t{-1} : static_cast<int64_t>(proof.commitment_index));
    details.pushKV("cmx", proof.cmx.GetHex());
    details.pushKV("amount", ValueFromAmount(proof.value));
    details.pushKV("private_address", EncodeNitoPrivateAddress(RawPrivateAddressArray(proof.recipient_raw), params));
    return details;
}

CPrivateNoteDisclosureProof MakePrivateNoteProof(const CPrivateWalletNote& note)
{
    if (!note.HasSpendSecrets()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private note does not have the decrypted note opening needed for a proof");
    }
    if (note.value <= 0 || !MoneyRange(note.value)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private note amount is out of range");
    }
    if (note.recipient_raw.size() != NITO_ORCHARD_RAW_ADDRESS_SIZE ||
        note.rho.size() != NITO_ORCHARD_RHO_SIZE ||
        note.rseed.size() != NITO_ORCHARD_RSEED_SIZE) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private note has invalid Orchard field sizes");
    }

    CPrivateNoteDisclosureProof proof;
    proof.txid = note.txid;
    proof.block_hash = note.block_hash;
    proof.block_height = note.block_height;
    proof.action_index = note.action_index;
    proof.commitment_index = note.commitment_index;
    proof.value = note.value;
    proof.cmx = note.cmx;
    proof.recipient_raw = note.recipient_raw;
    proof.rho = note.rho;
    proof.rseed = note.rseed;
    return proof;
}
} // namespace

static CAmount GetReceived(const CWallet& wallet, const UniValue& params, bool by_label) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::vector<CTxDestination> addresses;
    if (by_label) {
        // Get the set of addresses assigned to label
        addresses = wallet.ListAddrBookAddresses(CWallet::AddrBookFilter{LabelFromValue(params[0])});
        if (addresses.empty()) throw JSONRPCError(RPC_WALLET_ERROR, "Label not found in wallet");
    } else {
        // Get the address
        CTxDestination dest = DecodeDestination(params[0].get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Nito address");
        }
        addresses.emplace_back(dest);
    }

    // Filter by own scripts only
    std::set<CScript> output_scripts;
    for (const auto& address : addresses) {
        auto output_script{GetScriptForDestination(address)};
        if (wallet.IsMine(output_script)) {
            output_scripts.insert(output_script);
        }
    }

    if (output_scripts.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
    }

    // Minimum confirmations
    int min_depth = 1;
    if (!params[1].isNull())
        min_depth = params[1].getInt<int>();

    const bool include_immature_coinbase{params[2].isNull() ? false : params[2].get_bool()};

    // Tally
    CAmount amount = 0;
    for (const std::pair<const uint256, CWalletTx>& wtx_pair : wallet.mapWallet) {
        const CWalletTx& wtx = wtx_pair.second;
        int depth{wallet.GetTxDepthInMainChain(wtx)};
        if (depth < min_depth
            // Coinbase with less than 1 confirmation is no longer in the main chain
            || (wtx.IsCoinBase() && (depth < 1))
            || (wallet.IsTxImmatureCoinBase(wtx) && !include_immature_coinbase))
        {
            continue;
        }

        for (const CTxOut& txout : wtx.tx->vout) {
            if (output_scripts.count(txout.scriptPubKey) > 0) {
                amount += txout.nValue;
            }
        }
    }

    return amount;
}


RPCHelpMan getreceivedbyaddress()
{
    return RPCHelpMan{"getreceivedbyaddress",
                "\nReturns the total amount received by the given address in transactions with at least minconf confirmations.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The nito address for transactions."},
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Only include transactions confirmed at least this many times."},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                },
                RPCResult{
                    RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received at this address."
                },
                RPCExamples{
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 6") +
            "\nThe amount with at least 6 confirmations including immature coinbase outputs\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 6 true") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\", 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    return ValueFromAmount(GetReceived(*pwallet, request.params, /*by_label=*/false));
},
    };
}


RPCHelpMan getreceivedbylabel()
{
    return RPCHelpMan{"getreceivedbylabel",
                "\nReturns the total amount received by addresses with <label> in transactions with at least [minconf] confirmations.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The selected label, may be the default label using \"\"."},
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Only include transactions confirmed at least this many times."},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                },
                RPCResult{
                    RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received for this label."
                },
                RPCExamples{
            "\nAmount received by the default label with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbylabel", "\"\"") +
            "\nAmount received at the tabby label including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("getreceivedbylabel", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbylabel", "\"tabby\" 6") +
            "\nThe amount with at least 6 confirmations including immature coinbase outputs\n"
            + HelpExampleCli("getreceivedbylabel", "\"tabby\" 6 true") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getreceivedbylabel", "\"tabby\", 6, true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    return ValueFromAmount(GetReceived(*pwallet, request.params, /*by_label=*/true));
},
    };
}


RPCHelpMan getbalance()
{
    return RPCHelpMan{"getbalance",
                "\nReturns the total available balance.\n"
                "The available balance is what the wallet considers currently spendable, and is\n"
                "thus affected by options which limit spendability such as -spendzeroconfchange.\n",
                {
                    {"dummy", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Remains for backward compatibility. Must be excluded or set to \"*\"."},
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Only include transactions confirmed at least this many times."},
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Also include balance in watch-only addresses (see 'importaddress')"},
                    {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "(only available if avoid_reuse wallet flag is set) Do not include balance in dirty outputs; addresses are considered dirty if they have previously been used in a transaction."},
                },
                RPCResult{
                    RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received for this wallet."
                },
                RPCExamples{
            "\nThe total amount in the wallet with 0 or more confirmations\n"
            + HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet with at least 6 confirmations\n"
            + HelpExampleCli("getbalance", "\"*\" 6") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getbalance", "\"*\", 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);
    EnsureAvailableBalanceReady(*pwallet);

    const auto dummy_value{self.MaybeArg<std::string>(0)};
    if (dummy_value && *dummy_value != "*") {
        throw JSONRPCError(RPC_METHOD_DEPRECATED, "dummy first argument must be excluded or set to \"*\".");
    }

    int min_depth = 0;
    if (!request.params[1].isNull()) {
        min_depth = request.params[1].getInt<int>();
    }

    bool include_watchonly = ParseIncludeWatchonly(request.params[2], *pwallet);

    bool avoid_reuse = GetAvoidReuseFlag(*pwallet, request.params[3]);

    const auto bal = GetBalance(*pwallet, min_depth, avoid_reuse);

    return ValueFromAmount(bal.m_mine_trusted + (include_watchonly ? bal.m_watchonly_trusted : 0));
},
    };
}

RPCHelpMan getunconfirmedbalance()
{
    return RPCHelpMan{"getunconfirmedbalance",
                "DEPRECATED\nIdentical to getbalances().mine.untrusted_pending\n",
                {},
                RPCResult{RPCResult::Type::NUM, "", "The balance"},
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    return ValueFromAmount(GetBalance(*pwallet).m_mine_untrusted_pending);
},
    };
}

RPCHelpMan lockunspent()
{
    return RPCHelpMan{"lockunspent",
                "\nUpdates list of temporarily unspendable outputs.\n"
                "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
                "If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.\n"
                "A locked transaction output will not be chosen by automatic coin selection, when spending NITO.\n"
                "Manually selected coins are automatically unlocked.\n"
                "Locks are stored in memory only, unless persistent=true, in which case they will be written to the\n"
                "wallet database and loaded on node start. Unwritten (persistent=false) locks are always cleared\n"
                "(by virtue of process exit) when a node stops or fails. Unlocking will clear both persistent and not.\n"
                "Also see the listunspent call\n",
                {
                    {"unlock", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Whether to unlock (true) or lock (false) the specified transactions"},
                    {"transactions", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The transaction outputs and within each, the txid (string) vout (numeric).",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                },
                            },
                        },
                    },
                    {"persistent", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to write/erase this lock in the wallet database, or keep the change in memory only. Ignored for unlocking."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Whether the command was successful or not"
                },
                RPCExamples{
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nLock the transaction persistently in the wallet database\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\" true") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    bool fUnlock = request.params[0].get_bool();

    const bool persistent{request.params[2].isNull() ? false : request.params[2].get_bool()};

    if (request.params[1].isNull()) {
        if (fUnlock) {
            if (!pwallet->UnlockAllCoins())
                throw JSONRPCError(RPC_WALLET_ERROR, "Unlocking coins failed");
        }
        return true;
    }

    const UniValue& output_params = request.params[1].get_array();

    // Create and validate the COutPoints first.

    std::vector<COutPoint> outputs;
    outputs.reserve(output_params.size());

    for (unsigned int idx = 0; idx < output_params.size(); idx++) {
        const UniValue& o = output_params[idx].get_obj();

        RPCTypeCheckObj(o,
            {
                {"txid", UniValueType(UniValue::VSTR)},
                {"vout", UniValueType(UniValue::VNUM)},
            });

        const Txid txid = Txid::FromUint256(ParseHashO(o, "txid"));
        const int nOutput = o.find_value("vout").getInt<int>();
        if (nOutput < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout cannot be negative");
        }

        const COutPoint outpt(txid, nOutput);

        const auto it = pwallet->mapWallet.find(outpt.hash);
        if (it == pwallet->mapWallet.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, unknown transaction");
        }

        const CWalletTx& trans = it->second;

        if (outpt.n >= trans.tx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout index out of bounds");
        }

        if (pwallet->IsSpent(outpt)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected unspent output");
        }

        const bool is_locked = pwallet->IsLockedCoin(outpt);

        if (fUnlock && !is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected locked output");
        }

        if (!fUnlock && is_locked && !persistent) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output already locked");
        }

        outputs.push_back(outpt);
    }

    std::unique_ptr<WalletBatch> batch = nullptr;
    // Unlock is always persistent
    if (fUnlock || persistent) batch = std::make_unique<WalletBatch>(pwallet->GetDatabase());

    // Atomically set (un)locked status for the outputs.
    for (const COutPoint& outpt : outputs) {
        if (fUnlock) {
            if (!pwallet->UnlockCoin(outpt, batch.get())) throw JSONRPCError(RPC_WALLET_ERROR, "Unlocking coin failed");
        } else {
            if (!pwallet->LockCoin(outpt, batch.get())) throw JSONRPCError(RPC_WALLET_ERROR, "Locking coin failed");
        }
    }

    return true;
},
    };
}

RPCHelpMan listlockunspent()
{
    return RPCHelpMan{"listlockunspent",
                "\nReturns list of temporarily unspendable outputs.\n"
                "See the lockunspent call to lock and unlock transactions for spending.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id locked"},
                            {RPCResult::Type::NUM, "vout", "The vout value"},
                        }},
                    }
                },
                RPCExamples{
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listlockunspent", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    std::vector<COutPoint> vOutpts;
    pwallet->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    for (const COutPoint& outpt : vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.pushKV("txid", outpt.hash.GetHex());
        o.pushKV("vout", (int)outpt.n);
        ret.push_back(o);
    }

    return ret;
},
    };
}

RPCHelpMan getbalances()
{
    return RPCHelpMan{
        "getbalances",
        "Returns an object with all balances in " + CURRENCY_UNIT + ".\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ, "mine", "balances from outputs that the wallet can sign",
                {
                    {RPCResult::Type::STR_AMOUNT, "trusted", "trusted balance (outputs created by the wallet or confirmed outputs)"},
                    {RPCResult::Type::STR_AMOUNT, "untrusted_pending", "untrusted pending balance (outputs created by others that are in the mempool)"},
                    {RPCResult::Type::STR_AMOUNT, "immature", "balance from immature coinbase outputs"},
                    {RPCResult::Type::STR_AMOUNT, "used", /*optional=*/true, "(only present if avoid_reuse is set) balance from coins sent to addresses that were previously spent from (potentially privacy violating)"},
                }},
                {RPCResult::Type::OBJ, "private", /*optional=*/true, "Nito.network private-note balances from locally decrypted notes",
                {
                    {RPCResult::Type::STR_AMOUNT, "trusted", "confirmed spendable private-note balance"},
                    {RPCResult::Type::STR_AMOUNT, "untrusted_pending", "unconfirmed or not-yet-spendable private-note balance"},
                    {RPCResult::Type::STR_AMOUNT, "total_unspent", "all locally known unspent private notes"},
                }},
                {RPCResult::Type::OBJ, "watchonly", /*optional=*/true, "watchonly balances (not present if wallet does not watch anything)",
                {
                    {RPCResult::Type::STR_AMOUNT, "trusted", "trusted balance (outputs created by the wallet or confirmed outputs)"},
                    {RPCResult::Type::STR_AMOUNT, "untrusted_pending", "untrusted pending balance (outputs created by others that are in the mempool)"},
                    {RPCResult::Type::STR_AMOUNT, "immature", "balance from immature coinbase outputs"},
                }},
                RESULT_LAST_PROCESSED_BLOCK,
            }
            },
        RPCExamples{
            HelpExampleCli("getbalances", "") +
            HelpExampleRpc("getbalances", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const rpc_wallet = GetWalletForJSONRPCRequest(request);
    if (!rpc_wallet) return UniValue::VNULL;
    CWallet& wallet = *rpc_wallet;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    LOCK(wallet.cs_wallet);
    EnsureAvailableBalanceReady(wallet);

    const auto bal = GetBalance(wallet);
    UniValue balances{UniValue::VOBJ};
    {
        UniValue balances_mine{UniValue::VOBJ};
        balances_mine.pushKV("trusted", ValueFromAmount(bal.m_mine_trusted));
        balances_mine.pushKV("untrusted_pending", ValueFromAmount(bal.m_mine_untrusted_pending));
        balances_mine.pushKV("immature", ValueFromAmount(bal.m_mine_immature));
        if (wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            // If the AVOID_REUSE flag is set, bal has been set to just the un-reused address balance. Get
            // the total balance, and then subtract bal to get the reused address balance.
            const auto full_bal = GetBalance(wallet, 0, false);
            balances_mine.pushKV("used", ValueFromAmount(full_bal.m_mine_trusted + full_bal.m_mine_untrusted_pending - bal.m_mine_trusted - bal.m_mine_untrusted_pending));
        }
        balances.pushKV("mine", balances_mine);
    }
    if (IsPrivateTxActiveForWallet(wallet)) {
        if (!wallet.IsLocked() && HasPrivateWalletIndex(wallet)) {
            const PrivateBalanceSnapshot private_bal = GetPrivateBalanceSnapshot(wallet);
            UniValue balances_private{UniValue::VOBJ};
            balances_private.pushKV("trusted", ValueFromAmount(private_bal.trusted));
            balances_private.pushKV("untrusted_pending", ValueFromAmount(private_bal.untrusted));
            balances_private.pushKV("total_unspent", ValueFromAmount(private_bal.total_unspent));
            balances.pushKV("private", balances_private);
        }
    }
    auto spk_man = wallet.GetLegacyScriptPubKeyMan();
    if (spk_man && spk_man->HaveWatchOnly()) {
        UniValue balances_watchonly{UniValue::VOBJ};
        balances_watchonly.pushKV("trusted", ValueFromAmount(bal.m_watchonly_trusted));
        balances_watchonly.pushKV("untrusted_pending", ValueFromAmount(bal.m_watchonly_untrusted_pending));
        balances_watchonly.pushKV("immature", ValueFromAmount(bal.m_watchonly_immature));
        balances.pushKV("watchonly", balances_watchonly);
    }

    AppendLastProcessedBlock(balances, wallet);
    return balances;
},
    };
}

RPCHelpMan listunspent()
{
    return RPCHelpMan{
                "listunspent",
                "\nReturns array of unspent transaction outputs\n"
                "with between minconf and maxconf (inclusive) confirmations.\n"
                "Optionally filter to only include txouts paid to specified addresses.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum confirmations to filter"},
                    {"maxconf", RPCArg::Type::NUM, RPCArg::Default{9999999}, "The maximum confirmations to filter"},
                    {"addresses", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The nito addresses to filter",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "nito address"},
                        },
                    },
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include outputs that are not safe to spend\n"
                              "See description of \"safe\" attribute below."},
                    {"query_options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                        {
                            {"minimumAmount", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(0)}, "Minimum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Maximum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumCount", RPCArg::Type::NUM, RPCArg::DefaultHint{"unlimited"}, "Maximum number of UTXOs"},
                            {"minimumSumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Minimum sum value of all UTXOs in " + CURRENCY_UNIT + ""},
                            {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase UTXOs"}
                        },
                        RPCArgOptions{.oneline_description="query_options"}},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "the transaction id"},
                            {RPCResult::Type::NUM, "vout", "the vout value"},
                            {RPCResult::Type::STR, "address", /*optional=*/true, "the nito address"},
                            {RPCResult::Type::STR, "label", /*optional=*/true, "The associated label, or \"\" for the default label"},
                            {RPCResult::Type::STR, "scriptPubKey", "the script key"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "the transaction output amount in " + CURRENCY_UNIT},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                            {RPCResult::Type::NUM, "ancestorcount", /*optional=*/true, "The number of in-mempool ancestor transactions, including this one (if transaction is in the mempool)"},
                            {RPCResult::Type::NUM, "ancestorsize", /*optional=*/true, "The virtual transaction size of in-mempool ancestors, including this one (if transaction is in the mempool)"},
                            {RPCResult::Type::STR_AMOUNT, "ancestorfees", /*optional=*/true, "The total fees of in-mempool ancestors (including this one) with fee deltas used for mining priority in " + CURRENCY_ATOM + " (if transaction is in the mempool)"},
                            {RPCResult::Type::STR_HEX, "redeemScript", /*optional=*/true, "The redeemScript if scriptPubKey is P2SH"},
                            {RPCResult::Type::STR, "witnessScript", /*optional=*/true, "witnessScript if the scriptPubKey is P2WSH or P2SH-P2WSH"},
                            {RPCResult::Type::BOOL, "spendable", "Whether we have the private keys to spend this output"},
                            {RPCResult::Type::BOOL, "solvable", "Whether we know how to spend this output, ignoring the lack of keys"},
                            {RPCResult::Type::BOOL, "reused", /*optional=*/true, "(only present if avoid_reuse is set) Whether this output is reused/dirty (sent to an address that was previously spent from)"},
                            {RPCResult::Type::STR, "desc", /*optional=*/true, "(only when solvable) A descriptor for spending this output"},
                            {RPCResult::Type::ARR, "parent_descs", /*optional=*/false, "List of parent descriptors for the scriptPubKey of this coin.", {
                                {RPCResult::Type::STR, "desc", "The descriptor string."},
                            }},
                            {RPCResult::Type::BOOL, "safe", "Whether this output is considered safe to spend. Unconfirmed transactions\n"
                                                            "from outside keys and unconfirmed replacement transactions are considered unsafe\n"
                                                            "and are not eligible for spending by fundrawtransaction and sendtoaddress."},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listunspent", "")
            + HelpExampleCli("listunspent", "6 9999999 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"")
            + HelpExampleRpc("listunspent", "6, 9999999 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"")
            + HelpExampleCli("listunspent", "6 9999999 '[]' true '{ \"minimumAmount\": 0.005 }'")
            + HelpExampleRpc("listunspent", "6, 9999999, [] , true, { \"minimumAmount\": 0.005 } ")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    int nMinDepth = 1;
    if (!request.params[0].isNull()) {
        nMinDepth = request.params[0].getInt<int>();
    }

    int nMaxDepth = 9999999;
    if (!request.params[1].isNull()) {
        nMaxDepth = request.params[1].getInt<int>();
    }

    std::set<CTxDestination> destinations;
    if (!request.params[2].isNull()) {
        UniValue inputs = request.params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CTxDestination dest = DecodeDestination(input.get_str());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Nito address: ") + input.get_str());
            }
            if (!destinations.insert(dest).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + input.get_str());
            }
        }
    }

    bool include_unsafe = true;
    if (!request.params[3].isNull()) {
        include_unsafe = request.params[3].get_bool();
    }

    CoinFilterParams filter_coins;
    filter_coins.min_amount = 0;

    if (!request.params[4].isNull()) {
        const UniValue& options = request.params[4].get_obj();

        RPCTypeCheckObj(options,
            {
                {"minimumAmount", UniValueType()},
                {"maximumAmount", UniValueType()},
                {"minimumSumAmount", UniValueType()},
                {"maximumCount", UniValueType(UniValue::VNUM)},
                {"include_immature_coinbase", UniValueType(UniValue::VBOOL)}
            },
            true, true);

        if (options.exists("minimumAmount"))
            filter_coins.min_amount = AmountFromValue(options["minimumAmount"]);

        if (options.exists("maximumAmount"))
            filter_coins.max_amount = AmountFromValue(options["maximumAmount"]);

        if (options.exists("minimumSumAmount"))
            filter_coins.min_sum_amount = AmountFromValue(options["minimumSumAmount"]);

        if (options.exists("maximumCount"))
            filter_coins.max_count = options["maximumCount"].getInt<int64_t>();

        if (options.exists("include_immature_coinbase")) {
            filter_coins.include_immature_coinbase = options["include_immature_coinbase"].get_bool();
        }
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue results(UniValue::VARR);
    std::vector<COutput> vecOutputs;
    {
        CCoinControl cctl;
        cctl.m_avoid_address_reuse = false;
        cctl.m_min_depth = nMinDepth;
        cctl.m_max_depth = nMaxDepth;
        cctl.m_include_unsafe_inputs = include_unsafe;
        LOCK(pwallet->cs_wallet);
        EnsureAvailableBalanceReady(*pwallet);
        vecOutputs = AvailableCoinsListUnspent(*pwallet, &cctl, filter_coins).All();
    }

    LOCK(pwallet->cs_wallet);

    const bool avoid_reuse = pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);

    for (const COutput& out : vecOutputs) {
        CTxDestination address;
        const CScript& scriptPubKey = out.txout.scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);
        bool reused = avoid_reuse && pwallet->IsSpentKey(scriptPubKey);

        if (destinations.size() && (!fValidAddress || !destinations.count(address)))
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", out.outpoint.hash.GetHex());
        entry.pushKV("vout", (int)out.outpoint.n);

        if (fValidAddress) {
            entry.pushKV("address", EncodeDestination(address));

            const auto* address_book_entry = pwallet->FindAddressBookEntry(address);
            if (address_book_entry) {
                entry.pushKV("label", address_book_entry->GetLabel());
            }

            std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(scriptPubKey);
            if (provider) {
                if (scriptPubKey.IsPayToScriptHash()) {
                    const CScriptID hash = ToScriptID(std::get<ScriptHash>(address));
                    CScript redeemScript;
                    if (provider->GetCScript(hash, redeemScript)) {
                        entry.pushKV("redeemScript", HexStr(redeemScript));
                        // Now check if the redeemScript is actually a P2WSH script
                        CTxDestination witness_destination;
                        if (redeemScript.IsPayToWitnessScriptHash()) {
                            bool extracted = ExtractDestination(redeemScript, witness_destination);
                            CHECK_NONFATAL(extracted);
                            // Also return the witness script
                            const WitnessV0ScriptHash& whash = std::get<WitnessV0ScriptHash>(witness_destination);
                            CScriptID id{RIPEMD160(whash)};
                            CScript witnessScript;
                            if (provider->GetCScript(id, witnessScript)) {
                                entry.pushKV("witnessScript", HexStr(witnessScript));
                            }
                        }
                    }
                } else if (scriptPubKey.IsPayToWitnessScriptHash()) {
                    const WitnessV0ScriptHash& whash = std::get<WitnessV0ScriptHash>(address);
                    CScriptID id{RIPEMD160(whash)};
                    CScript witnessScript;
                    if (provider->GetCScript(id, witnessScript)) {
                        entry.pushKV("witnessScript", HexStr(witnessScript));
                    }
                }
            }
        }

        entry.pushKV("scriptPubKey", HexStr(scriptPubKey));
        entry.pushKV("amount", ValueFromAmount(out.txout.nValue));
        entry.pushKV("confirmations", out.depth);
        if (!out.depth) {
            size_t ancestor_count, descendant_count, ancestor_size;
            CAmount ancestor_fees;
            pwallet->chain().getTransactionAncestry(out.outpoint.hash, ancestor_count, descendant_count, &ancestor_size, &ancestor_fees);
            if (ancestor_count) {
                entry.pushKV("ancestorcount", uint64_t(ancestor_count));
                entry.pushKV("ancestorsize", uint64_t(ancestor_size));
                entry.pushKV("ancestorfees", uint64_t(ancestor_fees));
            }
        }
        entry.pushKV("spendable", out.spendable);
        entry.pushKV("solvable", out.solvable);
        if (out.solvable) {
            std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(scriptPubKey);
            if (provider) {
                auto descriptor = InferDescriptor(scriptPubKey, *provider);
                entry.pushKV("desc", descriptor->ToString());
            }
        }
        PushParentDescriptors(*pwallet, scriptPubKey, entry);
        if (avoid_reuse) entry.pushKV("reused", reused);
        entry.pushKV("safe", out.safe);
        results.push_back(entry);
    }

    return results;
},
    };
}

RPCHelpMan getprivatebalance()
{
    return RPCHelpMan{
        "getprivatebalance",
        "\nReturns experimental Nito.network private wallet balances from locally decrypted notes.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "trusted", "Confirmed, spendable private balance in " + CURRENCY_UNIT},
                {RPCResult::Type::STR_AMOUNT, "untrusted_pending", "Unconfirmed private notes in " + CURRENCY_UNIT},
                {RPCResult::Type::STR_AMOUNT, "total_unspent", "All locally known unspent private notes in " + CURRENCY_UNIT},
                {RPCResult::Type::NUM, "notes", "Number of locally known private notes"},
                {RPCResult::Type::NUM, "spendable_notes", "Number of confirmed private notes with witness data and spend secrets"},
            }
        },
        RPCExamples{
            HelpExampleCli("getprivatebalance", "")
            + HelpExampleRpc("getprivatebalance", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    pwallet->BlockUntilSyncedToCurrentChain();

    PrivateBalanceSnapshot snapshot;
    {
        LOCK(pwallet->cs_wallet);
        EnsurePrivateTxActiveForWallet(*pwallet);
        EnsureWalletIsUnlocked(*pwallet);
        EnsurePrivateWalletIndexAvailable(*pwallet);
        snapshot = GetPrivateBalanceSnapshot(*pwallet);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("trusted", ValueFromAmount(snapshot.trusted));
    result.pushKV("untrusted_pending", ValueFromAmount(snapshot.untrusted));
    result.pushKV("total_unspent", ValueFromAmount(snapshot.total_unspent));
    result.pushKV("notes", snapshot.notes_count);
    result.pushKV("spendable_notes", snapshot.spendable_notes);
    return result;
},
    };
}

RPCHelpMan listprivateunspent()
{
    return RPCHelpMan{
        "listprivateunspent",
        "\nReturns locally decrypted experimental Nito.network private notes.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum confirmations to filter"},
            {"include_spent", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include notes already marked spent by nullifier"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "cmx", "Private note commitment"},
                    {RPCResult::Type::STR_HEX, "nullifier", "Private note nullifier"},
                    {RPCResult::Type::STR_HEX, "txid", "Transaction that created the note"},
                    {RPCResult::Type::STR_HEX, "blockhash", "Block hash if confirmed"},
                    {RPCResult::Type::NUM, "blockheight", "Block height if confirmed"},
                    {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Private note amount in " + CURRENCY_UNIT},
                    {RPCResult::Type::BOOL, "spent", "Whether this note has been spent by a known nullifier"},
                    {RPCResult::Type::BOOL, "spendable", "Whether the wallet has all data needed to spend this note now"},
                    {RPCResult::Type::NUM, "commitment_index", "Private commitment tree position, or -1 if not known yet"},
                    {RPCResult::Type::STR, "derivation_id", "Stable Nito.network private derivation identifier"},
                    {RPCResult::Type::NUM, "derivation_version", "Stable Nito.network private derivation version"},
                    {RPCResult::Type::NUM, "account", "Private HD account"},
                    {RPCResult::Type::BOOL, "internal", "Whether this note belongs to the internal/change branch"},
                    {RPCResult::Type::STR, "scope", "Orchard note scope"},
                    {RPCResult::Type::NUM, "diversifier_index", "Private HD diversifier index"},
                    {RPCResult::Type::STR, "path", "Nito private HD path"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("listprivateunspent", "")
            + HelpExampleRpc("listprivateunspent", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    int min_depth = 1;
    if (!request.params[0].isNull()) {
        min_depth = request.params[0].getInt<int>();
    }
    const bool include_spent = !request.params[1].isNull() && request.params[1].get_bool();

    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue results(UniValue::VARR);
    LOCK(pwallet->cs_wallet);
    EnsurePrivateTxActiveForWallet(*pwallet);
    EnsureWalletIsUnlocked(*pwallet);
    EnsurePrivateWalletIndexAvailable(*pwallet);
    for (const auto& [cmx, note] : pwallet->mapPrivateNotes) {
        if (note.spent && !include_spent) continue;
        if (!PrivateNoteTxIsActive(*pwallet, note)) continue;
        const int depth = note.IsConfirmed() ? std::max(0, pwallet->GetLastBlockHeight() - note.block_height + 1) : 0;
        if (depth < min_depth) continue;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("cmx", note.cmx.GetHex());
        entry.pushKV("nullifier", note.nullifier.GetHex());
        entry.pushKV("txid", note.txid.GetHex());
        entry.pushKV("blockhash", note.block_hash.GetHex());
        entry.pushKV("blockheight", note.block_height);
        entry.pushKV("confirmations", depth);
        entry.pushKV("amount", ValueFromAmount(note.value));
        entry.pushKV("spent", note.spent);
        entry.pushKV("spendable", note.IsSpendable());
        entry.pushKV("commitment_index", note.HasWitnessPosition() ? static_cast<int64_t>(note.commitment_index) : int64_t{-1});
        entry.pushKV("derivation_id", NITO_PRIVATE_ORCHARD_DERIVATION_ID);
        entry.pushKV("derivation_version", static_cast<int64_t>(note.derivation_version));
        entry.pushKV("account", static_cast<int64_t>(note.account));
        entry.pushKV("internal", note.internal);
        entry.pushKV("scope", note.internal ? "internal" : "external");
        entry.pushKV("diversifier_index", static_cast<int64_t>(note.diversifier_index));
        entry.pushKV("path", PrivateOrchardKeyPath{note.account, note.internal, note.diversifier_index, note.derivation_version}.ToString());
        results.push_back(entry);
    }
    return results;
},
    };
}

RPCHelpMan getprivatenoteproof()
{
    return RPCHelpMan{
        "getprivatenoteproof",
        "\nExports a voluntary Nito.network private note proof for a locally decrypted note.\n"
        "\nThe proof opens one private note commitment to its amount and private address without revealing the spending key.\n"
        "Anyone who receives the proof can run checkprivatenoteproof and compare the cmx/txid/action_index with the public transaction.\n"
        "Treat the proof as sensitive: it reveals the selected private note amount, recipient and note opening.\n",
        {
            {"cmx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The private note commitment from listprivateunspent."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "proof", "Serialized private note proof. It reveals this note opening but not the spending key."},
                {RPCResult::Type::STR, "warning", "Disclosure warning"},
                {RPCResult::Type::OBJ, "details", "Human-readable proof summary",
                {
                    {RPCResult::Type::STR, "type", "Proof type"},
                    {RPCResult::Type::NUM, "version", "Proof version"},
                    {RPCResult::Type::STR_HEX, "proof_id", "Hash of the serialized proof"},
                    {RPCResult::Type::STR_HEX, "txid", "Transaction that created the note"},
                    {RPCResult::Type::NUM, "action_index", "Private action index inside the transaction"},
                    {RPCResult::Type::STR_HEX, "blockhash", "Block hash if confirmed"},
                    {RPCResult::Type::NUM, "blockheight", "Block height if confirmed"},
                    {RPCResult::Type::NUM, "commitment_index", "Private commitment tree position, or -1 if not known"},
                    {RPCResult::Type::STR_HEX, "cmx", "Private note commitment opened by the proof"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Private note amount in " + CURRENCY_UNIT},
                    {RPCResult::Type::STR, "private_address", "Nito private address receiving the note"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("getprivatenoteproof", "\"<cmx-from-listprivateunspent>\"")
            + HelpExampleRpc("getprivatenoteproof", "\"<cmx-from-listprivateunspent>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    EnsureWalletIsUnlocked(*pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();

    const uint256 cmx = ParseHashV(request.params[0], "cmx");
    CPrivateNoteDisclosureProof proof;
    {
        LOCK(pwallet->cs_wallet);
        EnsurePrivateTxActiveForWallet(*pwallet);
        EnsurePrivateWalletIndexAvailable(*pwallet);
        const auto it = pwallet->mapPrivateNotes.find(cmx);
        if (it == pwallet->mapPrivateNotes.end()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Private note commitment not found in this wallet");
        }
        if (!PrivateNoteTxIsActive(*pwallet, it->second)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Private note transaction is not active in the current chain or mempool");
        }
        proof = MakePrivateNoteProof(it->second);
    }

    std::string error;
    uint256 recomputed;
    const auto res = ComputePrivateOrchardNoteCommitment(
        Span<const unsigned char>{proof.recipient_raw.data(), proof.recipient_raw.size()},
        proof.value,
        Span<const unsigned char>{proof.rho.data(), proof.rho.size()},
        Span<const unsigned char>{proof.rseed.data(), proof.rseed.size()},
        recomputed,
        error);
    if (res != PrivateOrchardBuildResult::OK || recomputed != proof.cmx) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.empty() ? "Private note proof self-check failed" : error);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("proof", ProofToHex(proof));
    result.pushKV("warning", "This proof reveals one private note opening. It cannot spend the note, but it reveals the amount and recipient for this note.");
    result.pushKV("details", PrivateNoteProofDetails(proof, Params()));
    return result;
},
    };
}

RPCHelpMan checkprivatenoteproof()
{
    return RPCHelpMan{
        "checkprivatenoteproof",
        "\nChecks a voluntary Nito.network private note proof.\n"
        "\nThis verifies that the disclosed recipient, amount and note randomness recompute the disclosed Orchard commitment.\n"
        "If the creating transaction is present in the current wallet, the RPC also checks that txid/action_index contains the same cmx.\n",
        {
            {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized private note proof from getprivatenoteproof."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "True when the commitment opening is valid and any available wallet transaction match succeeds"},
                {RPCResult::Type::BOOL, "commitment_valid", "True when the proof recomputes the disclosed cmx"},
                {RPCResult::Type::STR_HEX, "computed_cmx", "Commitment recomputed from the proof opening"},
                {RPCResult::Type::BOOL, "wallet_tx_found", "True if this wallet has the proof txid locally"},
                {RPCResult::Type::BOOL, "wallet_tx_action_matches", "True if the local wallet tx has the same cmx at action_index"},
                {RPCResult::Type::OBJ, "details", "Human-readable proof summary",
                {
                    {RPCResult::Type::STR, "type", "Proof type"},
                    {RPCResult::Type::NUM, "version", "Proof version"},
                    {RPCResult::Type::STR_HEX, "proof_id", "Hash of the serialized proof"},
                    {RPCResult::Type::STR_HEX, "txid", "Transaction that created the note"},
                    {RPCResult::Type::NUM, "action_index", "Private action index inside the transaction"},
                    {RPCResult::Type::STR_HEX, "blockhash", "Block hash if confirmed"},
                    {RPCResult::Type::NUM, "blockheight", "Block height if confirmed"},
                    {RPCResult::Type::NUM, "commitment_index", "Private commitment tree position, or -1 if not known"},
                    {RPCResult::Type::STR_HEX, "cmx", "Private note commitment opened by the proof"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Private note amount in " + CURRENCY_UNIT},
                    {RPCResult::Type::STR, "private_address", "Nito private address receiving the note"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("checkprivatenoteproof", "\"<proof-hex>\"")
            + HelpExampleRpc("checkprivatenoteproof", "\"<proof-hex>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const CPrivateNoteDisclosureProof proof = ProofFromHex(request.params[0]);

    std::string error;
    uint256 computed;
    const auto res = ComputePrivateOrchardNoteCommitment(
        Span<const unsigned char>{proof.recipient_raw.data(), proof.recipient_raw.size()},
        proof.value,
        Span<const unsigned char>{proof.rho.data(), proof.rho.size()},
        Span<const unsigned char>{proof.rseed.data(), proof.rseed.size()},
        computed,
        error);
    if (res != PrivateOrchardBuildResult::OK) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error.empty() ? "Private note proof commitment check failed" : error);
    }

    const bool commitment_valid = computed == proof.cmx;
    bool wallet_tx_found = false;
    bool wallet_tx_action_matches = false;
    {
        LOCK(pwallet->cs_wallet);
        const auto it = pwallet->mapWallet.find(proof.txid);
        if (it != pwallet->mapWallet.end()) {
            wallet_tx_found = true;
            const CTransactionRef& tx = it->second.tx;
            if (tx && tx->HasPrivateBundle()) {
                const auto& actions = tx->m_private_bundle->effects.actions;
                if (proof.action_index < actions.size()) {
                    wallet_tx_action_matches = actions[proof.action_index].cmx == proof.cmx;
                }
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("valid", commitment_valid && (!wallet_tx_found || wallet_tx_action_matches));
    result.pushKV("commitment_valid", commitment_valid);
    result.pushKV("computed_cmx", computed.GetHex());
    result.pushKV("wallet_tx_found", wallet_tx_found);
    result.pushKV("wallet_tx_action_matches", wallet_tx_action_matches);
    result.pushKV("details", PrivateNoteProofDetails(proof, Params()));
    return result;
},
    };
}
} // namespace wallet
