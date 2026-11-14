// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/nito-config.h>
#endif

#include <core_io.h>
#include <chainparams.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <util/fs.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/bip39.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/rpc/wallet.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <optional>
#include <utility>

#include <univalue.h>


namespace wallet {

static const std::map<uint64_t, std::string> WALLET_FLAG_CAVEATS{
    {WALLET_FLAG_AVOID_REUSE,
     "You need to rescan the blockchain in order to correctly mark used "
     "destinations in the past. Until this is done, some destinations may "
     "be considered unused, even if the opposite is the case."},
};

/** Checks if a CKey is in the given CWallet compressed or otherwise*/
bool HaveKey(const SigningProvider& wallet, const CKey& key)
{
    CKey key2;
    key2.Set(key.begin(), key.end(), !key.IsCompressed());
    return wallet.HaveKey(key.GetPubKey().GetID()) || wallet.HaveKey(key2.GetPubKey().GetID());
}

struct HDSeedInput
{
    CKey key;
    bool bip39_mnemonic{false};
    bool generated_random{false};
};

static SecureString GetBIP39PassphraseFromRPCArgument(const UniValue& value)
{
    if (value.isNull()) return {};

    const std::string& raw_passphrase{value.get_str()};
    if (raw_passphrase.size() > MAX_BIP39_PASSPHRASE_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "BIP39 passphrase exceeds the maximum of %u UTF-8 bytes",
            static_cast<unsigned>(MAX_BIP39_PASSPHRASE_SIZE)));
    }

    SecureString passphrase;
    passphrase.reserve(raw_passphrase.size());
    passphrase.assign(raw_passphrase.begin(), raw_passphrase.end());
    auto normalized = NormalizeBIP39Passphrase(passphrase);
    if (!normalized) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, util::ErrorString(normalized).original);
    }
    return std::move(*normalized);
}

HDSeedInput GetSeedKeyFromRPCArgument(const UniValue& value)
{
    if (value.isNull()) {
        return {GenerateRandomKey(), /*bip39_mnemonic=*/false, /*generated_random=*/true};
    }

    const std::string seed{value.get_str()};
    CKey key = DecodeSecret(seed);
    if (key.IsValid()) {
        return {key, /*bip39_mnemonic=*/false, /*generated_random=*/false};
    }

    auto mnemonic_key = DecodeBIP39Mnemonic(seed);
    if (!mnemonic_key) {
        const std::string error = LooksLikeBIP39Mnemonic(seed) ? util::ErrorString(mnemonic_key).original : "Invalid private key or BIP39 mnemonic";
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }
    return {std::move(*mnemonic_key), /*bip39_mnemonic=*/true, /*generated_random=*/false};
}

static RPCHelpMan getwalletinfo()
{
    return RPCHelpMan{"getwalletinfo",
                "Returns an object containing various wallet state info.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                        {RPCResult::Type::NUM, "walletversion", "the wallet version"},
                        {RPCResult::Type::STR, "format", "the database format (bdb or sqlite)"},
                        {RPCResult::Type::STR_AMOUNT, "balance", "DEPRECATED. Identical to getbalances().mine.trusted"},
                        {RPCResult::Type::STR_AMOUNT, "unconfirmed_balance", "DEPRECATED. Identical to getbalances().mine.untrusted_pending"},
                        {RPCResult::Type::STR_AMOUNT, "immature_balance", "DEPRECATED. Identical to getbalances().mine.immature"},
                        {RPCResult::Type::NUM, "txcount", "the total number of transactions in the wallet"},
                        {RPCResult::Type::NUM_TIME, "keypoololdest", /*optional=*/true, "the " + UNIX_EPOCH_TIME + " of the oldest pre-generated key in the key pool. Legacy wallets only."},
                        {RPCResult::Type::NUM, "keypoolsize", "how many new keys are pre-generated (only counts external keys)"},
                        {RPCResult::Type::NUM, "keypoolsize_hd_internal", /*optional=*/true, "how many new keys are pre-generated for internal use (used for change outputs, only appears if the wallet is using this feature, otherwise external keys are used)"},
                        {RPCResult::Type::NUM_TIME, "unlocked_until", /*optional=*/true, "the " + UNIX_EPOCH_TIME + " until which the wallet is unlocked for transfers, or 0 if the wallet is locked (only present for passphrase-encrypted wallets)"},
                        {RPCResult::Type::STR_AMOUNT, "paytxfee", "the transaction fee configuration, set in " + CURRENCY_UNIT + "/kvB"},
                        {RPCResult::Type::STR_HEX, "hdseedid", /*optional=*/true, "the Hash160 of the HD seed (only present when HD is enabled)"},
                        {RPCResult::Type::BOOL, "bip39_passphrase_enabled", /*optional=*/true, "true when restoring this recovery phrase also requires its BIP39 passphrase"},
                        {RPCResult::Type::BOOL, "private_keys_enabled", "false if privatekeys are disabled for this wallet (enforced watch-only wallet)"},
                        {RPCResult::Type::BOOL, "avoid_reuse", "whether this wallet tracks clean/dirty coins in terms of reuse"},
                        {RPCResult::Type::OBJ, "scanning", "current scanning details, or false if no scan is in progress",
                        {
                            {RPCResult::Type::NUM, "duration", "elapsed seconds since scan start"},
                            {RPCResult::Type::NUM, "progress", "scanning progress percentage [0.0, 1.0]"},
                        }, /*skip_type_check=*/true},
                        {RPCResult::Type::BOOL, "descriptors", "whether this wallet uses descriptors for scriptPubKey management"},
                        {RPCResult::Type::BOOL, "external_signer", "whether this wallet is configured to use an external signer such as a hardware wallet"},
                        {RPCResult::Type::BOOL, "blank", "Whether this wallet intentionally does not contain any keys, scripts, or descriptors"},
                        {RPCResult::Type::OBJ, "seed_history", "Nito recovery-phrase history status",
                        {
                            {RPCResult::Type::STR, "mode", "\"unknown\", \"available_balance\", or \"full_history\""},
                            {RPCResult::Type::BOOL, "sync_pending", "true when automatic recovery is still catching up with chain synchronization"},
                            {RPCResult::Type::NUM, "full_history_height", "Last block height covered by a full-history scan, or -1 if never completed"},
                            {RPCResult::Type::STR_HEX, "full_history_block", "Last block hash covered by a full-history scan, or null hash if never completed"},
                            {RPCResult::Type::OBJ, "transparent", "Transparent recovery obligations", {}, /*skip_type_check=*/true},
                            {RPCResult::Type::OBJ, "orchard", "Orchard recovery obligations", {}, /*skip_type_check=*/true},
                            {RPCResult::Type::OBJ, "locked_live", "Deferred Orchard live scan received while the wallet was locked", {}, /*skip_type_check=*/true},
                        }},
                        {RPCResult::Type::NUM_TIME, "birthtime", /*optional=*/true, "The start time for blocks scanning. It could be modified by (re)importing any descriptor with an earlier timestamp."},
                        RESULT_LAST_PROCESSED_BLOCK,
                    }},
                },
                RPCExamples{
                    HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    UniValue obj(UniValue::VOBJ);

    size_t kpExternalSize = pwallet->KeypoolCountExternalKeys();
    const bool available_balance_sync_pending{pwallet->IsAvailableBalanceSyncPending()};
    const SeedHistoryState seed_history{pwallet->GetSeedHistoryState()};
    const CPrivateWalletChain private_chain{pwallet->GetOrchardKeyMan().GetChain()};
    const auto bal = GetBalance(*pwallet);
    obj.pushKV("walletname", pwallet->GetName());
    obj.pushKV("walletversion", pwallet->GetVersion());
    obj.pushKV("format", pwallet->GetDatabase().Format());
    obj.pushKV("balance", ValueFromAmount(bal.m_mine_trusted));
    obj.pushKV("unconfirmed_balance", ValueFromAmount(bal.m_mine_untrusted_pending));
    obj.pushKV("immature_balance", ValueFromAmount(bal.m_mine_immature));
    int tx_count{static_cast<int>(pwallet->mapWallet.size())};
    if (seed_history.m_mode == SeedHistoryMode::AVAILABLE_BALANCE) {
        tx_count = 0;
        for (const auto& entry : pwallet->mapWallet) {
            if (pwallet->ShouldShowTransaction(entry.second)) ++tx_count;
        }
    }
    obj.pushKV("txcount", tx_count);
    const auto kp_oldest = pwallet->GetOldestKeyPoolTime();
    if (kp_oldest.has_value()) {
        obj.pushKV("keypoololdest", kp_oldest.value());
    }
    obj.pushKV("keypoolsize", (int64_t)kpExternalSize);

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (spk_man) {
        CKeyID seed_id = spk_man->GetHDChain().seed_id;
        if (!seed_id.IsNull()) {
            obj.pushKV("hdseedid", seed_id.GetHex());
        }
    }

    if (pwallet->CanSupportFeature(FEATURE_HD_SPLIT)) {
        obj.pushKV("keypoolsize_hd_internal",   (int64_t)(pwallet->GetKeyPoolSize() - kpExternalSize));
    }
    if (pwallet->IsCrypted()) {
        obj.pushKV("unlocked_until", pwallet->nRelockTime);
    }
    obj.pushKV("paytxfee", ValueFromAmount(pwallet->m_pay_tx_fee.GetFeePerK()));
    if (!private_chain.hd_seed_id.IsNull()) {
        obj.pushKV("bip39_passphrase_enabled", pwallet->IsBIP39PassphraseEnabled());
    }
    obj.pushKV("private_keys_enabled", !pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    obj.pushKV("avoid_reuse", pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE));
    if (pwallet->IsScanning()) {
        UniValue scanning(UniValue::VOBJ);
        scanning.pushKV("duration", Ticks<std::chrono::seconds>(pwallet->ScanningDuration()));
        scanning.pushKV("progress", pwallet->ScanningProgress());
        obj.pushKV("scanning", scanning);
    } else {
        obj.pushKV("scanning", false);
    }
    obj.pushKV("descriptors", pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    obj.pushKV("external_signer", pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));
    obj.pushKV("blank", pwallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    UniValue seed_history_obj(UniValue::VOBJ);
    seed_history_obj.pushKV("mode", seed_history.ModeString());
    seed_history_obj.pushKV("sync_pending", available_balance_sync_pending);
    seed_history_obj.pushKV("full_history_height", seed_history.m_full_history_height);
    seed_history_obj.pushKV("full_history_block", seed_history.m_full_history_block.GetHex());
    auto recovery_progress_json = [](const SeedRecoveryProgress& progress) {
        UniValue value(UniValue::VOBJ);
        value.pushKV("status", progress.StatusString());
        value.pushKV("target_height", progress.m_height);
        value.pushKV("target_block", progress.m_block.GetHex());
        return value;
    };
    auto recovery_domain_json = [&](const SeedRecoveryDomainState& domain) {
        UniValue value(UniValue::VOBJ);
        value.pushKV("restore_funds", recovery_progress_json(domain.m_restore_funds));
        value.pushKV("explicit_history", recovery_progress_json(domain.m_explicit_history));
        return value;
    };
    seed_history_obj.pushKV("transparent", recovery_domain_json(seed_history.m_transparent));
    seed_history_obj.pushKV("orchard", recovery_domain_json(seed_history.m_orchard));
    UniValue locked_live(UniValue::VOBJ);
    if (private_chain.hd_seed_id.IsNull()) {
        locked_live.pushKV("status", "not_applicable");
    } else if (private_chain.private_locked_live_scan.IsPending()) {
        locked_live.pushKV("status", "pending");
    } else {
        locked_live.pushKV("status", "complete");
    }
    locked_live.pushKV("start_height", private_chain.private_locked_live_scan.start_height);
    locked_live.pushKV("start_block", private_chain.private_locked_live_scan.start_block.GetHex());
    locked_live.pushKV("target_height", private_chain.private_locked_live_scan.target_height);
    locked_live.pushKV("target_block", private_chain.private_locked_live_scan.target_block.GetHex());
    locked_live.pushKV("generation", private_chain.private_locked_live_scan.generation);
    seed_history_obj.pushKV("locked_live", locked_live);
    obj.pushKV("seed_history", seed_history_obj);
    if (int64_t birthtime = pwallet->GetBirthTime(); birthtime != UNKNOWN_TIME) {
        obj.pushKV("birthtime", birthtime);
    }

    AppendLastProcessedBlock(obj, *pwallet);
    return obj;
},
    };
}

static RPCHelpMan listwalletdir()
{
    return RPCHelpMan{"listwalletdir",
                "Returns a list of wallets in the wallet directory.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "wallets", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "name", "The wallet name"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwalletdir", "")
            + HelpExampleRpc("listwalletdir", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue wallets(UniValue::VARR);
    for (const auto& path : ListDatabases(GetWalletDir())) {
        UniValue wallet(UniValue::VOBJ);
        wallet.pushKV("name", path.utf8string());
        wallets.push_back(wallet);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("wallets", wallets);
    return result;
},
    };
}

static RPCHelpMan listwallets()
{
    return RPCHelpMan{"listwallets",
                "Returns a list of currently loaded wallets.\n"
                "For full information on the wallet, use \"getwalletinfo\"\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwallets", "")
            + HelpExampleRpc("listwallets", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue obj(UniValue::VARR);

    WalletContext& context = EnsureWalletContext(request.context);
    for (const std::shared_ptr<CWallet>& wallet : GetWallets(context)) {
        LOCK(wallet->cs_wallet);
        obj.push_back(wallet->GetName());
    }

    return obj;
},
    };
}

static RPCHelpMan loadwallet()
{
    return RPCHelpMan{"loadwallet",
                "\nLoads a wallet from a wallet file or directory."
                "\nNote that all wallet command-line options used when starting nitod will be"
                "\napplied to the new wallet.\n",
                {
                    {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet directory or .dat file."},
                    {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "name", "The wallet name if loaded successfully."},
                        {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to loading the wallet.",
                        {
                            {RPCResult::Type::STR, "", ""},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("loadwallet", "\"test.dat\"")
            + HelpExampleRpc("loadwallet", "\"test.dat\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    const std::string name(request.params[0].get_str());

    DatabaseOptions options;
    DatabaseStatus status;
    ReadDatabaseArgs(*context.args, options);
    options.require_existing = true;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    std::optional<bool> load_on_start = request.params[1].isNull() ? std::nullopt : std::optional<bool>(request.params[1].get_bool());

    {
        LOCK(context.wallets_mutex);
        if (std::any_of(context.wallets.begin(), context.wallets.end(), [&name](const auto& wallet) { return wallet->GetName() == name; })) {
            throw JSONRPCError(RPC_WALLET_ALREADY_LOADED, "Wallet \"" + name + "\" is already loaded.");
        }
    }

    std::shared_ptr<CWallet> const wallet = LoadWallet(context, name, load_on_start, options, status, error, warnings);

    HandleWalletError(wallet, status, error);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;
},
    };
}

static RPCHelpMan setwalletflag()
{
            std::string flags;
            for (auto& it : WALLET_FLAG_MAP)
                if (it.second & MUTABLE_WALLET_FLAGS)
                    flags += (flags == "" ? "" : ", ") + it.first;

    return RPCHelpMan{"setwalletflag",
                "\nChange the state of the given wallet flag for a wallet.\n",
                {
                    {"flag", RPCArg::Type::STR, RPCArg::Optional::NO, "The name of the flag to change. Current available flags: " + flags},
                    {"value", RPCArg::Type::BOOL, RPCArg::Default{true}, "The new state."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "flag_name", "The name of the flag that was modified"},
                        {RPCResult::Type::BOOL, "flag_state", "The new state of the flag"},
                        {RPCResult::Type::STR, "warnings", /*optional=*/true, "Any warnings associated with the change"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("setwalletflag", "avoid_reuse")
                  + HelpExampleRpc("setwalletflag", "\"avoid_reuse\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    std::string flag_str = request.params[0].get_str();
    bool value = request.params[1].isNull() || request.params[1].get_bool();

    if (!WALLET_FLAG_MAP.count(flag_str)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unknown wallet flag: %s", flag_str));
    }

    auto flag = WALLET_FLAG_MAP.at(flag_str);

    if (!(flag & MUTABLE_WALLET_FLAGS)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is immutable: %s", flag_str));
    }

    UniValue res(UniValue::VOBJ);

    if (pwallet->IsWalletFlagSet(flag) == value) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is already set to %s: %s", value ? "true" : "false", flag_str));
    }

    res.pushKV("flag_name", flag_str);
    res.pushKV("flag_state", value);

    if (value) {
        pwallet->SetWalletFlag(flag);
    } else {
        pwallet->UnsetWalletFlag(flag);
    }

    if (flag && value && WALLET_FLAG_CAVEATS.count(flag)) {
        res.pushKV("warnings", WALLET_FLAG_CAVEATS.at(flag));
    }

    return res;
},
    };
}

static RPCHelpMan createwallet()
{
    return RPCHelpMan{
        "createwallet",
        "\nCreates and loads a new wallet.\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name for the new wallet. If this is a path, the wallet will be created at the path location."},
            {"disable_private_keys", RPCArg::Type::BOOL, RPCArg::Default{false}, "Disable the possibility of private keys (only watchonlys are possible in this mode)."},
            {"blank", RPCArg::Type::BOOL, RPCArg::Default{false}, "Create a blank wallet. A blank wallet has no keys or HD seed. One can be set using sethdseed."},
            {"passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Encrypt the wallet with this passphrase."},
            {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{false}, "Keep track of coin reuse, and treat dirty and clean coins differently with privacy considerations in mind."},
            {"descriptors", RPCArg::Type::BOOL, RPCArg::Default{true}, "Create a native descriptor wallet. The wallet will use descriptors internally to handle address creation."
                                                                       " Setting to \"false\" will create a legacy wallet; This is only possible with the -deprecatedrpc=create_bdb setting because, the legacy wallet type is being deprecated and"
                                                                       " support for creating and opening legacy wallets will be removed in the future."},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
            {"external_signer", RPCArg::Type::BOOL, RPCArg::Default{false}, "Use an external signer such as a hardware wallet. Requires -signer to be configured. Wallet creation will fail if keys cannot be fetched. Requires disable_private_keys and descriptors set to true."},
            {"bip39_passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional BIP39 passphrase for the generated recovery phrase. This is distinct from the wallet encryption passphrase and is never stored. It is supported only by non-blank descriptor wallets with private keys enabled. At a terminal, use -named -interactive with nito-cli to require and confirm both secrets. Use -named -stdin only for protected automation."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if created successfully. If the wallet was created using a full path, the wallet_name will be the full path."},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to creating and loading the wallet.",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("createwallet", "\"testwallet\"")
            + HelpExampleRpc("createwallet", "\"testwallet\"")
            + HelpExampleCliNamed("createwallet", {{"wallet_name", "descriptors"}, {"avoid_reuse", true}, {"descriptors", true}, {"load_on_startup", true}})
            + HelpExampleRpcNamed("createwallet", {{"wallet_name", "descriptors"}, {"avoid_reuse", true}, {"descriptors", true}, {"load_on_startup", true}})
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    uint64_t flags = 0;
    if (!request.params[1].isNull() && request.params[1].get_bool()) {
        flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        flags |= WALLET_FLAG_BLANK_WALLET;
    }
    SecureString passphrase;
    passphrase.reserve(100);
    std::vector<bilingual_str> warnings;
    if (!request.params[3].isNull()) {
        passphrase = std::string_view{request.params[3].get_str()};
        if (passphrase.empty()) {
            // Empty string means unencrypted
            warnings.emplace_back(Untranslated("Empty string given as passphrase, wallet will not be encrypted."));
        }
    }

    if (!request.params[4].isNull() && request.params[4].get_bool()) {
        flags |= WALLET_FLAG_AVOID_REUSE;
    }

    SecureString bip39_passphrase{GetBIP39PassphraseFromRPCArgument(request.params[8])};
    const bool use_descriptors{self.Arg<bool>(5)};
    const bool use_external_signer{!request.params[7].isNull() && request.params[7].get_bool()};
    if (!bip39_passphrase.empty()) {
        if (!use_descriptors) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "A BIP39 passphrase is supported only for descriptor wallets");
        }
        if (flags & WALLET_FLAG_BLANK_WALLET) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "A BIP39 passphrase cannot be used when creating a blank wallet");
        }
        if (flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "A BIP39 passphrase cannot be used when private keys are disabled");
        }
        if (use_external_signer) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "A BIP39 passphrase cannot be used with an external signer");
        }
    }

    if (use_descriptors) {
#ifndef USE_SQLITE
        throw JSONRPCError(RPC_WALLET_ERROR, "Compiled without sqlite support (required for descriptor wallets)");
#endif
        flags |= WALLET_FLAG_DESCRIPTORS;
    } else {
        if (!context.chain->rpcEnableDeprecated("create_bdb")) {
            throw JSONRPCError(RPC_WALLET_ERROR, "BDB wallet creation is deprecated and will be removed in a future release."
                                                 " In this release it can be re-enabled temporarily with the -deprecatedrpc=create_bdb setting.");
        }
    }
    if (use_external_signer) {
#ifdef ENABLE_EXTERNAL_SIGNER
        flags |= WALLET_FLAG_EXTERNAL_SIGNER;
#else
        throw JSONRPCError(RPC_WALLET_ERROR, "Compiled without external signing support (required for external signing)");
#endif
    }

#ifndef USE_BDB
    if (!(flags & WALLET_FLAG_DESCRIPTORS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Compiled without bdb support (required for legacy wallets)");
    }
#endif

    DatabaseOptions options;
    DatabaseStatus status;
    ReadDatabaseArgs(*context.args, options);
    options.require_create = true;
    options.create_flags = flags;
    options.create_passphrase = passphrase;
    options.create_bip39_passphrase = bip39_passphrase;
    bilingual_str error;
    std::optional<bool> load_on_start = request.params[6].isNull() ? std::nullopt : std::optional<bool>(request.params[6].get_bool());
    const std::shared_ptr<CWallet> wallet = CreateWallet(context, request.params[0].get_str(), load_on_start, options, status, error, warnings);
    if (!wallet) {
        RPCErrorCode code = status == DatabaseStatus::FAILED_ENCRYPT ? RPC_WALLET_ENCRYPTION_FAILED : RPC_WALLET_ERROR;
        throw JSONRPCError(code, error.original);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;
},
    };
}

static RPCHelpMan unloadwallet()
{
    return RPCHelpMan{"unloadwallet",
                "Unloads the wallet referenced by the request endpoint, otherwise unloads the wallet specified in the argument.\n"
                "Specifying the wallet name on a wallet endpoint is invalid.",
                {
                    {"wallet_name", RPCArg::Type::STR, RPCArg::DefaultHint{"the wallet name from the RPC endpoint"}, "The name of the wallet to unload. If provided both here and in the RPC endpoint, the two must be identical."},
                    {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to unloading the wallet.",
                    {
                        {RPCResult::Type::STR, "", ""},
                    }},
                }},
                RPCExamples{
                    HelpExampleCli("unloadwallet", "wallet_name")
            + HelpExampleRpc("unloadwallet", "wallet_name")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string wallet_name;
    if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
        if (!(request.params[0].isNull() || request.params[0].get_str() == wallet_name)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "RPC endpoint wallet and wallet_name parameter specify different wallets");
        }
    } else {
        wallet_name = request.params[0].get_str();
    }

    WalletContext& context = EnsureWalletContext(request.context);
    std::shared_ptr<CWallet> wallet = GetWallet(context, wallet_name);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
    }

    std::vector<bilingual_str> warnings;
    {
        WalletRescanReserver reserver(*wallet);
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
        }

        // Release the "main" shared pointer and prevent further notifications.
        // Note that any attempt to load the same wallet would fail until the wallet
        // is destroyed (see CheckUniqueFileid).
        std::optional<bool> load_on_start{self.MaybeArg<bool>(1)};
        if (!RemoveWallet(context, wallet, load_on_start, warnings)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Requested wallet already unloaded");
        }
    }

    UnloadWallet(std::move(wallet));

    UniValue result(UniValue::VOBJ);
    PushWarnings(warnings, result);

    return result;
},
    };
}

static RPCHelpMan sethdseed()
{
    return RPCHelpMan{"sethdseed",
                "\nSet or generate a new HD wallet seed. Non-HD wallets will not be upgraded to being a HD wallet. Wallets that are already\n"
                "HD will have a new HD seed set so that new keys added to the keypool will be derived from this new seed.\n"
                "\nNote that you will need to MAKE A NEW BACKUP of your wallet after setting the HD wallet seed." + HELP_REQUIRING_PASSPHRASE +
                "Note: Existing descriptor wallets cannot rotate their seed with this command. For descriptor wallets, sethdseed can only initialize a blank descriptor wallet from a BIP39 mnemonic; WIF input remains available only to legacy wallets.\n"
                "When initializing a blank descriptor wallet from a BIP39 recovery phrase, Nito automatically restores complete chain-derived sent and received history together with current spendable funds. Existing chains require the transparent history index and, after private activation, the Orchard index. Keep wallet.dat backups for labels, metadata, and any non-seed/imported keys.\n",
                {
                    {"newkeypool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to flush old unused addresses, including change addresses, from the keypool and regenerate it.\n"
                                         "If true, the next address from getnewaddress and change address from getrawchangeaddress will be from this new seed.\n"
                                         "If false, addresses (including change addresses if the wallet already had HD Chain Split enabled) from the existing\n"
                                         "keypool will be used until it has been depleted."},
                    {"seed", RPCArg::Type::STR, RPCArg::DefaultHint{"random seed"}, "The BIP39 English 12- or 24-word mnemonic to use as the new HD seed, or a WIF private key for legacy wallets only.\n"
                                         "The WIF seed value can be retrieved using the dumpwallet command. It is the private key marked hdseed=1.\n"
                                         "The mnemonic seed value can be retrieved using the dumpmnemonic command."},
                    {"bip39_passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional BIP39 passphrase for the generated or supplied mnemonic used to initialize a blank descriptor wallet. This is distinct from the wallet encryption passphrase and is never stored. It is not supported with WIF or legacy wallets. Use -named -stdin with nito-cli so mnemonic and passphrase are not exposed in process arguments."},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("sethdseed", "")
            + HelpExampleCli("sethdseed", "false")
            + HelpExampleRpc("sethdseed", "true, \"wifkey\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set a HD seed to a wallet with private keys disabled");
    }

    EnsureWalletIsUnlocked(*pwallet);

    bool flush_key_pool = true;
    if (!request.params[0].isNull()) {
        flush_key_pool = request.params[0].get_bool();
    }

    SecureString bip39_passphrase{GetBIP39PassphraseFromRPCArgument(request.params[2])};
    const HDSeedInput seed_input = GetSeedKeyFromRPCArgument(request.params[1]);
    const CKey& key = seed_input.key;

    const bool descriptor_wallet{pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)};
    if (!bip39_passphrase.empty()) {
        if (!descriptor_wallet) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "A BIP39 passphrase is not supported by legacy wallets");
        }
        if (!seed_input.bip39_mnemonic && !seed_input.generated_random) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "A BIP39 passphrase cannot be used with a WIF seed");
        }
    }

    if (descriptor_wallet) {
        if (pwallet->HaveChain()) {
            const std::optional<int> chain_height{pwallet->chain().getHeight()};
            if (chain_height && *chain_height > 0) {
                const uint256 chain_tip{pwallet->chain().getBlockHash(*chain_height)};
                if (!pwallet->chain().hasBlocks(chain_tip, 0, *chain_height)) {
                    throw JSONRPCError(RPC_MISC_ERROR, PrunedWalletRecoveryError().original);
                }
                if (!pwallet->chain().hasTransparentHistoryIndex()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "A recovery phrase requires -transparenthistoryindex=1 when restoring an existing chain");
                }
                const int private_activation_height{Params().GetConsensus().privateTxActivationHeight};
                if (private_activation_height >= 0 && *chain_height >= private_activation_height &&
                    !pwallet->chain().hasOrchardIndex()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "A recovery phrase requires -orchardindex=1 after private activation");
                }
            }
        }
        {
            LOCK(pwallet->cs_wallet);
            if (!pwallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET) || !pwallet->GetActiveScriptPubKeyMans().empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Descriptor wallet HD seed can only be set on a blank descriptor wallet");
            }
            if (!seed_input.bip39_mnemonic && !seed_input.generated_random) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Descriptor wallet HD seed initialization requires a BIP39 mnemonic; WIF input is not supported");
            }

            pwallet->SetupDescriptorScriptPubKeyMans(key, bip39_passphrase);
        }

        pwallet->BlockUntilSyncedToCurrentChain();
        int recovery_target_height{0};
        uint256 recovery_target_block{Params().GenesisBlock().GetHash()};
        {
            LOCK(pwallet->cs_wallet);
            if (pwallet->GetLastBlockHeight() >= 0 && !pwallet->GetLastBlockHash().IsNull()) {
                recovery_target_height = pwallet->GetLastBlockHeight();
                recovery_target_block = pwallet->GetLastBlockHash();
            }
        }
        SeedHistoryState recovery_state{SeedHistoryState::AvailableBalance(
            recovery_target_height,
            recovery_target_block,
            /*orchard_applicable=*/true)};
        recovery_state.MarkHistory(/*orchard=*/false, SeedRecoveryStatus::PENDING, recovery_target_height, recovery_target_block);
        recovery_state.MarkHistory(/*orchard=*/true, SeedRecoveryStatus::PENDING, recovery_target_height, recovery_target_block);
        if (!pwallet->SetSeedHistoryState(recovery_state)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Could not save pending complete recovery state after setting HD seed");
        }
        if (!pwallet->TopUpSeedRestoreKeyPool()) {
            recovery_state.MarkFunds(/*orchard=*/false, SeedRecoveryStatus::FAILED, recovery_target_height, recovery_target_block);
            recovery_state.MarkFunds(/*orchard=*/true, SeedRecoveryStatus::FAILED, recovery_target_height, recovery_target_block);
            recovery_state.MarkHistory(/*orchard=*/false, SeedRecoveryStatus::FAILED, recovery_target_height, recovery_target_block);
            recovery_state.MarkHistory(/*orchard=*/true, SeedRecoveryStatus::FAILED, recovery_target_height, recovery_target_block);
            if (!pwallet->SetSeedHistoryState(recovery_state)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not save failed recovery state after address discovery preparation failed");
            }
            throw JSONRPCError(RPC_WALLET_ERROR, "Could not prepare wallet address discovery after setting HD seed");
        }
        if (auto restored = pwallet->RestoreSeedHistory(
                /*wait_for_indexes=*/true,
                /*show_progress=*/true);
            !restored) {
            throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(restored).original);
        }
        return UniValue::VNULL;
    }

    LegacyScriptPubKeyMan& spk_man = EnsureLegacyScriptPubKeyMan(*pwallet, true);
    LOCK2(pwallet->cs_wallet, spk_man.cs_KeyStore);

    if (pwallet->HasCanonicalPrivateHDSeed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot rotate the transparent HD seed after a canonical Orchard recovery root exists; this protects existing Orchard notes");
    }

    // Do not do anything to non-HD wallets
    if (!pwallet->CanSupportFeature(FEATURE_HD)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set an HD seed on a non-HD wallet. Use the upgradewallet RPC in order to upgrade a non-HD wallet to HD");
    }

    if (HaveKey(spk_man, key)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Already have this key (either as an HD seed or as a loose private key)");
    }

    CPubKey master_pub_key = spk_man.DeriveNewSeed(key);
    spk_man.SetHDSeed(master_pub_key);
    if (flush_key_pool) spk_man.NewKeyPool();

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan upgradeorchardwallet()
{
    return RPCHelpMan{"upgradeorchardwallet",
        "\nAdd one canonical BIP39 Orchard recovery root to an existing V3 wallet without changing its transparent keys, descriptors, address sequence, labels, or default receive type.\n"
        "A wallet.dat backup is created beside the wallet before any mutation. The returned phrase covers Orchard only; the backup remains required for pre-existing V3 transparent and imported keys." + HELP_REQUIRING_PASSPHRASE,
        {
            {"mnemonic", RPCArg::Type::STR, RPCArg::DefaultHint{"new random 24-word phrase"}, "Optional BIP39 English 12- or 24-word Orchard recovery phrase."},
            {"bip39_passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional BIP39 passphrase for this Orchard recovery phrase. This is distinct from the wallet encryption passphrase and is never stored. Use -named -stdin with nito-cli so mnemonic and passphrase are not exposed in process arguments."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "mnemonic", "BIP39 Orchard recovery phrase"},
                {RPCResult::Type::STR, "scope", "Recovery scope; always orchard_only for an upgraded V3 wallet"},
                {RPCResult::Type::BOOL, "bip39_passphrase_required", "true when this phrase must be restored with its BIP39 passphrase"},
                {RPCResult::Type::STR, "backup", "Pre-upgrade wallet.dat backup path"},
                {RPCResult::Type::STR, "warning", "Reminder that the V3 backup remains required"},
            }},
        RPCExamples{
            HelpExampleCli("upgradeorchardwallet", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    EnsureWalletIsUnlocked(*pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();

    SecureString bip39_passphrase{GetBIP39PassphraseFromRPCArgument(request.params[1])};

    CKey orchard_seed;
    if (request.params[0].isNull()) {
        orchard_seed = GenerateRandomKey();
    } else {
        auto decoded = DecodeBIP39Mnemonic(request.params[0].get_str());
        if (!decoded) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, util::ErrorString(decoded).original);
        }
        orchard_seed = std::move(*decoded);
    }
    auto mnemonic = EncodeBIP39Mnemonic(orchard_seed);
    if (!mnemonic) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(mnemonic).original);
    }

    fs::path backup_path;
    {
        LOCK(pwallet->cs_wallet);
        if (pwallet->HasCanonicalPrivateHDSeed()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "This wallet already has a canonical Orchard recovery root");
        }
        if (pwallet->GetActiveScriptPubKeyMans().empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot add Orchard to a wallet without an active transparent key manager; initialize the blank wallet first");
        }

        const fs::path wallet_file{fs::absolute(fs::PathFromString(pwallet->GetDatabase().Filename()))};
        const fs::path wallet_dir{wallet_file.parent_path()};
        const int64_t timestamp{GetTime()};
        backup_path = wallet_dir / fs::PathFromString(strprintf("wallet-pre-orchard-%d.bak", timestamp));
        for (unsigned int suffix = 1; fs::exists(backup_path) && suffix < 1000; ++suffix) {
            backup_path = wallet_dir / fs::PathFromString(strprintf("wallet-pre-orchard-%d-%u.bak", timestamp, suffix));
        }
        if (fs::exists(backup_path) || !pwallet->BackupWallet(fs::PathToString(backup_path))) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Unable to create the required pre-upgrade wallet.dat backup");
        }

        bilingual_str seed_error;
        if (!pwallet->InitializePrivateHDSeed(orchard_seed, bip39_passphrase, PrivateSeedScope::ORCHARD_ONLY, seed_error)) {
            throw JSONRPCError(RPC_WALLET_ERROR, seed_error.original);
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("mnemonic", *mnemonic);
    result.pushKV("scope", "orchard_only");
    result.pushKV("bip39_passphrase_required", !bip39_passphrase.empty());
    result.pushKV("backup", fs::PathToString(backup_path));
    result.pushKV("warning", bip39_passphrase.empty()
        ? "Keep this wallet.dat backup permanently: the Orchard phrase does not restore pre-existing V3 transparent or imported keys."
        : "Keep both the Orchard phrase and its separate BIP39 passphrase: the phrase alone restores a different wallet. Also keep this wallet.dat backup permanently because they do not restore pre-existing V3 transparent or imported keys.");
    return result;
},
    };
}

static RPCHelpMan dumpmnemonic()
{
    return RPCHelpMan{"dumpmnemonic",
        "\nReturns the canonical Orchard root encoded as a BIP39 English recovery phrase." + HELP_REQUIRING_PASSPHRASE +
        "The response states whether the phrase covers the full deterministic V4 wallet or Orchard only, and whether its separate BIP39 passphrase is required. The BIP39 passphrase itself is never returned. Keep wallet.dat backups for every V3 or imported transparent key.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "mnemonic", "BIP39 English mnemonic for the active Nito HD seed"},
                {RPCResult::Type::NUM, "words", "Number of words in the mnemonic"},
                {RPCResult::Type::STR, "format", "Mnemonic format"},
                {RPCResult::Type::STR, "seed_type", "How Nito interprets the mnemonic entropy"},
                {RPCResult::Type::STR, "scope", "full_wallet or orchard_only"},
                {RPCResult::Type::BOOL, "bip39_passphrase_required", "true when this phrase must be restored with its BIP39 passphrase"},
                {RPCResult::Type::STR, "warning", "Security warning"},
            }
        },
        RPCExamples{
            HelpExampleCli("dumpmnemonic", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    EnsureWalletIsUnlocked(*pwallet);

    LOCK(pwallet->cs_wallet);

    CKey hd_seed;
    bilingual_str seed_error;
    if (!pwallet->GetPrivateHDSeed(hd_seed, seed_error, /*require_exportable_seed=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, seed_error.original);
    }

    auto mnemonic = EncodeBIP39Mnemonic(hd_seed);
    if (!mnemonic) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(mnemonic).original);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("mnemonic", *mnemonic);
    result.pushKV("words", static_cast<int>(std::count(mnemonic->begin(), mnemonic->end(), ' ') + 1));
    result.pushKV("format", "bip39-english");
    const PrivateSeedScope scope{pwallet->GetPrivateSeedScope()};
    const bool orchard_only{scope == PrivateSeedScope::ORCHARD_ONLY};
    const bool passphrase_required{pwallet->IsBIP39PassphraseEnabled()};
    result.pushKV("seed_type", orchard_only ? "orchard_root_entropy" : (pwallet->IsLegacy() ? "legacy_hd_entropy" : "bip39_pbkdf2_master_seed"));
    result.pushKV("scope", orchard_only ? "orchard_only" : "full_wallet");
    result.pushKV("bip39_passphrase_required", passphrase_required);
    if (orchard_only) {
        result.pushKV("warning", passphrase_required
            ? "This phrase requires its separate BIP39 passphrase and restores Orchard only. The phrase alone restores a different wallet. Keep wallet.dat permanently for pre-existing V3 transparent and imported keys."
            : "This phrase restores Orchard only. Keep wallet.dat permanently for pre-existing V3 transparent and imported keys.");
    } else {
        result.pushKV("warning", passphrase_required
            ? "This phrase requires its separate BIP39 passphrase. The phrase alone restores a different wallet. Store both offline and separately, and never share them."
            : "Anyone with this mnemonic can spend funds derived from this wallet seed. Store it offline and never share it.");
    }
    return result;
},
    };
}

static RPCHelpMan upgradewallet()
{
    return RPCHelpMan{"upgradewallet",
        "\nUpgrade the wallet. Upgrades to the latest version if no version number is specified.\n"
        "New keys may be generated and a new wallet backup will need to be made.",
        {
            {"version", RPCArg::Type::NUM, RPCArg::Default{int{FEATURE_LATEST}}, "The version number to upgrade to. Default is the latest wallet version."}
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "wallet_name", "Name of wallet this operation was performed on"},
                {RPCResult::Type::NUM, "previous_version", "Version of wallet before this operation"},
                {RPCResult::Type::NUM, "current_version", "Version of wallet after this operation"},
                {RPCResult::Type::STR, "result", /*optional=*/true, "Description of result, if no error"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error message (if there is one)"}
            },
        },
        RPCExamples{
            HelpExampleCli("upgradewallet", "169900")
            + HelpExampleRpc("upgradewallet", "169900")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    EnsureWalletIsUnlocked(*pwallet);

    int version = 0;
    if (!request.params[0].isNull()) {
        version = request.params[0].getInt<int>();
    }
    bilingual_str error;
    const int previous_version{pwallet->GetVersion()};
    const bool wallet_upgraded{pwallet->UpgradeWallet(version, error)};
    const int current_version{pwallet->GetVersion()};
    std::string result;

    if (wallet_upgraded) {
        if (previous_version == current_version) {
            result = "Already at latest version. Wallet version unchanged.";
        } else {
            result = strprintf("Wallet upgraded successfully from version %i to version %i.", previous_version, current_version);
        }
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("wallet_name", pwallet->GetName());
    obj.pushKV("previous_version", previous_version);
    obj.pushKV("current_version", current_version);
    if (!result.empty()) {
        obj.pushKV("result", result);
    } else {
        CHECK_NONFATAL(!error.empty());
        obj.pushKV("error", error.original);
    }
    return obj;
},
    };
}

RPCHelpMan simulaterawtransaction()
{
    return RPCHelpMan{"simulaterawtransaction",
        "\nCalculate the balance change resulting in the signing and broadcasting of the given transaction(s).\n",
        {
            {"rawtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "An array of hex strings of raw transactions.\n",
                {
                    {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                },
            },
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Whether to include watch-only addresses (see RPC importaddress)"},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "balance_change", "The wallet balance change (negative means decrease)."},
            }
        },
        RPCExamples{
            HelpExampleCli("simulaterawtransaction", "[\"myhex\"]")
            + HelpExampleRpc("simulaterawtransaction", "[\"myhex\"]")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> rpc_wallet = GetWalletForJSONRPCRequest(request);
    if (!rpc_wallet) return UniValue::VNULL;
    const CWallet& wallet = *rpc_wallet;

    LOCK(wallet.cs_wallet);

    UniValue include_watchonly(UniValue::VNULL);
    if (request.params[1].isObject()) {
        UniValue options = request.params[1];
        RPCTypeCheckObj(options,
            {
                {"include_watchonly", UniValueType(UniValue::VBOOL)},
            },
            true, true);

        include_watchonly = options["include_watchonly"];
    }

    isminefilter filter = ISMINE_SPENDABLE;
    if (ParseIncludeWatchonly(include_watchonly, wallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    const auto& txs = request.params[0].get_array();
    CAmount changes{0};
    std::map<COutPoint, CAmount> new_utxos; // UTXO:s that were made available in transaction array
    std::set<COutPoint> spent;

    for (size_t i = 0; i < txs.size(); ++i) {
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, txs[i].get_str(), /* try_no_witness */ true, /* try_witness */ true)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction hex string decoding failure.");
        }

        // Fetch previous transactions (inputs)
        std::map<COutPoint, Coin> coins;
        for (const CTxIn& txin : mtx.vin) {
            coins[txin.prevout]; // Create empty map entry keyed by prevout.
        }
        wallet.chain().findCoins(coins);

        // Fetch debit; we are *spending* these; if the transaction is signed and
        // broadcast, we will lose everything in these
        for (const auto& txin : mtx.vin) {
            const auto& outpoint = txin.prevout;
            if (spent.count(outpoint)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction(s) are spending the same output more than once");
            }
            if (new_utxos.count(outpoint)) {
                changes -= new_utxos.at(outpoint);
                new_utxos.erase(outpoint);
            } else {
                if (coins.at(outpoint).IsSpent()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "One or more transaction inputs are missing or have been spent already");
                }
                changes -= wallet.GetDebit(txin, filter);
            }
            spent.insert(outpoint);
        }

        // Iterate over outputs; we are *receiving* these, if the wallet considers
        // them "mine"; if the transaction is signed and broadcast, we will receive
        // everything in these
        // Also populate new_utxos in case these are spent in later transactions

        const auto& hash = mtx.GetHash();
        for (size_t i = 0; i < mtx.vout.size(); ++i) {
            const auto& txout = mtx.vout[i];
            bool is_mine = 0 < (wallet.IsMine(txout) & filter);
            changes += new_utxos[COutPoint(hash, i)] = is_mine ? txout.nValue : 0;
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("balance_change", ValueFromAmount(changes));

    return result;
}
    };
}

static RPCHelpMan migratewallet()
{
    return RPCHelpMan{"migratewallet",
        "\nMigrate the wallet to a descriptor wallet.\n"
        "A new wallet backup will need to be made.\n"
        "\nThe migration process will create a backup of the wallet before migrating. This backup\n"
        "file will be named <wallet name>-<timestamp>.legacy.bak and can be found in the directory\n"
        "for this wallet. In the event of an incorrect migration, the backup can be restored using restorewallet."
        "\nEncrypted wallets must have the passphrase provided as an argument to this call.\n"
        "\nThis RPC may take a long time to complete. Increasing the RPC client timeout is recommended.",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::DefaultHint{"the wallet name from the RPC endpoint"}, "The name of the wallet to migrate. If provided both here and in the RPC endpoint, the two must be identical."},
            {"passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The wallet passphrase"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "wallet_name", "The name of the primary migrated wallet"},
                {RPCResult::Type::STR, "watchonly_name", /*optional=*/true, "The name of the migrated wallet containing the watchonly scripts"},
                {RPCResult::Type::STR, "solvables_name", /*optional=*/true, "The name of the migrated wallet containing solvable but not watched scripts"},
                {RPCResult::Type::STR, "backup_path", "The location of the backup of the original wallet"},
            }
        },
        RPCExamples{
            HelpExampleCli("migratewallet", "")
            + HelpExampleRpc("migratewallet", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string wallet_name;
            if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
                if (!(request.params[0].isNull() || request.params[0].get_str() == wallet_name)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "RPC endpoint wallet and wallet_name parameter specify different wallets");
                }
            } else {
                if (request.params[0].isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Either RPC endpoint wallet or wallet_name parameter must be provided");
                }
                wallet_name = request.params[0].get_str();
            }

            SecureString wallet_pass;
            wallet_pass.reserve(100);
            if (!request.params[1].isNull()) {
                wallet_pass = std::string_view{request.params[1].get_str()};
            }

            WalletContext& context = EnsureWalletContext(request.context);
            util::Result<MigrationResult> res = MigrateLegacyToDescriptor(wallet_name, wallet_pass, context);
            if (!res) {
                throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
            }

            UniValue r{UniValue::VOBJ};
            r.pushKV("wallet_name", res->wallet_name);
            if (res->watchonly_wallet) {
                r.pushKV("watchonly_name", res->watchonly_wallet->GetName());
            }
            if (res->solvables_wallet) {
                r.pushKV("solvables_name", res->solvables_wallet->GetName());
            }
            r.pushKV("backup_path", res->backup_path.utf8string());

            return r;
        },
    };
}

// addresses
RPCHelpMan getaddressinfo();
RPCHelpMan getnewaddress();
RPCHelpMan getprivatekeymaninfo();
RPCHelpMan getprivateviewkey();
RPCHelpMan getrawchangeaddress();
RPCHelpMan setlabel();
RPCHelpMan listaddressgroupings();
RPCHelpMan addmultisigaddress();
RPCHelpMan keypoolrefill();
RPCHelpMan newkeypool();
RPCHelpMan getaddressesbylabel();
RPCHelpMan listlabels();
#ifdef ENABLE_EXTERNAL_SIGNER
RPCHelpMan walletdisplayaddress();
#endif // ENABLE_EXTERNAL_SIGNER

// backup
RPCHelpMan dumpprivkey();
RPCHelpMan importprivkey();
RPCHelpMan importaddress();
RPCHelpMan importpubkey();
RPCHelpMan dumpwallet();
RPCHelpMan importwallet();
RPCHelpMan importprunedfunds();
RPCHelpMan removeprunedfunds();
RPCHelpMan importmulti();
RPCHelpMan importdescriptors();
RPCHelpMan listdescriptors();
RPCHelpMan backupwallet();
RPCHelpMan restorewallet();

// coins
RPCHelpMan getreceivedbyaddress();
RPCHelpMan getreceivedbylabel();
RPCHelpMan getbalance();
RPCHelpMan getunconfirmedbalance();
RPCHelpMan getprivatebalance();
RPCHelpMan getprivatenoteproof();
RPCHelpMan lockunspent();
RPCHelpMan listlockunspent();
RPCHelpMan getbalances();
RPCHelpMan listunspent();
RPCHelpMan listprivateunspent();
RPCHelpMan checkprivatenoteproof();

// encryption
RPCHelpMan walletpassphrase();
RPCHelpMan walletpassphrasechange();
RPCHelpMan walletlock();
RPCHelpMan encryptwallet();

// spend
RPCHelpMan sendtoaddress();
RPCHelpMan shieldtoaddress();
RPCHelpMan sendprivate();
RPCHelpMan sendmany();
RPCHelpMan settxfee();
RPCHelpMan fundrawtransaction();
RPCHelpMan bumpfee();
RPCHelpMan psbtbumpfee();
RPCHelpMan send();
RPCHelpMan sendall();
RPCHelpMan walletprocesspsbt();
RPCHelpMan walletcreatefundedpsbt();
RPCHelpMan signrawtransactionwithwallet();

// signmessage
RPCHelpMan signmessage();

// transactions
RPCHelpMan listreceivedbyaddress();
RPCHelpMan listreceivedbylabel();
RPCHelpMan listtransactions();
RPCHelpMan listsinceblock();
RPCHelpMan gettransaction();
RPCHelpMan abandontransaction();
RPCHelpMan rescanblockchain();
RPCHelpMan abortrescan();

Span<const CRPCCommand> GetWalletRPCCommands()
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &fundrawtransaction},
        {"wallet", &abandontransaction},
        {"wallet", &abortrescan},
        {"wallet", &addmultisigaddress},
        {"wallet", &backupwallet},
        {"wallet", &bumpfee},
        {"wallet", &psbtbumpfee},
        {"wallet", &createwallet},
        {"wallet", &restorewallet},
        {"wallet", &dumpprivkey},
        {"wallet", &dumpwallet},
        {"wallet", &dumpmnemonic},
        {"wallet", &encryptwallet},
        {"wallet", &getaddressesbylabel},
        {"wallet", &getaddressinfo},
        {"wallet", &getbalance},
        {"wallet", &getnewaddress},
        {"wallet", &getprivatebalance},
        {"wallet", &getprivatenoteproof},
        {"wallet", &getprivatekeymaninfo},
        {"wallet", &getprivateviewkey},
        {"wallet", &getrawchangeaddress},
        {"wallet", &getreceivedbyaddress},
        {"wallet", &getreceivedbylabel},
        {"wallet", &gettransaction},
        {"wallet", &getunconfirmedbalance},
        {"wallet", &getbalances},
        {"wallet", &getwalletinfo},
        {"wallet", &importaddress},
        {"wallet", &importdescriptors},
        {"wallet", &importmulti},
        {"wallet", &importprivkey},
        {"wallet", &importprunedfunds},
        {"wallet", &importpubkey},
        {"wallet", &importwallet},
        {"wallet", &keypoolrefill},
        {"wallet", &listaddressgroupings},
        {"wallet", &listdescriptors},
        {"wallet", &listlabels},
        {"wallet", &listlockunspent},
        {"wallet", &listprivateunspent},
        {"wallet", &checkprivatenoteproof},
        {"wallet", &listreceivedbyaddress},
        {"wallet", &listreceivedbylabel},
        {"wallet", &listsinceblock},
        {"wallet", &listtransactions},
        {"wallet", &listunspent},
        {"wallet", &listwalletdir},
        {"wallet", &listwallets},
        {"wallet", &loadwallet},
        {"wallet", &lockunspent},
        {"wallet", &migratewallet},
        {"wallet", &newkeypool},
        {"wallet", &removeprunedfunds},
        {"wallet", &rescanblockchain},
        {"wallet", &send},
        {"wallet", &sendmany},
        {"wallet", &sendprivate},
        {"wallet", &sendtoaddress},
        {"wallet", &shieldtoaddress},
        {"wallet", &sethdseed},
        {"wallet", &setlabel},
        {"wallet", &settxfee},
        {"wallet", &setwalletflag},
        {"wallet", &signmessage},
        {"wallet", &signrawtransactionwithwallet},
        {"wallet", &simulaterawtransaction},
        {"wallet", &sendall},
        {"wallet", &unloadwallet},
        {"wallet", &upgradewallet},
        {"wallet", &upgradeorchardwallet},
        {"wallet", &walletcreatefundedpsbt},
#ifdef ENABLE_EXTERNAL_SIGNER
        {"wallet", &walletdisplayaddress},
#endif // ENABLE_EXTERNAL_SIGNER
        {"wallet", &walletlock},
        {"wallet", &walletpassphrase},
        {"wallet", &walletpassphrasechange},
        {"wallet", &walletprocesspsbt},
    };
    return commands;
}
} // namespace wallet
