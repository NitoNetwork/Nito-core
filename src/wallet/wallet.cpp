// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#if defined(HAVE_CONFIG_H)
#include <config/nito-config.h>
#endif
#include <addresstype.h>
#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <common/settings.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <external_signer.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <interfaces/wallet.h>
#include <kernel/chain.h>
#include <kernel/mempool_removal_reason.h>
#include <key.h>
#include <key_io.h>
#include <logging.h>
#include <outputtype.h>
#include <policy/feerate.h>
#include <private/orchard_verifier.h>
#include <primitives/block.h>
#include <primitives/private_transaction.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <random.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <support/allocators/zeroafterfree.h>
#include <support/cleanse.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/error.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/message.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/bip39.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/crypter.h>
#include <wallet/db.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/feebumper.h>
#include <wallet/private_wallet.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/transaction.h>
#include <wallet/types.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <exception>
#include <ios>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <variant>

struct KeyOriginInfo;

using interfaces::FoundBlock;

namespace wallet {

namespace {
constexpr const char* AVAILABLE_BALANCE_INTERNAL_TX_KEY{"nito_available_balance_internal"};
constexpr const char* AVAILABLE_BALANCE_CURRENT_TX_KEY{"nito_available_balance_current"};

bool SetAvailableBalanceFlag(CWalletTx& wtx, const char* key, bool enabled)
{
    if (enabled) {
        const auto [_, inserted] = wtx.mapValue.emplace(key, "1");
        return inserted;
    }
    return wtx.mapValue.erase(key) != 0;
}

bool SetAvailableBalanceMarkers(CWalletTx& wtx, bool internal, bool current)
{
    bool changed{false};
    changed |= SetAvailableBalanceFlag(wtx, AVAILABLE_BALANCE_INTERNAL_TX_KEY, internal);
    changed |= SetAvailableBalanceFlag(wtx, AVAILABLE_BALANCE_CURRENT_TX_KEY, current);
    return changed;
}

bool IsAvailableBalanceInternal(const CWalletTx& wtx)
{
    return wtx.mapValue.count(AVAILABLE_BALANCE_INTERNAL_TX_KEY) != 0;
}

bool EncryptPrivateNotePayload(const CKeyingMaterial& master_key, const CPrivateWalletNote& note, std::vector<unsigned char>& ciphertext)
{
    DataStream stream;
    stream << note;
    const uint256 checksum{Hash(Span<const std::byte>{stream.data(), stream.size()})};
    stream << checksum;
    CKeyingMaterial plaintext(stream.size());
    if (!plaintext.empty()) {
        std::memcpy(plaintext.data(), UCharCast(stream.data()), stream.size());
    }
    const bool encrypted{EncryptSecret(master_key, plaintext, note.cmx, ciphertext)};
    if (!plaintext.empty()) memory_cleanse(plaintext.data(), plaintext.size());
    if (!stream.empty()) memory_cleanse(stream.data(), stream.size());
    return encrypted;
}

bool DecryptPrivateNotePayload(const CKeyingMaterial& master_key, const uint256& cmx, const std::vector<unsigned char>& ciphertext, CPrivateWalletNote& note)
{
    CKeyingMaterial plaintext;
    if (!DecryptSecret(master_key, ciphertext, cmx, plaintext)) return false;
    try {
        DataStream stream{Span<const uint8_t>{plaintext.data(), plaintext.size()}};
        uint256 checksum;
        stream >> note >> checksum;
        DataStream verification_stream;
        verification_stream << note;
        const uint256 expected_checksum{Hash(Span<const std::byte>{verification_stream.data(), verification_stream.size()})};
        const bool valid{stream.empty() && note.GetId() == cmx && checksum == expected_checksum};
        if (!verification_stream.empty()) memory_cleanse(verification_stream.data(), verification_stream.size());
        if (!plaintext.empty()) memory_cleanse(plaintext.data(), plaintext.size());
        return valid;
    } catch (...) {
        if (!plaintext.empty()) memory_cleanse(plaintext.data(), plaintext.size());
        return false;
    }
}
} // namespace

CWallet::~CWallet()
{
    {
        LOCK(cs_wallet);
        ClearBIP39DerivedSeedCache();
        if (!vMasterKey.empty()) {
            memory_cleanse(vMasterKey.data(), vMasterKey.size() * sizeof(CKeyingMaterial::value_type));
            vMasterKey.clear();
        }
        if (m_bip39_derived_seed_record && !m_bip39_derived_seed_record->payload.empty()) {
            memory_cleanse(m_bip39_derived_seed_record->payload.data(), m_bip39_derived_seed_record->payload.size());
            m_bip39_derived_seed_record->payload.clear();
        }
    }
    // Should not have slots connected at this point.
    assert(NotifyUnload.empty());
}

bool AddWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    common::SettingsValue setting_value = chain.getRwSetting("wallet");
    if (!setting_value.isArray()) setting_value.setArray();
    for (const common::SettingsValue& value : setting_value.getValues()) {
        if (value.isStr() && value.get_str() == wallet_name) return true;
    }
    setting_value.push_back(wallet_name);
    return chain.updateRwSetting("wallet", setting_value);
}

bool RemoveWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    common::SettingsValue setting_value = chain.getRwSetting("wallet");
    if (!setting_value.isArray()) return true;
    common::SettingsValue new_value(common::SettingsValue::VARR);
    for (const common::SettingsValue& value : setting_value.getValues()) {
        if (!value.isStr() || value.get_str() != wallet_name) new_value.push_back(value);
    }
    if (new_value.size() == setting_value.size()) return true;
    return chain.updateRwSetting("wallet", new_value);
}

static void UpdateWalletSetting(interfaces::Chain& chain,
                                const std::string& wallet_name,
                                std::optional<bool> load_on_startup,
                                std::vector<bilingual_str>& warnings)
{
    if (!load_on_startup) return;
    if (load_on_startup.value() && !AddWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may not be loaded next node startup."));
    } else if (!load_on_startup.value() && !RemoveWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may still be loaded next node startup."));
    }
}

/**
 * Refresh mempool status so the wallet is in an internally consistent state and
 * immediately knows the transaction's status: Whether it can be considered
 * trusted and is eligible to be abandoned ...
 */
static void RefreshMempoolStatus(CWalletTx& tx, interfaces::Chain& chain)
{
    if (chain.isInMempool(tx.GetHash())) {
        tx.m_state = TxStateInMempool();
    } else if (tx.state<TxStateInMempool>()) {
        tx.m_state = TxStateInactive();
    }
}

bool AddWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    assert(wallet);
    std::vector<std::shared_ptr<CWallet>>::const_iterator i = std::find(context.wallets.begin(), context.wallets.end(), wallet);
    if (i != context.wallets.end()) return false;
    context.wallets.push_back(wallet);
    wallet->ConnectScriptPubKeyManNotifiers();
    wallet->NotifyCanGetAddressesChanged();
    return true;
}

bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet, std::optional<bool> load_on_start, std::vector<bilingual_str>& warnings)
{
    assert(wallet);

    interfaces::Chain& chain = wallet->chain();
    std::string name = wallet->GetName();

    // Unregister with the validation interface which also drops shared pointers.
    wallet->m_chain_notifications_handler.reset();
    LOCK(context.wallets_mutex);
    std::vector<std::shared_ptr<CWallet>>::iterator i = std::find(context.wallets.begin(), context.wallets.end(), wallet);
    if (i == context.wallets.end()) return false;
    context.wallets.erase(i);

    // Write the wallet setting
    UpdateWalletSetting(chain, name, load_on_start, warnings);

    return true;
}

bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet, std::optional<bool> load_on_start)
{
    std::vector<bilingual_str> warnings;
    return RemoveWallet(context, wallet, load_on_start, warnings);
}

std::vector<std::shared_ptr<CWallet>> GetWallets(WalletContext& context)
{
    LOCK(context.wallets_mutex);
    return context.wallets;
}

std::shared_ptr<CWallet> GetDefaultWallet(WalletContext& context, size_t& count)
{
    LOCK(context.wallets_mutex);
    count = context.wallets.size();
    return count == 1 ? context.wallets[0] : nullptr;
}

std::shared_ptr<CWallet> GetWallet(WalletContext& context, const std::string& name)
{
    LOCK(context.wallets_mutex);
    for (const std::shared_ptr<CWallet>& wallet : context.wallets) {
        if (wallet->GetName() == name) return wallet;
    }
    return nullptr;
}

std::unique_ptr<interfaces::Handler> HandleLoadWallet(WalletContext& context, LoadWalletFn load_wallet)
{
    LOCK(context.wallets_mutex);
    auto it = context.wallet_load_fns.emplace(context.wallet_load_fns.end(), std::move(load_wallet));
    return interfaces::MakeCleanupHandler([&context, it] { LOCK(context.wallets_mutex); context.wallet_load_fns.erase(it); });
}

void NotifyWalletLoaded(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    for (auto& load_wallet : context.wallet_load_fns) {
        load_wallet(interfaces::MakeWallet(context, wallet));
    }
}

static GlobalMutex g_loading_wallet_mutex;
static GlobalMutex g_wallet_release_mutex;
static std::condition_variable g_wallet_release_cv;
static std::set<std::string> g_loading_wallet_set GUARDED_BY(g_loading_wallet_mutex);
static std::set<std::string> g_unloading_wallet_set GUARDED_BY(g_wallet_release_mutex);

// Custom deleter for shared_ptr<CWallet>.
static void ReleaseWallet(CWallet* wallet)
{
    const std::string name = wallet->GetName();
    wallet->WalletLogPrintf("Releasing wallet\n");
    wallet->Flush();
    delete wallet;
    // Wallet is now released, notify UnloadWallet, if any.
    {
        LOCK(g_wallet_release_mutex);
        if (g_unloading_wallet_set.erase(name) == 0) {
            // UnloadWallet was not called for this wallet, all done.
            return;
        }
    }
    g_wallet_release_cv.notify_all();
}

void UnloadWallet(std::shared_ptr<CWallet>&& wallet)
{
    // Mark wallet for unloading.
    const std::string name = wallet->GetName();
    {
        LOCK(g_wallet_release_mutex);
        auto it = g_unloading_wallet_set.insert(name);
        assert(it.second);
    }
    // The wallet can be in use so it's not possible to explicitly unload here.
    // Notify the unload intent so that all remaining shared pointers are
    // released.
    wallet->NotifyUnload();

    // Time to ditch our shared_ptr and wait for ReleaseWallet call.
    wallet.reset();
    {
        WAIT_LOCK(g_wallet_release_mutex, lock);
        while (g_unloading_wallet_set.count(name) == 1) {
            g_wallet_release_cv.wait(lock);
        }
    }
}

namespace {
bool PopulatePrivateViewingKeys(CPrivateWalletChain& chain, const BIP39Seed& seed, std::string& error)
{
    OrchardKeyMan keyman{chain};
    for (const bool internal : {false, true}) {
        PrivateOrchardKeyPath path{keyman.GetChain().account, internal, 0, keyman.GetChain().derivation_version};
        std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE> full_viewing_key{};
        const auto result = DeriveNitoPrivateOrchardFullViewingKey(seed, path, full_viewing_key, error);
        if (result != PrivateOrchardBuildResult::OK) {
            return false;
        }
        chain.SetFullViewingKey(internal, full_viewing_key);
    }
    return true;
}

std::shared_ptr<CWallet> LoadWalletInternal(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    try {
        std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(name, options, status, error);
        if (!database) {
            error = Untranslated("Wallet file verification failed.") + Untranslated(" ") + error;
            return nullptr;
        }

        context.chain->initMessage(_("Loading wallet…").translated);
        const SecureString empty_bip39_passphrase;
        std::shared_ptr<CWallet> wallet = CWallet::Create(context, name, std::move(database), options.create_flags, empty_bip39_passphrase, error, warnings);
        if (!wallet) {
            error = _("Wallet loading failed.") + Untranslated(" ") + error;
            status = DatabaseStatus::FAILED_LOAD;
            return nullptr;
        }

        // Legacy wallets are being deprecated, warn if the loaded wallet is legacy
        if (!wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            warnings.push_back(_("Wallet loaded successfully. The legacy wallet type is being deprecated and support for creating and opening legacy wallets will be removed in the future. Legacy wallets can be migrated to a descriptor wallet with migratewallet."));
        }

        NotifyWalletLoaded(context, wallet);
        AddWallet(context, wallet);
        wallet->postInitProcess();

        // Write the wallet setting
        UpdateWalletSetting(*context.chain, name, load_on_start, warnings);

        return wallet;
    } catch (const std::runtime_error& e) {
        error = Untranslated(e.what());
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }
}

class FastWalletRescanFilter
{
public:
    explicit FastWalletRescanFilter(const CWallet& wallet) : m_wallet(wallet)
    {
        // fast rescanning via block filters is only supported by descriptor wallets right now
        assert(!m_wallet.IsLegacy());

        // create initial filter with scripts from all ScriptPubKeyMans
        for (auto spkm : m_wallet.GetAllScriptPubKeyMans()) {
            auto desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(spkm)};
            assert(desc_spkm != nullptr);
            const int32_t covered_range_end{desc_spkm->GetEndRange()};
            AddScriptPubKeys(desc_spkm);
            // save each range descriptor's end for possible future filter updates
            if (desc_spkm->IsHDEnabled()) {
                m_last_range_ends.emplace(desc_spkm->GetID(), covered_range_end);
            }
        }
    }

    bool UpdateIfNeeded()
    {
        bool updated{false};
        // repopulate filter with new scripts if top-up has happened since last iteration
        for (const auto& [desc_spkm_id, last_range_end] : m_last_range_ends) {
            auto desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(m_wallet.GetScriptPubKeyMan(desc_spkm_id))};
            assert(desc_spkm != nullptr);
            int32_t current_range_end{desc_spkm->GetEndRange()};
            if (current_range_end > last_range_end) {
                AddScriptPubKeys(desc_spkm, last_range_end);
                m_last_range_ends.at(desc_spkm->GetID()) = current_range_end;
                updated = true;
            }
        }
        return updated;
    }

    std::optional<bool> MatchesBlock(const uint256& block_hash) const
    {
        return m_wallet.chain().blockFilterMatchesAny(BlockFilterType::BASIC, block_hash, m_filter_set);
    }

    std::optional<std::vector<interfaces::BlockKey>> MatchBlockRange(int start_height, int stop_height) const
    {
        return m_wallet.chain().findBlockFilterMatches(BlockFilterType::BASIC, start_height, stop_height, m_filter_set);
    }

private:
    const CWallet& m_wallet;
    /** Map for keeping track of each range descriptor's last covered filter end.
      * This information is used to detect whether new addresses should be added
      * to the filter after processing a block.
      */
    std::map<uint256, int32_t> m_last_range_ends;
    GCSFilter::ElementSet m_filter_set;

    void AddScriptPubKeys(const DescriptorScriptPubKeyMan* desc_spkm, int32_t last_range_end = 0)
    {
        for (const auto& script_pub_key : desc_spkm->GetScriptPubKeys(last_range_end)) {
            m_filter_set.emplace(script_pub_key.begin(), script_pub_key.end());
        }
    }
};

std::set<CScript> CollectWalletScriptPubKeys(const CWallet& wallet)
{
    std::set<CScript> script_pub_keys;
    LOCK(wallet.cs_wallet);
    for (ScriptPubKeyMan* spkm : wallet.GetAllScriptPubKeyMans()) {
        const auto scripts = spkm->GetScriptPubKeys();
        script_pub_keys.insert(scripts.begin(), scripts.end());
    }
    return script_pub_keys;
}

static constexpr unsigned int SEED_RESTORE_KEYPOOL_SIZE{DEFAULT_KEYPOOL_SIZE};
} // namespace

std::shared_ptr<CWallet> LoadWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    auto result = WITH_LOCK(g_loading_wallet_mutex, return g_loading_wallet_set.insert(name));
    if (!result.second) {
        error = Untranslated("Wallet already loading.");
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }
    auto wallet = LoadWalletInternal(context, name, load_on_start, options, status, error, warnings);
    WITH_LOCK(g_loading_wallet_mutex, g_loading_wallet_set.erase(result.first));
    return wallet;
}

std::shared_ptr<CWallet> CreateWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    uint64_t wallet_creation_flags = options.create_flags;
    const SecureString& passphrase = options.create_passphrase;
    const SecureString& bip39_passphrase = options.create_bip39_passphrase;

    auto normalized_bip39_passphrase{NormalizeBIP39Passphrase(bip39_passphrase)};
    if (!normalized_bip39_passphrase) {
        error = util::ErrorString(normalized_bip39_passphrase);
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }
    const bool bip39_passphrase_enabled{!normalized_bip39_passphrase->empty()};
    ClearBIP39Passphrase(*normalized_bip39_passphrase);

    if (bip39_passphrase_enabled && !(wallet_creation_flags & WALLET_FLAG_DESCRIPTORS)) {
        error = Untranslated("A BIP39 passphrase requires a descriptor wallet.");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }
    if (bip39_passphrase_enabled && (wallet_creation_flags & WALLET_FLAG_BLANK_WALLET)) {
        error = Untranslated("A BIP39 passphrase cannot be used to create a blank wallet.");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }
    if (bip39_passphrase_enabled && (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = Untranslated("A BIP39 passphrase cannot be used when private keys are disabled.");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }
    if (bip39_passphrase_enabled && (wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER)) {
        error = Untranslated("A BIP39 passphrase cannot be used with an external signer.");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    if (wallet_creation_flags & WALLET_FLAG_DESCRIPTORS) options.require_format = DatabaseFormat::SQLITE;

    // Indicate that the wallet is actually supposed to be blank and not just blank to make it encrypted
    bool create_blank = (wallet_creation_flags & WALLET_FLAG_BLANK_WALLET);

    // Born encrypted wallets need to be created blank first.
    if (!passphrase.empty()) {
        wallet_creation_flags |= WALLET_FLAG_BLANK_WALLET;
    }

    // Private keys must be disabled for an external signer wallet
    if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) && !(wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = Untranslated("Private keys must be disabled when using an external signer");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Descriptor support must be enabled for an external signer wallet
    if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) && !(wallet_creation_flags & WALLET_FLAG_DESCRIPTORS)) {
        error = Untranslated("Descriptor support must be enabled when using an external signer");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Do not allow a passphrase when private keys are disabled
    if (!passphrase.empty() && (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = Untranslated("Passphrase provided but private keys are disabled. A passphrase is only used to encrypt private keys, so cannot be used for wallets with private keys disabled.");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Wallet::Verify will check if we're trying to create a wallet with a duplicate name.
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(name, options, status, error);
    if (!database) {
        error = Untranslated("Wallet file verification failed.") + Untranslated(" ") + error;
        status = DatabaseStatus::FAILED_VERIFY;
        return nullptr;
    }

    // Make the wallet
    context.chain->initMessage(_("Loading wallet…").translated);
    std::shared_ptr<CWallet> wallet = CWallet::Create(context, name, std::move(database), wallet_creation_flags, bip39_passphrase, error, warnings);
    if (!wallet) {
        error = Untranslated("Wallet creation failed.") + Untranslated(" ") + error;
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Encrypt the wallet
    if (!passphrase.empty() && !(wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        if (!wallet->EncryptWallet(passphrase)) {
            error = Untranslated("Error: Wallet created but failed to encrypt.");
            status = DatabaseStatus::FAILED_ENCRYPT;
            return nullptr;
        }
        if (!create_blank) {
            // Unlock the wallet
            if (!wallet->Unlock(passphrase)) {
                error = Untranslated("Error: Wallet was encrypted but could not be unlocked");
                status = DatabaseStatus::FAILED_ENCRYPT;
                return nullptr;
            }

            // Set a seed for the wallet
            {
                LOCK(wallet->cs_wallet);
                if (wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
                    CKey mnemonic_entropy{GenerateRandomKey()};
                    wallet->SetupDescriptorScriptPubKeyMans(mnemonic_entropy, bip39_passphrase);
                } else {
                    for (auto spk_man : wallet->GetActiveScriptPubKeyMans()) {
                        if (!spk_man->SetupGeneration()) {
                            error = Untranslated("Unable to generate initial keys");
                            status = DatabaseStatus::FAILED_CREATE;
                            return nullptr;
                        }
                    }
                    LegacyScriptPubKeyMan* legacy_spk_man{wallet->GetLegacyScriptPubKeyMan()};
                    if (!legacy_spk_man) {
                        error = Untranslated("Unable to access the newly-created encrypted legacy wallet key manager.");
                        status = DatabaseStatus::FAILED_CREATE;
                        return nullptr;
                    }
                    const CHDChain& hd_chain{legacy_spk_man->GetHDChain()};
                    CKey legacy_seed;
                    if (hd_chain.seed_id.IsNull() || !legacy_spk_man->GetKey(hd_chain.seed_id, legacy_seed)) {
                        error = Untranslated("Unable to retrieve the newly-created encrypted legacy wallet seed.");
                        status = DatabaseStatus::FAILED_CREATE;
                        return nullptr;
                    }
                    bilingual_str private_seed_error;
                    const SecureString empty_bip39_passphrase;
                    if (!wallet->InitializePrivateHDSeed(legacy_seed, empty_bip39_passphrase, PrivateSeedScope::FULL_WALLET, private_seed_error)) {
                        error = private_seed_error;
                        status = DatabaseStatus::FAILED_CREATE;
                        return nullptr;
                    }
                    bilingual_str private_metadata_error;
                    if (!wallet->PreparePrivateViewingKeyMetadata(/*batch=*/nullptr, private_metadata_error)) {
                        error = private_metadata_error;
                        status = DatabaseStatus::FAILED_CREATE;
                        return nullptr;
                    }
                }
            }

            // Relock the wallet
            wallet->Lock();
        }
    }

    NotifyWalletLoaded(context, wallet);
    AddWallet(context, wallet);
    wallet->postInitProcess();

    // Write the wallet settings
    UpdateWalletSetting(*context.chain, name, load_on_start, warnings);

    // Legacy wallets are being deprecated, warn if a newly created wallet is legacy
    if (!(wallet_creation_flags & WALLET_FLAG_DESCRIPTORS)) {
        warnings.push_back(_("Wallet created successfully. The legacy wallet type is being deprecated and support for creating and opening legacy wallets will be removed in the future."));
    }

    status = DatabaseStatus::SUCCESS;
    return wallet;
}

std::shared_ptr<CWallet> RestoreWallet(WalletContext& context, const fs::path& backup_file, const std::string& wallet_name, std::optional<bool> load_on_start, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    DatabaseOptions options;
    ReadDatabaseArgs(*context.args, options);
    options.require_existing = true;

    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::u8path(wallet_name));
    auto wallet_file = wallet_path / "wallet.dat";
    std::shared_ptr<CWallet> wallet;

    try {
        if (!fs::exists(backup_file)) {
            error = Untranslated("Backup file does not exist");
            status = DatabaseStatus::FAILED_INVALID_BACKUP_FILE;
            return nullptr;
        }

        if (fs::exists(wallet_path) || !TryCreateDirectories(wallet_path)) {
            error = Untranslated(strprintf("Failed to create database path '%s'. Database already exists.", fs::PathToString(wallet_path)));
            status = DatabaseStatus::FAILED_ALREADY_EXISTS;
            return nullptr;
        }

        fs::copy_file(backup_file, wallet_file, fs::copy_options::none);

        wallet = LoadWallet(context, wallet_name, load_on_start, options, status, error, warnings);
    } catch (const std::exception& e) {
        assert(!wallet);
        if (!error.empty()) error += Untranslated("\n");
        error += strprintf(Untranslated("Unexpected exception: %s"), e.what());
    }
    if (!wallet) {
        fs::remove_all(wallet_path);
    }

    return wallet;
}

/** @defgroup mapWallet
 *
 * @{
 */

const CWalletTx* CWallet::GetWalletTx(const uint256& hash) const
{
    AssertLockHeld(cs_wallet);
    const auto it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return nullptr;
    return &(it->second);
}

void CWallet::UpgradeKeyMetadata()
{
    if (IsLocked() || IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
        return;
    }

    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return;
    }

    spk_man->UpgradeKeyMetadata();
    SetWalletFlag(WALLET_FLAG_KEY_ORIGIN_METADATA);
}

void CWallet::UpgradeDescriptorCache()
{
    if (!IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) || IsLocked() || IsWalletFlagSet(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED)) {
        return;
    }

    for (ScriptPubKeyMan* spkm : GetAllScriptPubKeyMans()) {
        DescriptorScriptPubKeyMan* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        desc_spkm->UpgradeDescriptorCache();
    }
    SetWalletFlag(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase, bilingual_str* error)
{
    CCrypter crypter;
    CKeyingMaterial _vMasterKey;
    bilingual_str derived_seed_error;
    if (error) *error = {};

    {
        LOCK(cs_wallet);
        for (const MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                continue; // try another master key
            bilingual_str candidate_error;
            if (Unlock(_vMasterKey, &candidate_error)) {
                // Now that we've unlocked, upgrade the key metadata
                UpgradeKeyMetadata();
                // Now that we've unlocked, upgrade the descriptor cache
                UpgradeDescriptorCache();
                bilingual_str private_metadata_error;
                if (!PreparePrivateViewingKeyMetadata(/*batch=*/nullptr, private_metadata_error, /*require_seed=*/false)) {
                    WalletLogPrintf("Nito.network private viewing metadata preparation skipped after unlock: %s\n", private_metadata_error.original);
                }
                return true;
            }
            if (!candidate_error.original.empty()) derived_seed_error = std::move(candidate_error);
        }
    }
    if (error && !derived_seed_error.original.empty()) *error = std::move(derived_seed_error);
    return false;
}

bool CWallet::TryRelock(int64_t expected_relock_time)
{
    LOCK2(m_relock_mutex, cs_wallet);
    if (nRelockTime != expected_relock_time || IsScanningWithPassphrase()) {
        return false;
    }
    Lock();
    nRelockTime = 0;
    return true;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK2(m_relock_mutex, cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial _vMasterKey;
        for (MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                return false;
            if (Unlock(_vMasterKey))
            {
                constexpr MillisecondsDouble target{100};
                auto start{SteadyClock::now()};
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * target / (SteadyClock::now() - start));

                start = SteadyClock::now();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * target / (SteadyClock::now() - start))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                WalletLogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(_vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                WalletBatch(GetDatabase()).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::chainStateFlushed(ChainstateRole role, const CBlockLocator& loc)
{
    // Don't update the best block until the chain is attached so that in case of a shutdown,
    // the rescan will be restarted at next startup.
    if (m_attaching_chain || role == ChainstateRole::BACKGROUND) {
        return;
    }

    std::optional<SeedHistoryState> updated_seed_history;
    {
        LOCK(cs_wallet);
        const CPrivateWalletChain& private_chain{m_orchard_keyman.GetChain()};
        if (m_seed_history_state.m_mode == SeedHistoryMode::FULL_HISTORY &&
            m_last_block_processed_height >= 0 &&
            !private_chain.private_locked_live_scan.IsPending()) {
            updated_seed_history = m_seed_history_state;
            updated_seed_history->m_full_history_height = m_last_block_processed_height;
            updated_seed_history->m_full_history_block = m_last_block_processed;
            updated_seed_history->MarkHistory(/*orchard=*/false, SeedRecoveryStatus::COMPLETE, m_last_block_processed_height, m_last_block_processed);
            if (updated_seed_history->m_orchard.m_explicit_history.m_status != SeedRecoveryStatus::NOT_APPLICABLE) {
                updated_seed_history->MarkHistory(/*orchard=*/true, SeedRecoveryStatus::COMPLETE, m_last_block_processed_height, m_last_block_processed);
            }
        }
    }

    WalletBatch batch(GetDatabase());
    batch.WriteBestBlock(loc);
    if (updated_seed_history) {
        if (batch.WriteSeedHistoryState(*updated_seed_history)) {
            LOCK(cs_wallet);
            m_seed_history_state = *updated_seed_history;
        }
    }
}

bool CWallet::SetSeedHistoryState(const SeedHistoryState& state)
{
    if (!state.IsValid()) return false;
    if (!WalletBatch(GetDatabase()).WriteSeedHistoryState(state)) return false;
    LOCK(cs_wallet);
    m_seed_history_state = state;
    return true;
}

void CWallet::SetMinVersion(enum WalletFeature nVersion, WalletBatch* batch_in)
{
    LOCK(cs_wallet);
    if (nWalletVersion >= nVersion)
        return;
    WalletLogPrintf("Setting minversion to %d\n", nVersion);
    nWalletVersion = nVersion;

    {
        WalletBatch* batch = batch_in ? batch_in : new WalletBatch(GetDatabase());
        if (nWalletVersion > 40000)
            batch->WriteMinVersion(nWalletVersion);
        if (!batch_in)
            delete batch;
    }
}

std::set<uint256> CWallet::GetConflicts(const uint256& txid) const
{
    std::set<uint256> result;
    AssertLockHeld(cs_wallet);

    const auto it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (const CTxIn& txin : wtx.tx->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
            result.insert(_it->second);
    }
    return result;
}

bool CWallet::HasWalletSpend(const CTransactionRef& tx) const
{
    AssertLockHeld(cs_wallet);
    const Txid& txid = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); ++i) {
        if (IsSpent(COutPoint(txid, i))) {
            return true;
        }
    }
    return false;
}

void CWallet::Flush()
{
    GetDatabase().Flush();
}

void CWallet::Close()
{
    GetDatabase().Close();
}

void CWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = nullptr;
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const CWalletTx* wtx = &mapWallet.at(it->second);
        if (wtx->nOrderPos < nMinOrderPos) {
            nMinOrderPos = wtx->nOrderPos;
            copyFrom = wtx;
        }
    }

    if (!copyFrom) {
        return;
    }

    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        CWalletTx* copyTo = &mapWallet.at(hash);
        if (copyFrom == copyTo) continue;
        assert(copyFrom && "Oldest wallet transaction in range assumed to have been found.");
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const COutPoint& outpoint) const
{
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        const uint256& wtxid = it->second;
        const auto mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            int depth = GetTxDepthInMainChain(mit->second);
            if (depth > 0  || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

bool CWallet::ShouldShowTransaction(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);
    return !IsAvailableBalanceInternal(wtx);
}

bool CWallet::IsAvailableBalanceSyncPending() const
{
    AssertLockHeld(cs_wallet);
    return m_seed_history_state.m_mode == SeedHistoryMode::AVAILABLE_BALANCE &&
           (!m_seed_history_state.FundsRecoveryComplete() || chain().isInitialBlockDownload());
}

void CWallet::AddToSpends(const COutPoint& outpoint, const uint256& wtxid, WalletBatch* batch)
{
    mapTxSpends.insert(std::make_pair(outpoint, wtxid));

    if (batch) {
        UnlockCoin(outpoint, batch);
    } else {
        WalletBatch temp_batch(GetDatabase());
        UnlockCoin(outpoint, &temp_batch);
    }

    std::pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CWallet::AddToSpends(const CWalletTx& wtx, WalletBatch* batch)
{
    if (wtx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn& txin : wtx.tx->vin)
        AddToSpends(txin.prevout, wtx.GetHash(), batch);
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial _vMasterKey;

    _vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(_vMasterKey);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(kMasterKey.vchSalt);

    CCrypter crypter;
    constexpr MillisecondsDouble target{100};
    auto start{SteadyClock::now()};
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = static_cast<unsigned int>(25000 * target / (SteadyClock::now() - start));

    start = SteadyClock::now();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + static_cast<unsigned int>(kMasterKey.nDeriveIterations * target / (SteadyClock::now() - start))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    WalletLogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(_vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK2(m_relock_mutex, cs_wallet);
        // Prepare recipe ciphertext before mutating any wallet key state. A
        // preparation failure can therefore leave the wallet unencrypted.
        std::map<uint256, mapValue_t> protected_bump_metadata;
        for (const auto& [txid, wtx] : mapWallet) {
            if (!wtx.tx->HasPrivateBundle()) continue;
            mapValue_t map_value{wtx.mapValue};
            auto protected_result{feebumper::EncryptPrivateBumpMetadata(_vMasterKey, txid, map_value)};
            if (!protected_result) return false;
            if (*protected_result) protected_bump_metadata.emplace(txid, std::move(map_value));
        }

        // Prepare the BIP39 seed envelope before changing any in-memory key
        // manager. The passphrase itself is never retained; only the already
        // derived 64-byte seed is converted from its clear wallet record.
        std::optional<CBIP39DerivedSeedRecord> protected_bip39_record;
        if (m_bip39_derived_seed_record) {
            auto encrypted_record{EncryptBIP39DerivedSeedRecord(*m_bip39_derived_seed_record, _vMasterKey)};
            if (!encrypted_record) return false;
            protected_bip39_record = std::move(*encrypted_record);
        }

        WalletBatch* encrypted_batch = new WalletBatch(GetDatabase());
        if (!encrypted_batch->TxnBegin()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            return false;
        }
        if (protected_bip39_record && !encrypted_batch->WriteBIP39DerivedSeed(*protected_bip39_record)) {
            encrypted_batch->TxnAbort();
            delete encrypted_batch;
            encrypted_batch = nullptr;
            return false;
        }
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        encrypted_batch->WriteMasterKey(nMasterKeyMaxID, kMasterKey);

        for (const auto& spk_man_pair : m_spk_managers) {
            auto spk_man = spk_man_pair.second.get();
            if (!spk_man->Encrypt(_vMasterKey, encrypted_batch)) {
                encrypted_batch->TxnAbort();
                delete encrypted_batch;
                encrypted_batch = nullptr;
                // We now probably have half of our keys encrypted in memory, and half not...
                // die and let the user reload the unencrypted wallet.
                assert(false);
            }
        }

        // Persist prepared recipe ciphertext in the same transaction that
        // makes the wallet encrypted.
        for (const auto& [txid, map_value] : protected_bump_metadata) {
            const CWalletTx& original_wtx{mapWallet.at(txid)};
            CWalletTx protected_wtx{original_wtx.tx, original_wtx.m_state};
            protected_wtx.CopyFrom(original_wtx);
            protected_wtx.mapValue = map_value;
            if (!encrypted_batch->WriteTx(protected_wtx)) {
                encrypted_batch->TxnAbort();
                delete encrypted_batch;
                encrypted_batch = nullptr;
                assert(false);
            }
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, encrypted_batch);

        if (!encrypted_batch->TxnCommit()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            // We now have keys encrypted in memory, but not on disk...
            // die to avoid confusion and let the user reload the unencrypted wallet.
            assert(false);
        }

        for (auto& [txid, map_value] : protected_bump_metadata) {
            mapWallet.at(txid).mapValue = std::move(map_value);
        }
        if (protected_bip39_record) {
            if (!m_bip39_derived_seed_record->payload.empty()) {
                memory_cleanse(m_bip39_derived_seed_record->payload.data(), m_bip39_derived_seed_record->payload.size());
                m_bip39_derived_seed_record->payload.clear();
            }
            m_bip39_derived_seed_record = std::move(*protected_bip39_record);
        }

        delete encrypted_batch;
        encrypted_batch = nullptr;

        // Convert any already-received Orchard notes before Lock() scrubs the
        // decrypted in-memory records. This migration uses the new master key
        // and removes the legacy plaintext note records atomically.
        vMasterKey = _vMasterKey;
        if (!MigratePrivateNoteEncryption()) {
            assert(false);
        }
        Lock();
        Unlock(strWalletPassphrase);

        bilingual_str private_metadata_error;
        if (!PreparePrivateViewingKeyMetadata(/*batch=*/nullptr, private_metadata_error, /*require_seed=*/false)) {
            WalletLogPrintf("Nito.network private viewing metadata preparation skipped during encryption: %s\n", private_metadata_error.original);
        }
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        if (!GetDatabase().Rewrite()) {
            // The logical records are encrypted, but old plaintext may remain
            // in database slack/free pages until the rewrite completes.
            assert(false);
        }

        // BDB seems to have a bad habit of writing old data into
        // slack space in .dat files; that is bad if the old data is
        // unencrypted private keys. So:
        GetDatabase().ReloadDbEnv();

    }
    NotifyStatusChanged(this);

    return true;
}

DBErrors CWallet::ReorderTransactions()
{
    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx into a sorted-by-time multimap.
    typedef std::multimap<int64_t, CWalletTx*> TxItems;
    TxItems txByTime;

    for (auto& entry : mapWallet)
    {
        CWalletTx* wtx = &entry.second;
        txByTime.insert(std::make_pair(wtx->nTimeReceived, wtx));
    }

    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second;
        int64_t& nOrderPos = pwtx->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (!batch.WriteTx(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            for (const int64_t& nOffsetStart : nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (!batch.WriteTx(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
    }
    batch.WriteOrderPosNext(nOrderPosNext);

    return DBErrors::LOAD_OK;
}

int64_t CWallet::IncOrderPosNext(WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    int64_t nRet = nOrderPosNext++;
    if (batch) {
        batch->WriteOrderPosNext(nOrderPosNext);
    } else {
        WalletBatch(GetDatabase()).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        for (std::pair<const uint256, CWalletTx>& item : mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::MarkReplaced(const uint256& originalHash, const uint256& newHash)
{
    LOCK(cs_wallet);

    auto mi = mapWallet.find(originalHash);

    // There is a bug if MarkReplaced is not called on an existing wallet transaction.
    assert(mi != mapWallet.end());

    CWalletTx& wtx = (*mi).second;

    // Ensure for now that we're not overwriting data
    assert(wtx.mapValue.count("replaced_by_txid") == 0);

    wtx.mapValue["replaced_by_txid"] = newHash.ToString();

    // Refresh mempool status without waiting for transactionRemovedFromMempool or transactionAddedToMempool
    RefreshMempoolStatus(wtx, chain());
    if (wtx.tx && wtx.tx->HasPrivateBundle()) {
        RefreshPrivateSpentState();
    }

    WalletBatch batch(GetDatabase());

    bool success = true;
    if (!batch.WriteTx(wtx)) {
        if (wtx.tx && wtx.tx->HasPrivateBundle()) {
            WalletLogPrintf("%s: Updating private transaction batch failed (identifier redacted)\n", __func__);
        } else {
            WalletLogPrintf("%s: Updating batch tx %s failed\n", __func__, wtx.GetHash().ToString());
        }
        success = false;
    }

    NotifyTransactionChanged(originalHash, CT_UPDATED);

    return success;
}

void CWallet::SetSpentKeyState(WalletBatch& batch, const uint256& hash, unsigned int n, bool used, std::set<CTxDestination>& tx_destinations)
{
    AssertLockHeld(cs_wallet);
    const CWalletTx* srctx = GetWalletTx(hash);
    if (!srctx) return;

    CTxDestination dst;
    if (ExtractDestination(srctx->tx->vout[n].scriptPubKey, dst)) {
        if (IsMine(dst)) {
            if (used != IsAddressPreviouslySpent(dst)) {
                if (used) {
                    tx_destinations.insert(dst);
                }
                SetAddressPreviouslySpent(batch, dst, used);
            }
        }
    }
}

bool CWallet::IsSpentKey(const CScript& scriptPubKey) const
{
    AssertLockHeld(cs_wallet);
    CTxDestination dest;
    if (!ExtractDestination(scriptPubKey, dest)) {
        return false;
    }
    if (IsAddressPreviouslySpent(dest)) {
        return true;
    }
    if (IsLegacy()) {
        LegacyScriptPubKeyMan* spk_man = GetLegacyScriptPubKeyMan();
        assert(spk_man != nullptr);
        for (const auto& keyid : GetAffectedKeys(scriptPubKey, *spk_man)) {
            WitnessV0KeyHash wpkh_dest(keyid);
            if (IsAddressPreviouslySpent(wpkh_dest)) {
                return true;
            }
            ScriptHash sh_wpkh_dest(GetScriptForDestination(wpkh_dest));
            if (IsAddressPreviouslySpent(sh_wpkh_dest)) {
                return true;
            }
            PKHash pkh_dest(keyid);
            if (IsAddressPreviouslySpent(pkh_dest)) {
                return true;
            }
        }
    }
    return false;
}

CWalletTx* CWallet::AddToWallet(CTransactionRef tx, const TxState& state, const UpdateWalletTxFn& update_wtx, bool fFlushOnClose, bool rescanning_old_block)
{
    LOCK(cs_wallet);

    WalletBatch batch(GetDatabase(), fFlushOnClose);

    uint256 hash = tx->GetHash();

    if (IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
        // Mark used destinations
        std::set<CTxDestination> tx_destinations;

        for (const CTxIn& txin : tx->vin) {
            const COutPoint& op = txin.prevout;
            SetSpentKeyState(batch, op.hash, op.n, true, tx_destinations);
        }

        MarkDestinationsDirty(tx_destinations);
    }

    // Inserts only if not already there, returns tx inserted or tx found
    auto ret = mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple(tx, state));
    CWalletTx& wtx = (*ret.first).second;
    bool fInsertedNew = ret.second;
    bool fUpdated = update_wtx && update_wtx(wtx, fInsertedNew);
    if (fInsertedNew) {
        wtx.nTimeReceived = GetTime();
        wtx.nOrderPos = IncOrderPosNext(&batch);
        wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
        wtx.nTimeSmart = ComputeTimeSmart(wtx, rescanning_old_block);
        AddToSpends(wtx, &batch);

        // Update birth time when tx time is older than it.
        MaybeUpdateBirthTime(wtx.GetTxTime());
    }

    if (!fInsertedNew)
    {
        if (state.index() != wtx.m_state.index()) {
            wtx.m_state = state;
            fUpdated = true;
        } else {
            assert(TxStateSerializedIndex(wtx.m_state) == TxStateSerializedIndex(state));
            assert(TxStateSerializedBlockHash(wtx.m_state) == TxStateSerializedBlockHash(state));
        }
        // If we have a witness-stripped version of this transaction, and we
        // see a new version with a witness, then we must be upgrading a pre-segwit
        // wallet.  Store the new version of the transaction with the witness,
        // as the stripped-version must be invalid.
        // TODO: Store all versions of the transaction, instead of just one.
        if (tx->HasWitness() && !wtx.tx->HasWitness()) {
            wtx.SetTx(tx);
            fUpdated = true;
        }
    }

    // Capture display metadata while previous outputs are still available. It
    // is committed in the same wallet record as the transaction, before notify.
    // Live block notifications resolve undo data after releasing cs_wallet.
    // Historical scans already run in a wallet worker and reuse the block cache.
    const auto input_addresses = ResolveInputAddresses(wtx, /*read_block=*/rescanning_old_block);
    if (input_addresses != wtx.m_input_addresses) {
        wtx.m_input_addresses = input_addresses;
        fUpdated = true;
    }

    // Mark inactive coinbase transactions and their descendants as abandoned
    if (wtx.IsCoinBase() && wtx.isInactive()) {
        std::vector<CWalletTx*> txs{&wtx};

        TxStateInactive inactive_state = TxStateInactive{/*abandoned=*/true};

        while (!txs.empty()) {
            CWalletTx* desc_tx = txs.back();
            txs.pop_back();
            desc_tx->m_state = inactive_state;
            // Break caches since we have changed the state
            desc_tx->MarkDirty();
            batch.WriteTx(*desc_tx);
            MarkInputsDirty(desc_tx->tx);
            for (unsigned int i = 0; i < desc_tx->tx->vout.size(); ++i) {
                COutPoint outpoint(desc_tx->GetHash(), i);
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(outpoint);
                for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
                    const auto wit = mapWallet.find(it->second);
                    if (wit != mapWallet.end()) {
                        txs.push_back(&wit->second);
                    }
                }
            }
        }
    }

    if (wtx.tx && wtx.tx->HasPrivateBundle()) {
        WalletLogPrintf("AddToWallet [private transaction identifiers redacted]  %s%s\n",
            (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));
    } else {
        WalletLogPrintf("AddToWallet %s  %s%s %s\n", hash.ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""), TxStateString(state));
    }

    // Write to disk
    if (fInsertedNew || fUpdated)
        if (!batch.WriteTx(wtx))
            return nullptr;

    // Break debit/credit balance caches:
    wtx.MarkDirty();

    // Notify UI of new or updated transaction
    NotifyTransactionChanged(hash, fInsertedNew ? CT_NEW : CT_UPDATED);

#if HAVE_SYSTEM
    // notify an external script when a wallet transaction comes in or is updated
    std::string strCmd = m_notify_tx_changed_script;

    if (!strCmd.empty())
    {
        ReplaceAll(strCmd, "%s", hash.GetHex());
        if (auto* conf = wtx.state<TxStateConfirmed>())
        {
            ReplaceAll(strCmd, "%b", conf->confirmed_block_hash.GetHex());
            ReplaceAll(strCmd, "%h", ToString(conf->confirmed_block_height));
        } else {
            ReplaceAll(strCmd, "%b", "unconfirmed");
            ReplaceAll(strCmd, "%h", "-1");
        }
#ifndef WIN32
        // Substituting the wallet name isn't currently supported on windows
        // because windows shell escaping has not been implemented yet:
        // https://github.com/bitcoin/bitcoin/pull/13339#issuecomment-537384875
        // A few ways it could be implemented in the future are described in:
        // https://github.com/bitcoin/bitcoin/pull/13339#issuecomment-461288094
        ReplaceAll(strCmd, "%w", ShellEscape(GetName()));
#endif
        std::thread t(runCommand, strCmd);
        t.detach(); // thread runs free
    }
#endif

    return &wtx;
}

bool CWallet::LoadToWallet(const uint256& hash, const UpdateWalletTxFn& fill_wtx)
{
    const auto& ins = mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple(nullptr, TxStateInactive{}));
    CWalletTx& wtx = ins.first->second;
    if (!fill_wtx(wtx, ins.second)) {
        return false;
    }
    // If wallet doesn't have a chain (e.g when using nito-wallet tool),
    // don't bother to update txn.
    if (HaveChain()) {
      wtx.updateState(chain());
    }
    if (/* insertion took place */ ins.second) {
        wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
    }
    AddToSpends(wtx);
    for (const CTxIn& txin : wtx.tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            CWalletTx& prevtx = it->second;
            if (auto* prev = prevtx.state<TxStateConflicted>()) {
                MarkConflicted(prev->conflicting_block_hash, prev->conflicting_block_height, wtx.GetHash());
            }
        }
    }

    // Update birth time when tx time is older than it.
    MaybeUpdateBirthTime(wtx.GetTxTime());

    return true;
}

void CWallet::ClearPrivateRescanViewingKeys()
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    for (auto& key : m_private_rescan_viewing_keys) {
        memory_cleanse(key.full_viewing_key.data(), key.full_viewing_key.size());
    }
    m_private_rescan_viewing_keys.clear();
    m_private_rescan_viewing_key_end.fill(0);
}

bool CWallet::MakePrivateScanViewingKey(const CPrivateWalletChain& chain, bool internal, PrivateOrchardScanViewingKey& viewing_key) const
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    viewing_key = PrivateOrchardScanViewingKey{};
    viewing_key.internal = internal;

    if (!CanViewPrivateData() || !chain.HasFullViewingKey(internal)) return false;

    viewing_key.full_viewing_key = chain.FullViewingKey(internal);
    return true;
}

bool CWallet::ExtendPrivateRescanViewingKeys(const CPrivateWalletChain& chain, bool internal, uint32_t target_end)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    const size_t branch_pos = internal ? 1 : 0;
    uint32_t& cached_end = m_private_rescan_viewing_key_end[branch_pos];
    if (target_end <= cached_end) return true;

    const uint32_t begin = cached_end;
    const bool branch_key_cached = std::any_of(m_private_rescan_viewing_keys.begin(), m_private_rescan_viewing_keys.end(),
        [&](const PrivateOrchardScanViewingKey& key) { return key.internal == internal; });

    if (!branch_key_cached) {
        PrivateOrchardScanViewingKey viewing_key;
        if (!MakePrivateScanViewingKey(chain, internal, viewing_key)) return false;
        m_private_rescan_viewing_keys.push_back(viewing_key);
        memory_cleanse(viewing_key.full_viewing_key.data(), viewing_key.full_viewing_key.size());
    }

    cached_end = target_end;
    LogPrint(BCLog::SCAN, "Private Wallet Scan: Prepared %s Orchard branch viewing key; resolution end advanced from %u to %u\n",
        internal ? "internal" : "external",
        static_cast<unsigned>(begin),
        static_cast<unsigned>(target_end));
    return true;
}

bool CWallet::PreparePrivateRescanViewingKeys(bool deep_scan)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    ClearPrivateRescanViewingKeys();

    OrchardKeyMan scan_keyman{m_orchard_keyman.GetChain()};
    const uint32_t lookahead = deep_scan ? NITO_PRIVATE_ORCHARD_RECOVERY_GAP_LIMIT : NITO_PRIVATE_ORCHARD_LIVE_LOOKAHEAD;

    for (const bool internal : {false, true}) {
        const uint32_t next_index = scan_keyman.NextIndex(internal);
        const uint32_t scan_limit = next_index > std::numeric_limits<uint32_t>::max() - lookahead ?
            std::numeric_limits<uint32_t>::max() : next_index + lookahead;
        if (!ExtendPrivateRescanViewingKeys(scan_keyman.GetChain(), internal, scan_limit)) {
            ClearPrivateRescanViewingKeys();
            return false;
        }
    }

    LogPrint(BCLog::SCAN, "Private Wallet Scan: Prepared %u Orchard branch viewing keys for %s rescan with gap %u\n",
        static_cast<unsigned>(m_private_rescan_viewing_keys.size()),
        deep_scan ? "deep" : "live",
        static_cast<unsigned>(lookahead));
    return !m_private_rescan_viewing_keys.empty();
}

CWallet::PrivateCompactProbeResult CWallet::ProbePrivateCompactEffects(const CPrivateCompactEffects& effects, std::vector<PrivateOrchardCompactMatch>& matches)
{
    matches.clear();
    if (!effects.HasActions()) return PrivateCompactProbeResult::NO_MATCH;

    std::vector<PrivateOrchardScanViewingKey> all_scan_keys;
    CPrivateWalletChain private_chain;
    {
        LOCK(cs_wallet);
        all_scan_keys = m_private_rescan_viewing_keys;
        private_chain = m_orchard_keyman.GetChain();
    }
    if (all_scan_keys.empty()) return PrivateCompactProbeResult::NO_MATCH;

    auto cleanse_scan_keys = [](std::vector<PrivateOrchardScanViewingKey>& scan_keys) {
        for (auto& scan_key : scan_keys) {
            memory_cleanse(scan_key.full_viewing_key.data(), scan_key.full_viewing_key.size());
        }
    };

    std::vector<PrivateOrchardViewingKey> viewing_keys;
    viewing_keys.reserve(all_scan_keys.size());
    for (const auto& scan_key : all_scan_keys) {
        viewing_keys.push_back(PrivateOrchardViewingKey{
            scan_key.internal,
            Span<const unsigned char>{scan_key.full_viewing_key.data(), scan_key.full_viewing_key.size()},
            Span<const unsigned char>{},
            false});
    }

    std::vector<PrivateOrchardCompactDecryptionResult> results;
    std::string error;
    const auto scan_start{SteadyClock::now()};
    const auto result = DecryptPrivateOrchardCompactOutputsWithFullViewingKeys(
        Span<const PrivateOrchardViewingKey>{viewing_keys.data(), viewing_keys.size()},
        effects,
        results,
        error);
    if (result != PrivateOrchardBuildResult::OK) {
        cleanse_scan_keys(all_scan_keys);
        WalletLogPrintf("Private Wallet Compact Scan: failed to probe indexed Orchard effects: %s\n", error);
        return PrivateCompactProbeResult::SCAN_ERROR;
    }

    for (size_t action_index = 0; action_index < results.size(); ++action_index) {
        const auto& result = results[action_index];
        if (!result.matched || result.viewing_key_index >= all_scan_keys.size()) continue;

        const PrivateOrchardScanViewingKey& scan_key = all_scan_keys[result.viewing_key_index];
        bool index_matched{false};
        uint32_t diversifier_index{0};
        const auto index_result = GetPrivateOrchardDiversifierIndex(
            Span<const unsigned char>{scan_key.full_viewing_key.data(), scan_key.full_viewing_key.size()},
            scan_key.internal,
            Span<const unsigned char>{result.note.recipient_raw.data(), result.note.recipient_raw.size()},
            index_matched,
            diversifier_index,
            error);
        if (index_result != PrivateOrchardBuildResult::OK || !index_matched) {
            WalletLogPrintf("Private Wallet Compact Scan: failed to resolve an Orchard diversifier index: %s\n", error);
            cleanse_scan_keys(all_scan_keys);
            return PrivateCompactProbeResult::SCAN_ERROR;
        }

        matches.push_back(PrivateOrchardCompactMatch{
            action_index,
            PrivateOrchardKeyPath{private_chain.account, scan_key.internal, diversifier_index, private_chain.derivation_version},
            result.note});
    }
    cleanse_scan_keys(all_scan_keys);

    LogPrint(BCLog::SCAN, "Private Wallet Compact Scan: Actions:%u BranchKeys:%u Matches:%u TimeMs:%d\n",
        static_cast<unsigned>(effects.actions.size()),
        static_cast<unsigned>(viewing_keys.size()),
        static_cast<unsigned>(matches.size()),
        Ticks<std::chrono::milliseconds>(SteadyClock::now() - scan_start));
    return matches.empty() ? PrivateCompactProbeResult::NO_MATCH : PrivateCompactProbeResult::MATCH;
}

void CWallet::RecordPrivateSpentNullifier(WalletBatch& batch, const uint256& nullifier, const uint256& txid, const SyncTxState& state, uint32_t action_index)
{
    AssertLockHeld(cs_wallet);
    if (nullifier.IsNull()) return;

    if (mapPrivateNoteNullifiers.find(nullifier) == mapPrivateNoteNullifiers.end()) return;

    const auto* confirmed = std::get_if<TxStateConfirmed>(&state);
    if (confirmed == nullptr) return;

    CPrivateSpentNullifier spent;
    spent.nullifier = nullifier;
    spent.txid = txid;
    spent.block_hash = confirmed->confirmed_block_hash;
    spent.block_height = confirmed->confirmed_block_height;
    spent.action_index = action_index;

    mapPrivateSpentNullifiers[spent.GetId()] = spent;
    if (!batch.WritePrivateSpentNullifier(spent)) {
        throw std::runtime_error("DB error writing private spent nullifier");
    }
}

bool CWallet::SyncPrivateBundle(const uint256& txid, const CPrivateBundle& bundle, const SyncTxState& state, bool deep_scan)
{
    LOCK(cs_wallet);

    const auto scan_start{SteadyClock::now()};
    bool updated{false};
    size_t decrypt_attempts{0};
    WalletBatch batch(GetDatabase());
    if (!batch.TxnBegin()) {
        throw std::runtime_error("DB error starting atomic private wallet bundle update");
    }

    for (size_t action_index = 0; action_index < bundle.effects.actions.size(); ++action_index) {
        const auto& action = bundle.effects.actions[action_index];
        if (mapPrivateNoteNullifiers.find(action.nullifier) != mapPrivateNoteNullifiers.end()) {
            updated = true;
        }
    }

    const auto* confirmed = std::get_if<TxStateConfirmed>(&state);
    OrchardKeyMan scan_keyman{m_orchard_keyman.GetChain()};
    bool private_chain_dirty{false};
    const uint32_t lookahead = deep_scan ? NITO_PRIVATE_ORCHARD_RECOVERY_GAP_LIMIT : NITO_PRIVATE_ORCHARD_LIVE_LOOKAHEAD;
    std::vector<bool> matched_actions(bundle.effects.actions.size(), false);
    std::string error;

    auto has_unmatched_action = [&]() {
        return std::any_of(matched_actions.begin(), matched_actions.end(), [](bool matched) { return !matched; });
    };

    auto find_commitment_index = [&](const uint256& cmx, uint64_t& commitment_index) {
        return HaveChain() && chain().getPrivateCommitmentIndex(cmx, commitment_index);
    };

    auto record_decrypted_note = [&](const PrivateOrchardKeyPath& path, size_t action_index, const PrivateOrchardDecryptedNote& decrypted)
        EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        const CPrivateActionEffects& action = bundle.effects.actions[action_index];

        CPrivateWalletNote note;
        note.cmx = decrypted.cmx;
        note.nullifier = decrypted.nullifier;
        note.txid = txid;
        if (confirmed) {
            note.block_hash = confirmed->confirmed_block_hash;
            note.block_height = confirmed->confirmed_block_height;
        }
        note.value = decrypted.value;
        note.derivation_version = path.derivation_version;
        note.account = path.account;
        note.internal = path.internal;
        note.diversifier_index = path.diversifier_index;
        note.action_index = static_cast<uint32_t>(action_index);
        note.decrypted = true;
        note.recipient_raw.assign(decrypted.recipient_raw.begin(), decrypted.recipient_raw.end());
        note.rho.assign(decrypted.rho.begin(), decrypted.rho.end());
        note.rseed.assign(decrypted.rseed.begin(), decrypted.rseed.end());
        note.memo.assign(decrypted.memo.begin(), decrypted.memo.end());
        note.enc_ciphertext = action.enc_ciphertext;
        note.out_ciphertext = action.out_ciphertext;

        updated = true;
        matched_actions[action_index] = true;
        if (path.diversifier_index >= scan_keyman.NextIndex(path.internal)) {
            scan_keyman.MarkUsed(path.internal, path.diversifier_index);
            private_chain_dirty = true;
            if (deep_scan && !m_private_rescan_viewing_keys.empty()) {
                const uint32_t next_index = scan_keyman.NextIndex(path.internal);
                const uint32_t scan_limit = next_index > std::numeric_limits<uint32_t>::max() - lookahead ?
                    std::numeric_limits<uint32_t>::max() : next_index + lookahead;
                if (!ExtendPrivateRescanViewingKeys(scan_keyman.GetChain(), path.internal, scan_limit)) {
                    WalletLogPrintf("Private Wallet Scan: Failed to extend an Orchard recovery gap (branch and index redacted)\n");
                }
            }
        }

        if (confirmed) {
            uint64_t commitment_index{0};
            if (find_commitment_index(note.cmx, commitment_index)) {
                note.commitment_index = commitment_index;
            }
        }

        auto existing = mapPrivateNotes.find(note.GetId());
        if (existing == mapPrivateNotes.end()) {
            if (!LoadPrivateNote(note) || !WritePrivateNoteRecord(batch, note)) {
                throw std::runtime_error("DB error writing private wallet note");
            }
        } else {
            CPrivateWalletNote& current = existing->second;
            if (current.txid != note.txid || current.out_ciphertext != note.out_ciphertext) current.m_is_change.reset();
            current.txid = note.txid;
            if (confirmed) {
                current.block_hash = note.block_hash;
                current.block_height = note.block_height;
            } else {
                current.block_hash.SetNull();
                current.block_height = -1;
                current.commitment_index = std::numeric_limits<uint64_t>::max();
            }
            if (note.HasWitnessPosition()) current.commitment_index = note.commitment_index;
            RemovePrivateNoteNullifierIndex(current);
            current.nullifier = note.nullifier;
            current.value = note.value;
            current.derivation_version = note.derivation_version;
            current.account = note.account;
            current.internal = note.internal;
            current.diversifier_index = note.diversifier_index;
            current.action_index = note.action_index;
            current.decrypted = note.decrypted;
            current.recipient_raw = note.recipient_raw;
            current.rho = note.rho;
            current.rseed = note.rseed;
            current.memo = note.memo;
            current.enc_ciphertext = note.enc_ciphertext;
            current.out_ciphertext = note.out_ciphertext;
            AddPrivateNoteNullifierIndex(current);
            if (!WritePrivateNoteRecord(batch, current)) {
                throw std::runtime_error("DB error updating private wallet note");
            }
        }
    };

    auto update_existing_note_for_action = [&](size_t action_index) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        const CPrivateActionEffects& action = bundle.effects.actions[action_index];
        auto existing = mapPrivateNotes.find(action.cmx);
        if (existing == mapPrivateNotes.end()) return false;

        updated = true;
        if (!matched_actions[action_index]) {
            matched_actions[action_index] = true;
        }

        CPrivateWalletNote& current = existing->second;
        if (current.txid != txid || current.out_ciphertext != action.out_ciphertext) current.m_is_change.reset();
        current.txid = txid;
        if (confirmed) {
            current.block_hash = confirmed->confirmed_block_hash;
            current.block_height = confirmed->confirmed_block_height;
            uint64_t commitment_index{0};
            if (find_commitment_index(current.cmx, commitment_index)) {
                current.commitment_index = commitment_index;
            }
        } else {
            current.block_hash.SetNull();
            current.block_height = -1;
            current.commitment_index = std::numeric_limits<uint64_t>::max();
        }
        current.action_index = static_cast<uint32_t>(action_index);
        current.enc_ciphertext = action.enc_ciphertext;
        current.out_ciphertext = action.out_ciphertext;
        if (!WritePrivateNoteRecord(batch, current)) {
            throw std::runtime_error("DB error updating existing private wallet note");
        }
        return true;
    };

    auto resolve_path_for_viewing_key = [&](const PrivateOrchardScanViewingKey& viewing_key, const PrivateOrchardDecryptedNote& decrypted, PrivateOrchardKeyPath& path_out)
        EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        bool index_matched{false};
        uint32_t diversifier_index{0};
        const auto index_result = GetPrivateOrchardDiversifierIndex(
            Span<const unsigned char>{viewing_key.full_viewing_key.data(), viewing_key.full_viewing_key.size()},
            viewing_key.internal,
            Span<const unsigned char>{decrypted.recipient_raw.data(), decrypted.recipient_raw.size()},
            index_matched,
            diversifier_index,
            error);
        if (index_result != PrivateOrchardBuildResult::OK || !index_matched) {
            WalletLogPrintf("Private Wallet Scan: Failed to resolve Orchard diversifier index: %s\n", error);
            return false;
        }

        path_out = PrivateOrchardKeyPath{
            scan_keyman.GetChain().account,
            viewing_key.internal,
            diversifier_index,
            scan_keyman.GetChain().derivation_version};
        return true;
    };

    auto scan_branch_viewing_key = [&](PrivateOrchardScanViewingKey& viewing_key) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        for (size_t action_index = 0; action_index < bundle.effects.actions.size(); ++action_index) {
            if (matched_actions[action_index]) continue;

            PrivateOrchardDecryptedNote decrypted;
            ++decrypt_attempts;
            const auto decrypt_result = DecryptPrivateOrchardOutputWithFullViewingKey(
                Span<const unsigned char>{viewing_key.full_viewing_key.data(), viewing_key.full_viewing_key.size()},
                viewing_key.internal,
                bundle,
                action_index,
                decrypted,
                error);
            if (decrypt_result != PrivateOrchardBuildResult::OK || !decrypted.matched) {
                continue;
            }

            PrivateOrchardKeyPath path;
            if (!resolve_path_for_viewing_key(viewing_key, decrypted, path)) continue;
            record_decrypted_note(path, action_index, decrypted);
        }
    };

    auto scan_cached_viewing_keys = [&](size_t begin_pos) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        for (size_t key_pos = begin_pos; key_pos < m_private_rescan_viewing_keys.size(); ++key_pos) {
            if (!has_unmatched_action()) break;
            PrivateOrchardScanViewingKey viewing_key = m_private_rescan_viewing_keys[key_pos];
            scan_branch_viewing_key(viewing_key);
            memory_cleanse(viewing_key.full_viewing_key.data(), viewing_key.full_viewing_key.size());
        }
    };

    auto derive_branch_viewing_key = [&](bool internal, PrivateOrchardScanViewingKey& viewing_key) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        return MakePrivateScanViewingKey(scan_keyman.GetChain(), internal, viewing_key);
    };

    for (size_t action_index = 0; action_index < bundle.effects.actions.size(); ++action_index) {
        if (!matched_actions[action_index]) {
            update_existing_note_for_action(action_index);
        }
    }

    if (deep_scan && !m_private_rescan_viewing_keys.empty()) {
        scan_cached_viewing_keys(/*begin_pos=*/0);
    } else {
        for (const bool internal : {false, true}) {
            if (!has_unmatched_action()) break;
            PrivateOrchardScanViewingKey viewing_key;
            if (!derive_branch_viewing_key(internal, viewing_key)) continue;
            scan_branch_viewing_key(viewing_key);
            memory_cleanse(viewing_key.full_viewing_key.data(), viewing_key.full_viewing_key.size());
            if (!has_unmatched_action()) break;
        }
    }

    if (private_chain_dirty) {
        if (!PersistPrivateChain(batch, scan_keyman.GetChain())) {
            throw std::runtime_error("DB error updating private wallet lookahead chain");
        }
        LoadPrivateChain(scan_keyman.GetChain());
    }
    if (!batch.TxnCommit()) {
        throw std::runtime_error("DB error committing atomic private wallet bundle update");
    }

    LogPrint(BCLog::SCAN, "Private Wallet Scan: Actions:%u Attempts:%u Lookahead:%u Mode:%s Updated:%d TimeMs:%d\n",
        static_cast<unsigned>(bundle.effects.actions.size()),
        static_cast<unsigned>(decrypt_attempts),
        static_cast<unsigned>(lookahead),
        (deep_scan && !m_private_rescan_viewing_keys.empty()) ? "deep-cached" : (deep_scan ? "deep" : "live"),
        updated ? 1 : 0,
        Ticks<std::chrono::milliseconds>(SteadyClock::now() - scan_start));

    return updated;
}

CWallet::PrivateCompactProbeResult CWallet::SyncPrivateCompactEffects(const uint256& txid, const CPrivateCompactEffects& effects, const SyncTxState& state)
{
    const auto scan_start{SteadyClock::now()};
    std::vector<PrivateOrchardCompactMatch> matches;
    const PrivateCompactProbeResult probe_result{ProbePrivateCompactEffects(effects, matches)};
    if (probe_result == PrivateCompactProbeResult::SCAN_ERROR) {
        return PrivateCompactProbeResult::SCAN_ERROR;
    }

    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());
    if (!batch.TxnBegin()) {
        throw std::runtime_error("DB error starting atomic compact private wallet update");
    }
    bool updated{false};
    bool private_chain_dirty{false};
    const auto* confirmed = std::get_if<TxStateConfirmed>(&state);
    OrchardKeyMan scan_keyman{m_orchard_keyman.GetChain()};

    for (size_t action_index = 0; action_index < effects.actions.size(); ++action_index) {
        if (mapPrivateNoteNullifiers.find(effects.actions[action_index].nullifier) != mapPrivateNoteNullifiers.end()) {
            updated = true;
        }
        RecordPrivateSpentNullifier(batch, effects.actions[action_index].nullifier, txid, state, static_cast<uint32_t>(action_index));
    }

    auto find_commitment_index = [&](const uint256& cmx, uint64_t& commitment_index) {
        return HaveChain() && chain().getPrivateCommitmentIndex(cmx, commitment_index);
    };

    for (const auto& match : matches) {
        if (match.action_index >= effects.actions.size()) continue;
        const CPrivateCompactAction& action = effects.actions[match.action_index];
        if (match.note.cmx != action.cmx || !MoneyRange(match.note.value) || match.note.value <= 0) continue;

        CPrivateWalletNote note;
        note.cmx = match.note.cmx;
        note.nullifier = match.note.nullifier;
        note.txid = txid;
        if (confirmed) {
            note.block_hash = confirmed->confirmed_block_hash;
            note.block_height = confirmed->confirmed_block_height;
        }
        note.value = match.note.value;
        note.derivation_version = match.path.derivation_version == 0 ? NITO_PRIVATE_ORCHARD_DERIVATION_VERSION : match.path.derivation_version;
        note.account = match.path.account;
        note.internal = match.path.internal;
        note.diversifier_index = match.path.diversifier_index;
        note.action_index = static_cast<uint32_t>(match.action_index);
        note.decrypted = true;
        note.recipient_raw.assign(match.note.recipient_raw.begin(), match.note.recipient_raw.end());
        note.rho.assign(match.note.rho.begin(), match.note.rho.end());
        note.rseed.assign(match.note.rseed.begin(), match.note.rseed.end());

        if (confirmed) {
            uint64_t commitment_index{0};
            if (find_commitment_index(note.cmx, commitment_index)) {
                note.commitment_index = commitment_index;
            }
        }

        if (match.path.diversifier_index >= scan_keyman.NextIndex(match.path.internal)) {
            scan_keyman.MarkUsed(match.path.internal, match.path.diversifier_index);
            private_chain_dirty = true;
            const uint32_t next_index = scan_keyman.NextIndex(match.path.internal);
            const uint32_t scan_limit = next_index > std::numeric_limits<uint32_t>::max() - NITO_PRIVATE_ORCHARD_RECOVERY_GAP_LIMIT ?
                std::numeric_limits<uint32_t>::max() : next_index + NITO_PRIVATE_ORCHARD_RECOVERY_GAP_LIMIT;
            if (!ExtendPrivateRescanViewingKeys(scan_keyman.GetChain(), match.path.internal, scan_limit)) {
                WalletLogPrintf("Private Wallet Compact Scan: failed to extend an Orchard recovery gap (branch and index redacted)\n");
            }
        }

        auto existing = mapPrivateNotes.find(note.GetId());
        if (existing == mapPrivateNotes.end()) {
            if (!LoadPrivateNote(note) || !WritePrivateNoteRecord(batch, note)) {
                throw std::runtime_error("DB error writing compact private wallet note");
            }
        } else {
            CPrivateWalletNote& current = existing->second;
            if (current.txid != note.txid) current.m_is_change.reset();
            current.txid = note.txid;
            if (confirmed) {
                current.block_hash = note.block_hash;
                current.block_height = note.block_height;
            } else {
                current.block_hash.SetNull();
                current.block_height = -1;
                current.commitment_index = std::numeric_limits<uint64_t>::max();
            }
            if (note.HasWitnessPosition()) current.commitment_index = note.commitment_index;
            RemovePrivateNoteNullifierIndex(current);
            current.nullifier = note.nullifier;
            current.value = note.value;
            current.derivation_version = note.derivation_version;
            current.account = note.account;
            current.internal = note.internal;
            current.diversifier_index = note.diversifier_index;
            current.action_index = note.action_index;
            current.decrypted = note.decrypted;
            current.recipient_raw = note.recipient_raw;
            current.rho = note.rho;
            current.rseed = note.rseed;
            AddPrivateNoteNullifierIndex(current);
            if (!WritePrivateNoteRecord(batch, current)) {
                throw std::runtime_error("DB error updating compact private wallet note");
            }
        }
        updated = true;
    }

    if (private_chain_dirty) {
        if (!PersistPrivateChain(batch, scan_keyman.GetChain())) {
            throw std::runtime_error("DB error updating compact private wallet lookahead chain");
        }
        LoadPrivateChain(scan_keyman.GetChain());
    }

    if (updated) {
        RefreshPrivateSpentState(&batch);
    }
    if (!batch.TxnCommit()) {
        throw std::runtime_error("DB error committing atomic compact private wallet update");
    }
    LogPrint(BCLog::SCAN, "Private Wallet Compact Scan: Actions:%u Matches:%u Updated:%d TimeMs:%d\n",
        static_cast<unsigned>(effects.actions.size()),
        static_cast<unsigned>(matches.size()),
        updated ? 1 : 0,
        Ticks<std::chrono::milliseconds>(SteadyClock::now() - scan_start));
    return updated ? PrivateCompactProbeResult::MATCH : PrivateCompactProbeResult::NO_MATCH;
}

bool CWallet::SyncPrivateTransaction(const CTransaction& tx, const SyncTxState& state, bool deep_scan)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    if (!tx.HasPrivateBundle()) return false;
    return SyncPrivateBundle(tx.GetHash(), *tx.m_private_bundle, state, deep_scan);
}

std::set<uint256> CWallet::GetPrivateNullifierConflicts(const CTransaction& tx) const
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    std::set<uint256> conflicts;
    if (!tx.HasPrivateBundle()) return conflicts;

    std::set<uint256> nullifiers;
    for (const auto& action : tx.m_private_bundle->effects.actions) {
        if (!action.nullifier.IsNull()) {
            nullifiers.insert(action.nullifier);
        }
    }
    if (nullifiers.empty()) return conflicts;

    const uint256 txid{tx.GetHash()};
    for (const auto& [wallet_txid, wtx] : mapWallet) {
        if (wallet_txid == txid || !wtx.tx || !wtx.tx->HasPrivateBundle()) continue;
        for (const auto& action : wtx.tx->m_private_bundle->effects.actions) {
            if (!action.nullifier.IsNull() && nullifiers.count(action.nullifier) != 0) {
                conflicts.insert(wallet_txid);
                break;
            }
        }
    }
    return conflicts;
}

void CWallet::MarkPrivateNullifierConflicts(const CTransaction& tx, const TxStateConfirmed& confirmed)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    for (const uint256& conflict : GetPrivateNullifierConflicts(tx)) {
        WalletLogPrintf("Private transaction conflict detected at height %d (transaction, block and nullifier identifiers redacted)\n",
            confirmed.confirmed_block_height);
        MarkConflicted(confirmed.confirmed_block_hash, confirmed.confirmed_block_height, conflict);
    }
}

void CWallet::UnmarkPrivateNullifierConflicts(const CTransaction& tx, int disconnect_height)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    for (const uint256& conflict : GetPrivateNullifierConflicts(tx)) {
        auto it = mapWallet.find(conflict);
        if (it == mapWallet.end() || !it->second.isConflicted()) continue;
        const auto* conflicted = it->second.state<TxStateConflicted>();
        if (!conflicted || conflicted->conflicting_block_height < disconnect_height) continue;

        RecursiveUpdateTxState(conflict, [&](CWalletTx& wtx) {
            if (!wtx.isConflicted()) return TxUpdate::UNCHANGED;
            const auto* state = wtx.state<TxStateConflicted>();
            if (state && state->conflicting_block_height >= disconnect_height) {
                wtx.m_state = TxStateInactive{};
                return TxUpdate::CHANGED;
            }
            return TxUpdate::UNCHANGED;
        });
    }
    RefreshPrivateSpentState();
}

bool CWallet::RefreshPrivateCommitmentIndexes(WalletBatch* batch)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    if (!HaveChain()) return false;

    std::unique_ptr<WalletBatch> local_batch;
    WalletBatch* writer{batch};
    bool updated{false};
    for (auto& [cmx, note] : mapPrivateNotes) {
        if (!note.IsConfirmed() || note.HasWitnessPosition()) continue;

        uint64_t commitment_index{0};
        if (!chain().getPrivateCommitmentIndex(cmx, commitment_index)) continue;

        note.commitment_index = commitment_index;
        if (writer == nullptr) {
            local_batch = std::make_unique<WalletBatch>(GetDatabase());
            writer = local_batch.get();
        }
        if (!WritePrivateNoteRecord(*writer, note)) {
            throw std::runtime_error("DB error refreshing private note commitment index");
        }
        updated = true;
    }
    return updated;
}

void CWallet::RefreshPrivateSpentState(WalletBatch* batch)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);

    std::set<uint256> spent_nullifiers;
    for (const auto& [txid, wtx] : mapWallet) {
        if (!wtx.tx || !wtx.tx->HasPrivateBundle()) continue;
        if (!wtx.state<TxStateConfirmed>() && !wtx.state<TxStateInMempool>()) continue;
        for (const auto& action : wtx.tx->m_private_bundle->effects.actions) {
            spent_nullifiers.insert(action.nullifier);
        }
    }
    for (const auto& [nullifier, spent] : mapPrivateSpentNullifiers) {
        if (spent.IsConfirmed() && HaveChain()) {
            bool active{false};
            int height{-1};
            if (!chain().findBlock(spent.block_hash, FoundBlock().inActiveChain(active).height(height)) ||
                    !active || height != spent.block_height) {
                continue;
            }
        }
        spent_nullifiers.insert(nullifier);
    }

    auto write_spent_state = [&](WalletBatch& writer) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        for (auto& [cmx, note] : mapPrivateNotes) {
            const bool spent = note.HasNullifier() && spent_nullifiers.count(note.nullifier) != 0;
            if (note.spent == spent) continue;
            note.spent = spent;
            if (!WritePrivateNoteRecord(writer, note)) {
                throw std::runtime_error("DB error refreshing private note spent state");
            }
        }
    };

    if (batch != nullptr) {
        write_spent_state(*batch);
    } else {
        WalletBatch local_batch(GetDatabase());
        write_spent_state(local_batch);
    }
}

bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef& ptx, const SyncTxState& state, bool fUpdate,
                                       bool rescanning_old_block, bool scan_private_bundles,
                                       bool available_balance_internal)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    const CTransaction& tx = *ptx;
    {
        AssertLockHeld(cs_wallet);
        const bool confirmed_private_scan = std::get_if<TxStateConfirmed>(&state) != nullptr;
        const bool private_updated = scan_private_bundles && SyncPrivateTransaction(tx, state, rescanning_old_block || confirmed_private_scan);

        if (auto* conf = std::get_if<TxStateConfirmed>(&state)) {
            for (const CTxIn& txin : tx.vin) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) {
                    if (range.first->second != tx.GetHash()) {
                        if (tx.HasPrivateBundle()) {
                            WalletLogPrintf("Private transaction transparent-input conflict detected at height %d (identifiers redacted)\n", conf->confirmed_block_height);
                        } else {
                            WalletLogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), conf->confirmed_block_hash.ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        }
                        MarkConflicted(conf->confirmed_block_hash, conf->confirmed_block_height, range.first->second);
                    }
                    range.first++;
                }
            }
            if (tx.HasPrivateBundle()) {
                MarkPrivateNullifierConflicts(tx, *conf);
            }
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || private_updated || IsMine(tx) || IsFromMe(tx))
        {
            /* Check if any keys in the wallet keypool that were supposed to be unused
             * have appeared in a new transaction. If so, remove those keys from the keypool.
             * This can happen when restoring a wallet file that does not contain
             * the most recently created wallet transactions.
             */

            // loop though all outputs
            for (const CTxOut& txout: tx.vout) {
                for (const auto& spk_man : GetScriptPubKeyMans(txout.scriptPubKey)) {
                    for (auto &dest : spk_man->MarkUnusedAddresses(txout.scriptPubKey)) {
                        // If internal flag is not defined try to infer it from the ScriptPubKeyMan
                        if (!dest.internal.has_value()) {
                            dest.internal = IsInternalScriptPubKeyMan(spk_man);
                        }

                        // skip if can't determine whether it's a receiving address or not
                        if (!dest.internal.has_value()) continue;

                        // If this is a receiving address and it's not in the address book yet
                        // (e.g. it wasn't generated on this node or we're restoring from backup)
                        // add it to the address book for proper transaction accounting
                        if (!*dest.internal && !FindAddressBookEntry(dest.dest, /* allow_change= */ false)) {
                            SetAddressBook(dest.dest, "", AddressPurpose::RECEIVE);
                        }
                    }
                }
            }

            // Block disconnection override an abandoned tx as unconfirmed
            // which means user may have to call abandontransaction again
            TxState tx_state = std::visit([](auto&& s) -> TxState { return s; }, state);
            CWalletTx* wtx = AddToWallet(MakeTransactionRef(tx), tx_state, [&](CWalletTx& wtx, bool) {
                return SetAvailableBalanceMarkers(wtx, available_balance_internal, /*current=*/false);
            }, /*fFlushOnClose=*/false, rescanning_old_block);
            if (!wtx) {
                // Can only be nullptr if there was a db write error (missing db, read-only db or a db engine internal writing error).
                // As we only store arriving transaction in this process, and we don't want an inconsistent state, let's throw an error.
                throw std::runtime_error("DB error adding transaction to wallet, write failed");
            }
            if (scan_private_bundles && (tx.HasPrivateBundle() || private_updated)) {
                WalletBatch batch(GetDatabase());
                RefreshPrivateSpentState(&batch);
            }
            return true;
        }
    }
    return false;
}

bool CWallet::TransactionCanBeAbandoned(const uint256& hashTx) const
{
    LOCK(cs_wallet);
    const CWalletTx* wtx = GetWalletTx(hashTx);
    return wtx && !wtx->isAbandoned() && GetTxDepthInMainChain(*wtx) == 0 && !wtx->InMempool();
}

void CWallet::MarkInputsDirty(const CTransactionRef& tx)
{
    for (const CTxIn& txin : tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            it->second.MarkDirty();
        }
    }
}

bool CWallet::AbandonTransaction(const uint256& hashTx)
{
    LOCK(cs_wallet);

    // Can't mark abandoned if confirmed or in mempool
    auto it = mapWallet.find(hashTx);
    assert(it != mapWallet.end());
    const CWalletTx& origtx = it->second;
    if (GetTxDepthInMainChain(origtx) != 0 || origtx.InMempool()) {
        return false;
    }

    auto try_updating_state = [](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        // If the orig tx was not in block/mempool, none of its spends can be.
        assert(!wtx.isConfirmed());
        assert(!wtx.InMempool());
        // If already conflicted or abandoned, no need to set abandoned
        if (!wtx.isConflicted() && !wtx.isAbandoned()) {
            wtx.m_state = TxStateInactive{/*abandoned=*/true};
            return TxUpdate::NOTIFY_CHANGED;
        }
        return TxUpdate::UNCHANGED;
    };

    // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too.
    // States are not permanent, so these transactions can become unabandoned if they are re-added to the
    // mempool, or confirmed in a block, or conflicted.
    // Note: If the reorged coinbase is re-added to the main chain, the descendants that have not had their
    // states change will remain abandoned and will require manual broadcast if the user wants them.

    RecursiveUpdateTxState(hashTx, try_updating_state);
    RefreshPrivateSpentState();

    return true;
}

void CWallet::MarkConflicted(const uint256& hashBlock, int conflicting_height, const uint256& hashTx)
{
    LOCK(cs_wallet);

    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (m_last_block_processed_height < 0 || conflicting_height < 0) {
        return;
    }
    int conflictconfirms = (m_last_block_processed_height - conflicting_height + 1) * -1;
    if (conflictconfirms >= 0)
        return;

    auto try_updating_state = [&](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        if (conflictconfirms < GetTxDepthInMainChain(wtx)) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.m_state = TxStateConflicted{hashBlock, conflicting_height};
            return TxUpdate::CHANGED;
        }
        return TxUpdate::UNCHANGED;
    };

    // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too.
    RecursiveUpdateTxState(hashTx, try_updating_state);
    RefreshPrivateSpentState();

}

void CWallet::RecursiveUpdateTxState(const uint256& tx_hash, const TryUpdatingStateFn& try_updating_state) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
    // Do not flush the wallet here for performance reasons
    WalletBatch batch(GetDatabase(), false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(tx_hash);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;

        TxUpdate update_state = try_updating_state(wtx);
        if (update_state != TxUpdate::UNCHANGED) {
            wtx.MarkDirty();
            batch.WriteTx(wtx);
            // Iterate over all its outputs, and update those tx states as well (if applicable)
            for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(COutPoint(Txid::FromUint256(now), i));
                for (TxSpends::const_iterator iter = range.first; iter != range.second; ++iter) {
                    if (!done.count(iter->second)) {
                        todo.insert(iter->second);
                    }
                }
            }

            if (update_state == TxUpdate::NOTIFY_CHANGED) {
                NotifyTransactionChanged(wtx.GetHash(), CT_UPDATED);
            }

            // If a transaction changes its tx state, that usually changes the balance
            // available of the outputs it spends. So force those to be recomputed
            MarkInputsDirty(wtx.tx);
        }
    }
}

void CWallet::SyncTransaction(const CTransactionRef& ptx, const SyncTxState& state, bool update_tx,
                              bool rescanning_old_block, bool scan_private_bundles,
                              bool available_balance_internal)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    if (!AddToWalletIfInvolvingMe(ptx, state, update_tx, rescanning_old_block, scan_private_bundles, available_balance_internal))
        return; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    MarkInputsDirty(ptx);

    if (available_balance_internal) {
        WalletBatch batch(GetDatabase());
        auto current_it = mapWallet.find(ptx->GetHash());
        if (current_it != mapWallet.end()) {
            CWalletTx& current_wtx = current_it->second;
            current_wtx.MarkDirty();
            const CAmount available_credit{
                CachedTxGetAvailableCredit(*this, current_wtx, ISMINE_SPENDABLE | ISMINE_WATCH_ONLY)};
            const bool should_hide{available_credit <= 0};
            if (SetAvailableBalanceMarkers(current_wtx, should_hide, !should_hide)) {
                if (!batch.WriteTx(current_wtx)) {
                    throw std::runtime_error("DB error updating recovery wallet transaction visibility");
                }
                NotifyTransactionChanged(current_wtx.GetHash(), CT_UPDATED);
            }
        }

        for (const CTxIn& txin : ptx->vin) {
            auto it = mapWallet.find(txin.prevout.hash);
            if (it == mapWallet.end()) continue;

            CWalletTx& previous_wtx = it->second;
            previous_wtx.MarkDirty();
            if (CachedTxGetAvailableCredit(*this, previous_wtx, ISMINE_SPENDABLE | ISMINE_WATCH_ONLY) > 0) continue;
            if (!SetAvailableBalanceMarkers(previous_wtx, /*internal=*/true, /*current=*/false)) continue;

            if (!batch.WriteTx(previous_wtx)) {
                throw std::runtime_error("DB error updating recovery wallet transaction visibility");
            }
            NotifyTransactionChanged(previous_wtx.GetHash(), CT_UPDATED);
        }
    }
}

void CWallet::transactionAddedToMempool(const CTransactionRef& tx) {
    LOCK(cs_wallet);
    const bool scan_private_bundles{CanViewPrivateData()};
    SyncTransaction(tx, TxStateInMempool{}, /*update_tx=*/true, /*rescanning_old_block=*/false,
                    /*scan_private_bundles=*/scan_private_bundles);

    auto it = mapWallet.find(tx->GetHash());
    if (it != mapWallet.end()) {
        RefreshMempoolStatus(it->second, chain());
        if (tx->HasPrivateBundle() && scan_private_bundles) {
            RefreshPrivateSpentState();
        }
    }
}

void CWallet::transactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason) {
    LOCK(cs_wallet);
    auto it = mapWallet.find(tx->GetHash());
    if (it != mapWallet.end()) {
        RefreshMempoolStatus(it->second, chain());
        if (tx->HasPrivateBundle()) {
            RefreshPrivateSpentState();
        }
    }
    // Handle transactions that were removed from the mempool because they
    // conflict with transactions in a newly connected block.
    if (reason == MemPoolRemovalReason::CONFLICT) {
        // Trigger external -walletnotify notifications for these transactions.
        // Set Status::UNCONFIRMED instead of Status::CONFLICTED for a few reasons:
        //
        // 1. The transactionRemovedFromMempool callback does not currently
        //    provide the conflicting block's hash and height, and for backwards
        //    compatibility reasons it may not be not safe to store conflicted
        //    wallet transactions with a null block hash. See
        //    https://github.com/bitcoin/bitcoin/pull/18600#discussion_r420195993.
        // 2. For most of these transactions, the wallet's internal conflict
        //    detection in the blockConnected handler will subsequently call
        //    MarkConflicted and update them with CONFLICTED status anyway. This
        //    applies to any wallet transaction that has inputs spent in the
        //    block, or that has ancestors in the wallet with inputs spent by
        //    the block.
        // 3. Longstanding behavior since the sync implementation in
        //    https://github.com/bitcoin/bitcoin/pull/9371 and the prior sync
        //    implementation before that was to mark these transactions
        //    unconfirmed rather than conflicted.
        //
        // Nothing described above should be seen as an unchangeable requirement
        // when improving this code in the future. The wallet's heuristics for
        // distinguishing between conflicted and unconfirmed transactions are
        // imperfect, and could be improved in general, see
        // https://github.com/nito-core/nito-devwiki/wiki/Wallet-Transaction-Conflict-Tracking
        SyncTransaction(tx, TxStateInactive{});
    }
}

void CWallet::blockConnected(ChainstateRole role, const interfaces::BlockInfo& block)
{
    if (role == ChainstateRole::BACKGROUND) {
        return;
    }
    assert(block.data);
    WAIT_LOCK(cs_wallet, lock);

    m_last_block_processed_height = block.height;
    m_last_block_processed = block.hash;

    const bool contains_private_bundle{std::any_of(block.data->vtx.begin(), block.data->vtx.end(),
        [](const CTransactionRef& tx) { return tx && tx->HasPrivateBundle(); })};
    CPrivateWalletChain private_chain{m_orchard_keyman.GetChain()};
    const bool can_view_private_data{CanViewPrivateData()};
    if (contains_private_bundle && !can_view_private_data && !private_chain.hd_seed_id.IsNull()) {
        private_chain.private_locked_live_scan.Mark(block.height, block.hash, block.height, block.hash);
        private_chain.Normalize();
        WalletBatch batch(GetDatabase());
        if (!PersistPrivateChain(batch, private_chain)) {
            throw std::runtime_error("DB error recording pending private wallet catch-up target");
        }
        LoadPrivateChain(private_chain);
        WalletLogPrintf("Private wallet live catch-up deferred at height %d while encrypted keys are locked (generation %u; block identifier redacted)\n",
                        block.height,
                        static_cast<unsigned>(private_chain.private_locked_live_scan.generation));
    }

    // No need to scan block if it was created before the wallet birthday.
    // Uses chain max time and twice the grace period to adjust time for block time variability.
    if (block.chain_time_max < m_birth_time.load() - (TIMESTAMP_WINDOW * 2)) return;

    // Scan block
    const bool available_balance_catchup{
        m_seed_history_state.m_mode == SeedHistoryMode::AVAILABLE_BALANCE && chain().isInitialBlockDownload()};
    for (size_t index = 0; index < block.data->vtx.size(); index++) {
        SyncTransaction(block.data->vtx[index],
                        TxStateConfirmed{block.hash, block.height, static_cast<int>(index)},
                        /*update_tx=*/true,
                        /*rescanning_old_block=*/false,
                        /*scan_private_bundles=*/can_view_private_data,
                        /*available_balance_internal=*/available_balance_catchup);
        transactionRemovedFromMempool(block.data->vtx[index], MemPoolRemovalReason::BLOCK);
    }
    lock.unlock();
    std::vector<uint256> transaction_ids;
    for (const auto& tx : block.data->vtx) {
        if (!tx->IsCoinBase() && !tx->HasPrivateBundle()) transaction_ids.push_back(tx->GetHash());
    }
    if (!transaction_ids.empty()) RefreshInputAddresses(transaction_ids);
}

void CWallet::blockDisconnected(const interfaces::BlockInfo& block)
{
    assert(block.data);
    LOCK(cs_wallet);

    // At block disconnection, this will change an abandoned transaction to
    // be unconfirmed, whether or not the transaction is added back to the mempool.
    // User may have to call abandontransaction again. It may be addressed in the
    // future with a stickier abandoned state or even removing abandontransaction call.
    m_last_block_processed_height = block.height - 1;
    m_last_block_processed = *Assert(block.prev_hash);

    int disconnect_height = block.height;

    for (const CTransactionRef& ptx : Assert(block.data)->vtx) {
        SyncTransaction(ptx, TxStateInactive{});

        for (const CTxIn& tx_in : ptx->vin) {
            // No other wallet transactions conflicted with this transaction
            if (mapTxSpends.count(tx_in.prevout) < 1) continue;

            std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(tx_in.prevout);

            // For all of the spends that conflict with this transaction
            for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it) {
                CWalletTx& wtx = mapWallet.find(_it->second)->second;

                if (!wtx.isConflicted()) continue;

                auto try_updating_state = [&](CWalletTx& tx) {
                    if (!tx.isConflicted()) return TxUpdate::UNCHANGED;
                    if (tx.state<TxStateConflicted>()->conflicting_block_height >= disconnect_height) {
                        tx.m_state = TxStateInactive{};
                        return TxUpdate::CHANGED;
                    }
                    return TxUpdate::UNCHANGED;
                };

                RecursiveUpdateTxState(wtx.tx->GetHash(), try_updating_state);
            }
        }
        if (ptx->HasPrivateBundle()) {
            UnmarkPrivateNullifierConflicts(*ptx, disconnect_height);
        }
    }
}

void CWallet::updatedBlockTip()
{
    m_best_block_time = GetTime();
}

void CWallet::BlockUntilSyncedToCurrentChain() const {
    AssertLockNotHeld(cs_wallet);
    // Skip the queue-draining stuff if we know we're caught up with
    // chain().Tip(), otherwise put a callback in the validation interface queue and wait
    // for the queue to drain enough to execute it (indicating we are caught up
    // at least with the time we entered this function).
    uint256 last_block_hash = WITH_LOCK(cs_wallet, return m_last_block_processed);
    chain().waitForNotificationsIfTipChanged(last_block_hash);
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" (according to the filter) input.
CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        const auto mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
                    return prev.tx->vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxOut& txout) const
{
    AssertLockHeld(cs_wallet);
    return IsMine(txout.scriptPubKey);
}

isminetype CWallet::IsMine(const CTxDestination& dest) const
{
    AssertLockHeld(cs_wallet);
    return IsMine(GetScriptForDestination(dest));
}

isminetype CWallet::IsMine(const CScript& script) const
{
    AssertLockHeld(cs_wallet);

    // Search the cache so that IsMine is called only on the relevant SPKMs instead of on everything in m_spk_managers
    const auto& it = m_cached_spks.find(script);
    if (it != m_cached_spks.end()) {
        isminetype res = ISMINE_NO;
        for (const auto& spkm : it->second) {
            res = std::max(res, spkm->IsMine(script));
        }
        Assume(res == ISMINE_SPENDABLE);
        return res;
    }

    // Legacy wallet
    if (IsLegacy()) return GetLegacyScriptPubKeyMan()->IsMine(script);

    return ISMINE_NO;
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    AssertLockHeld(cs_wallet);
    for (const CTxOut& txout : tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

isminetype CWallet::IsMine(const COutPoint& outpoint) const
{
    AssertLockHeld(cs_wallet);
    auto wtx = GetWalletTx(outpoint.hash);
    if (!wtx) {
        return ISMINE_NO;
    }
    if (outpoint.n >= wtx->tx->vout.size()) {
        return ISMINE_NO;
    }
    return IsMine(wtx->tx->vout[outpoint.n]);
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    for (const CTxIn& txin : tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nDebit;
}

bool CWallet::IsHDEnabled() const
{
    // All Active ScriptPubKeyMans must be HD for this to be true
    bool result = false;
    for (const auto& spk_man : GetActiveScriptPubKeyMans()) {
        if (!spk_man->IsHDEnabled()) return false;
        result = true;
    }
    return result;
}

bool CWallet::CanGetAddresses(bool internal) const
{
    LOCK(cs_wallet);
    if (m_spk_managers.empty()) return false;
    for (OutputType t : OUTPUT_TYPES) {
        auto spk_man = GetScriptPubKeyMan(t, internal);
        if (spk_man && spk_man->CanGetAddresses(internal)) {
            return true;
        }
    }
    return false;
}

void CWallet::SetWalletFlag(uint64_t flags)
{
    WalletBatch batch(GetDatabase());
    SetWalletFlagWithDB(batch, flags);
}

void CWallet::SetWalletFlagWithDB(WalletBatch& batch, uint64_t flags)
{
    LOCK(cs_wallet);
    const uint64_t old_flags{m_wallet_flags.load()};
    m_wallet_flags = old_flags | flags;
    if (!batch.WriteWalletFlags(m_wallet_flags)) {
        m_wallet_flags = old_flags;
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
    }
}

void CWallet::UnsetWalletFlag(uint64_t flag)
{
    WalletBatch batch(GetDatabase());
    UnsetWalletFlagWithDB(batch, flag);
}

void CWallet::UnsetWalletFlagWithDB(WalletBatch& batch, uint64_t flag)
{
    LOCK(cs_wallet);
    m_wallet_flags &= ~flag;
    if (!batch.WriteWalletFlags(m_wallet_flags))
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetBlankWalletFlag(WalletBatch& batch)
{
    UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET);
}

bool CWallet::IsWalletFlagSet(uint64_t flag) const
{
    return (m_wallet_flags & flag);
}

bool CWallet::LoadWalletFlags(uint64_t flags)
{
    LOCK(cs_wallet);
    if (((flags & KNOWN_WALLET_FLAGS) >> 32) ^ (flags >> 32)) {
        // contains unknown non-tolerable wallet flags
        return false;
    }
    m_wallet_flags = flags;

    return true;
}

void CWallet::InitWalletFlags(uint64_t flags)
{
    LOCK(cs_wallet);

    // We should never be writing unknown non-tolerable wallet flags
    assert(((flags & KNOWN_WALLET_FLAGS) >> 32) == (flags >> 32));
    // This should only be used once, when creating a new wallet - so current flags are expected to be blank
    assert(m_wallet_flags == 0);

    if (!WalletBatch(GetDatabase()).WriteWalletFlags(flags)) {
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
    }

    if (!LoadWalletFlags(flags)) assert(false);
}

bool CWallet::ImportScripts(const std::set<CScript> scripts, int64_t timestamp)
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return false;
    }
    LOCK(spk_man->cs_KeyStore);
    return spk_man->ImportScripts(scripts, timestamp);
}

bool CWallet::ImportPrivKeys(const std::map<CKeyID, CKey>& privkey_map, const int64_t timestamp)
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return false;
    }
    LOCK(spk_man->cs_KeyStore);
    return spk_man->ImportPrivKeys(privkey_map, timestamp);
}

bool CWallet::ImportPubKeys(const std::vector<CKeyID>& ordered_pubkeys, const std::map<CKeyID, CPubKey>& pubkey_map, const std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>>& key_origins, const bool add_keypool, const bool internal, const int64_t timestamp)
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return false;
    }
    LOCK(spk_man->cs_KeyStore);
    return spk_man->ImportPubKeys(ordered_pubkeys, pubkey_map, key_origins, add_keypool, internal, timestamp);
}

bool CWallet::ImportScriptPubKeys(const std::string& label, const std::set<CScript>& script_pub_keys, const bool have_solving_data, const bool apply_label, const int64_t timestamp)
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return false;
    }
    LOCK(spk_man->cs_KeyStore);
    if (!spk_man->ImportScriptPubKeys(script_pub_keys, have_solving_data, timestamp)) {
        return false;
    }
    if (apply_label) {
        WalletBatch batch(GetDatabase());
        for (const CScript& script : script_pub_keys) {
            CTxDestination dest;
            ExtractDestination(script, dest);
            if (IsValidDestination(dest)) {
                SetAddressBookWithDB(batch, dest, label, AddressPurpose::RECEIVE);
            }
        }
    }
    return true;
}

void CWallet::MaybeUpdateBirthTime(int64_t time)
{
    int64_t birthtime = m_birth_time.load();
    if (time < birthtime) {
        m_birth_time = time;
    }
}

/**
 * Scan active chain for relevant transactions after importing keys. This should
 * be called whenever new keys are added to the wallet, with the oldest key
 * creation time.
 *
 * @return Earliest timestamp that could be successfully scanned from. Timestamp
 * returned will be higher than startTime if relevant blocks could not be read.
 */
int64_t CWallet::RescanFromTime(int64_t startTime, const WalletRescanReserver& reserver, bool update, bool require_filter_index, std::optional<int> max_height, bool require_private_index)
{
    // Find starting block. May be null if nCreateTime is greater than the
    // highest blockchain timestamp, in which case there is nothing that needs
    // to be scanned.
    int start_height = 0;
    uint256 start_block;
    bool start = chain().findFirstBlockWithTimeAndHeight(startTime - TIMESTAMP_WINDOW, 0, FoundBlock().hash(start_block).height(start_height));
    WalletLogPrintf("%s: Rescanning last %i blocks\n", __func__, start ? WITH_LOCK(cs_wallet, return GetLastBlockHeight()) - start_height + 1 : 0);

    if (start) {
        // TODO: this should take into account failure by ScanResult::USER_ABORT
        ScanResult result = ScanForWalletTransactions(start_block, start_height, max_height, reserver, /*fUpdate=*/update, /*save_progress=*/false, require_filter_index, require_private_index);
        if (result.status == ScanResult::FAILURE) {
            int64_t time_max;
            CHECK_NONFATAL(chain().findBlock(result.last_failed_block, FoundBlock().maxTime(time_max)));
            return time_max + TIMESTAMP_WINDOW + 1;
        }
    }
    return startTime;
}

CWallet::ScanResult CWallet::ScanCurrentWalletUtxos(bool update, std::optional<int> max_height, bool scan_private_bundles, CWallet::ScanProgressFn progress_fn)
{
    ScanResult result;
    auto report_scan_progress = [&](int value) {
        if (progress_fn) progress_fn(std::clamp(value, 0, 100));
    };
    struct ConfirmedWalletTx {
        CTransactionRef tx;
        uint256 block_hash;
        int height;
        int pos;
    };

    std::set<CScript> script_pub_keys;
    {
        LOCK(cs_wallet);
        for (ScriptPubKeyMan* spkm : GetAllScriptPubKeyMans()) {
            const auto scripts = spkm->GetScriptPubKeys();
            script_pub_keys.insert(scripts.begin(), scripts.end());
        }
    }

    if (script_pub_keys.empty()) {
        report_scan_progress(100);
        return result;
    }

    WalletLogPrintf("Scanning current UTXO set for %u wallet scripts\n", static_cast<unsigned>(script_pub_keys.size()));
    const auto start_time{SteadyClock::now()};
    report_scan_progress(5);

    std::map<COutPoint, Coin> coins;
    if (!chain().findCoinsByScriptPubKeys(script_pub_keys, coins)) {
        result.status = ScanResult::FAILURE;
        return result;
    }
    report_scan_progress(35);

    std::map<int, std::set<uint256>> txids_by_height;
    std::set<COutPoint> current_outpoints;
    for (const auto& [outpoint, coin] : coins) {
        if (coin.IsSpent()) continue;
        if (coin.nHeight < 0) continue;
        if (max_height && coin.nHeight > *max_height) continue;
        txids_by_height[coin.nHeight].insert(outpoint.hash);
        current_outpoints.insert(outpoint);
    }

    std::optional<int> reconciliation_start_height;
    std::set<COutPoint> spent_sibling_outpoints;
    std::vector<ConfirmedWalletTx> funding_txs;
    const size_t funding_height_count{txids_by_height.size()};
    size_t funding_height_index{0};
    for (const auto& [height, txids] : txids_by_height) {
        if (chain().shutdownRequested()) {
            result.status = ScanResult::USER_ABORT;
            break;
        }

        const uint256 block_hash{chain().getBlockHash(height)};
        CBlock block;
        bool block_still_active{false};
        chain().findBlock(block_hash, FoundBlock().inActiveChain(block_still_active).data(block));
        if (!block_still_active || block.IsNull()) {
            result.last_failed_block = block_hash;
            result.status = ScanResult::FAILURE;
            break;
        }

        LOCK(cs_wallet);
        for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
            const CTransactionRef& tx_ref = block.vtx[posInBlock];
            if (tx_ref && txids.count(tx_ref->GetHash())) {
                funding_txs.push_back({tx_ref, block_hash, height, static_cast<int>(posInBlock)});
                const Txid txid{tx_ref->GetHash()};
                for (uint32_t output_index{0}; output_index < tx_ref->vout.size(); ++output_index) {
                    const COutPoint outpoint{txid, output_index};
                    if (current_outpoints.count(outpoint)) continue;
                    if (!(IsMine(tx_ref->vout[output_index]) & ISMINE_ALL)) continue;
                    reconciliation_start_height = reconciliation_start_height ? std::min(*reconciliation_start_height, height) : height;
                    spent_sibling_outpoints.insert(outpoint);
                }
            }
        }
        result.last_scanned_block = block_hash;
        result.last_scanned_height = height;
        ++funding_height_index;
        if (funding_height_count > 0) {
            report_scan_progress(35 + static_cast<int>((funding_height_index * 20) / funding_height_count));
        }
    }

    const std::optional<int> tip_height{max_height ? max_height : chain().getHeight()};
    std::vector<ConfirmedWalletTx> spend_txs;
    auto collect_spends_from_block = [&](const uint256& block_hash, int height) {
        CBlock block;
        bool block_still_active{false};
        chain().findBlock(block_hash, FoundBlock().inActiveChain(block_still_active).data(block));
        if (!block_still_active || block.IsNull()) {
            result.last_failed_block = block_hash;
            result.status = ScanResult::FAILURE;
            return false;
        }

        for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
            std::vector<COutPoint> matched_spends;
            for (const CTxIn& txin : block.vtx[posInBlock]->vin) {
                if (spent_sibling_outpoints.count(txin.prevout)) {
                    matched_spends.push_back(txin.prevout);
                }
            }
            if (matched_spends.empty()) continue;

            spend_txs.push_back({block.vtx[posInBlock], block_hash, height, static_cast<int>(posInBlock)});
            for (const COutPoint& outpoint : matched_spends) {
                spent_sibling_outpoints.erase(outpoint);
            }
        }

        result.last_scanned_block = block_hash;
        result.last_scanned_height = height;
        return true;
    };
    auto collect_spends_by_direct_block_scan = [&](int start_height, int stop_height) {
        WalletLogPrintf("Current UTXO-set scan is reconciling spent sibling wallet outputs by direct block scan from height %d to %d\n",
                        start_height, stop_height);
        const int total_heights{std::max(1, stop_height - start_height + 1)};
        for (int height = start_height; height <= stop_height && !spent_sibling_outpoints.empty(); ++height) {
            if (chain().shutdownRequested()) {
                result.status = ScanResult::USER_ABORT;
                return;
            }
            const uint256 block_hash{chain().getBlockHash(height)};
            if (!collect_spends_from_block(block_hash, height)) return;
            report_scan_progress(55 + static_cast<int>(((height - start_height + 1) * 30) / total_heights));
        }
    };
    if (result.status == ScanResult::SUCCESS && reconciliation_start_height && tip_height && *reconciliation_start_height <= *tip_height) {
        if (IsLegacy() || !chain().hasBlockFilterIndex(BlockFilterType::BASIC)) {
            collect_spends_by_direct_block_scan(*reconciliation_start_height, *tip_height);
        } else {
            WalletLogPrintf("Current UTXO-set scan found %u spent sibling wallet outputs; reconciling their spends from height %d with compact filters\n",
                            static_cast<unsigned>(spent_sibling_outpoints.size()), *reconciliation_start_height);
            FastWalletRescanFilter fast_rescan_filter{*this};
            static constexpr int FILTER_RANGE_CHUNK{10000};
            int next_height{*reconciliation_start_height};
            while (next_height <= *tip_height && !spent_sibling_outpoints.empty() && !chain().shutdownRequested()) {
                const int chunk_stop{std::min(*tip_height, next_height + FILTER_RANGE_CHUNK - 1)};
                fast_rescan_filter.UpdateIfNeeded();
                const auto matches{fast_rescan_filter.MatchBlockRange(next_height, chunk_stop)};
                if (!matches) {
                    WalletLogPrintf("Current UTXO-set scan could not read compact filters at height %d; falling back to direct block scan for exact spent-output reconciliation\n",
                                    next_height);
                    collect_spends_by_direct_block_scan(next_height, *tip_height);
                    break;
                }

                bool restart_chunk{false};
                for (const auto& match : *matches) {
                    if (chain().shutdownRequested()) break;

                    if (!collect_spends_from_block(match.hash, match.height)) break;

                    result.last_scanned_block = match.hash;
                    result.last_scanned_height = match.height;

                    if (fast_rescan_filter.UpdateIfNeeded()) {
                        next_height = match.height + 1;
                        restart_chunk = true;
                        break;
                    }
                }
                if (result.status == ScanResult::FAILURE || chain().shutdownRequested()) break;
                if (restart_chunk) continue;

                result.last_scanned_block = chain().getBlockHash(chunk_stop);
                result.last_scanned_height = chunk_stop;
                const int total_heights{std::max(1, *tip_height - *reconciliation_start_height + 1)};
                report_scan_progress(55 + static_cast<int>(((chunk_stop - *reconciliation_start_height + 1) * 30) / total_heights));
                next_height = chunk_stop + 1;
            }
        }
        if (result.status == ScanResult::SUCCESS && !spent_sibling_outpoints.empty() && !chain().shutdownRequested()) {
            WalletLogPrintf("Current UTXO-set scan could not reconcile %u spent sibling wallet outputs by the current tip\n",
                            static_cast<unsigned>(spent_sibling_outpoints.size()));
            result.last_failed_block = chain().getBlockHash(*tip_height);
            result.status = ScanResult::FAILURE;
        }
        if (chain().shutdownRequested() && result.status == ScanResult::SUCCESS) {
            result.status = ScanResult::USER_ABORT;
        }
    }

    if (result.status == ScanResult::SUCCESS && tip_height) {
        report_scan_progress(90);
        if (update) {
            LOCK(cs_wallet);
            for (const auto& wallet_tx : funding_txs) {
                SyncTransaction(wallet_tx.tx,
                                TxStateConfirmed{wallet_tx.block_hash, wallet_tx.height, wallet_tx.pos},
                                /*update_tx=*/true,
                                /*rescanning_old_block=*/true,
                                scan_private_bundles,
                                /*available_balance_internal=*/false);
            }
            for (const auto& wallet_tx : spend_txs) {
                SyncTransaction(wallet_tx.tx,
                                TxStateConfirmed{wallet_tx.block_hash, wallet_tx.height, wallet_tx.pos},
                                /*update_tx=*/true,
                                /*rescanning_old_block=*/true,
                                /*scan_private_bundles=*/false,
                                /*available_balance_internal=*/true);
            }
        }
        const uint256 tip_hash{chain().getBlockHash(*tip_height)};
        if (CBlockLocator locator = chain().getActiveChainLocator(tip_hash); !locator.IsNull()) {
            WalletBatch batch(GetDatabase());
            batch.WriteBestBlock(locator);
        }
        {
            LOCK(cs_wallet);
            SetLastBlockProcessed(*tip_height, tip_hash);
        }
        result.last_scanned_block = tip_hash;
        result.last_scanned_height = *tip_height;
        report_scan_progress(100);
    }

    WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));

    WalletLogPrintf("Current UTXO-set scan found %u matching coins in %15dms\n",
                    static_cast<unsigned>(coins.size()),
                    Ticks<std::chrono::milliseconds>(SteadyClock::now() - start_time));
    return result;
}

CWallet::ScanResult CWallet::ScanPrivateNotesFromIndex(const uint256& start_block, int start_height, std::optional<int> max_height, const WalletRescanReserver& reserver, bool require_private_index, bool show_progress, bool hydrate_wallet_history, CWallet::ScanProgressFn progress_fn, const uint256& expected_stop_block)
{
    constexpr auto INTERVAL_TIME{60s};
    auto current_time{reserver.now()};
    assert(reserver.isReserved());

    ScanResult result;
    if (require_private_index && !chain().hasOrchardIndex()) {
        WalletLogPrintf("Private note recovery stopped: private wallet index is unavailable (block identifier redacted)\n");
        result.last_failed_block = start_block;
        result.status = ScanResult::FAILURE;
        return result;
    }

    const int private_activation_height{Params().GetConsensus().privateTxActivationHeight};
    const bool scan_private_bundles{
        private_activation_height >= 0 &&
        WITH_LOCK(cs_wallet, return !m_orchard_keyman.GetChain().hd_seed_id.IsNull())};
    if (!scan_private_bundles) return result;

    class PrivateRescanViewingKeysGuard
    {
    public:
        explicit PrivateRescanViewingKeysGuard(CWallet& wallet) : m_wallet{wallet} {}
        ~PrivateRescanViewingKeysGuard() { Clear(); }

        bool Prepare(bool deep_scan)
        {
            LOCK(m_wallet.cs_wallet);
            m_active = m_wallet.PreparePrivateRescanViewingKeys(deep_scan);
            return m_active;
        }

        void Clear()
        {
            if (!m_active) return;
            LOCK(m_wallet.cs_wallet);
            m_wallet.ClearPrivateRescanViewingKeys();
            m_active = false;
        }

    private:
        CWallet& m_wallet;
        bool m_active{false};
    };

    uint256 block_hash = start_block;
    int block_height = start_height;
    if (block_height < private_activation_height) {
        block_height = private_activation_height;
        block_hash = chain().getBlockHash(block_height);
    }

    const uint256 tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
    uint256 end_hash = tip_hash;
    if (max_height && !chain().findAncestorByHeight(tip_hash, *max_height, FoundBlock().hash(end_hash))) {
        WalletLogPrintf("Private note recovery could not bind target height %d to the wallet chain tip (block identifier redacted)\n", *max_height);
        result.last_failed_block = tip_hash;
        result.status = ScanResult::FAILURE;
        return result;
    }
    if (!expected_stop_block.IsNull() && end_hash != expected_stop_block) {
        WalletLogPrintf("Private note recovery target changed before scanning (block identifiers redacted)\n");
        result.last_failed_block = expected_stop_block;
        result.status = ScanResult::FAILURE;
        return result;
    }
    double progress_begin = chain().guessVerificationProgress(block_hash);
    double progress_end = chain().guessVerificationProgress(end_hash);
    double progress_current = progress_begin;
    const int progress_start_height{block_height};
    int last_reported_progress{-1};
    const std::string progress_title{strprintf("%s " + _("Restoring private balance...").translated, GetDisplayName())};
    auto report_scan_progress = [&](int progress_percent) {
        if (progress_fn) progress_fn(progress_percent);
        if (show_progress) ShowProgress(progress_title, progress_percent);
    };
    auto update_scan_progress = [&] {
        double scan_progress{m_scanning_progress.load()};
        if (max_height && *max_height >= progress_start_height) {
            const int total_blocks{std::max(1, *max_height - progress_start_height + 1)};
            const int scanned_blocks{std::clamp(block_height - progress_start_height, 0, total_blocks)};
            scan_progress = static_cast<double>(scanned_blocks) / static_cast<double>(total_blocks);
        } else if (progress_end - progress_begin > 0.0) {
            scan_progress = (progress_current - progress_begin) / (progress_end - progress_begin);
        }
        scan_progress = std::clamp(scan_progress, 0.0, 1.0);
        m_scanning_progress = scan_progress;
        if (progress_fn || show_progress) {
            const int progress_percent{std::max(1, std::min(99, static_cast<int>(scan_progress * 100)))};
            if (progress_percent != last_reported_progress) {
                report_scan_progress(progress_percent);
                last_reported_progress = progress_percent;
            }
        }
    };

    PrivateRescanViewingKeysGuard private_rescan_keys{*this};
    if (!private_rescan_keys.Prepare(/*deep_scan=*/true)) {
        WalletLogPrintf("Private note recovery could not prepare Orchard viewing keys\n");
        result.last_failed_block = block_hash;
        result.status = ScanResult::FAILURE;
        return result;
    }

    fAbortRescan = false;
    if (progress_fn || show_progress) {
        report_scan_progress(0);
    }

    WalletLogPrintf("Private note recovery started from height %d using private wallet index (block identifier redacted)\n", block_height);

    while (!fAbortRescan && !chain().shutdownRequested()) {
        update_scan_progress();

        if (reserver.now() >= current_time + INTERVAL_TIME) {
            current_time = reserver.now();
            WalletLogPrintf("Still recovering private notes. At block %d. Progress=%f\n", block_height, progress_current);
        }

        std::optional<std::vector<interfaces::OrchardIndexedTransaction>> indexed_private_txs = chain().getOrchardBlockTransactions(block_hash);
        if (!indexed_private_txs.has_value() && require_private_index) {
            WalletLogPrintf("Private note recovery stopped at block %d: private wallet index is not ready (block identifier redacted)\n", block_height);
            result.last_failed_block = block_hash;
            result.status = ScanResult::FAILURE;
            break;
        }

        bool block_still_active{false};
        bool next_block{false};
        uint256 next_block_hash;
        chain().findBlock(block_hash, FoundBlock().inActiveChain(block_still_active).nextBlock(FoundBlock().inActiveChain(next_block).hash(next_block_hash)));
        if (!block_still_active) {
            result.last_failed_block = block_hash;
            result.status = ScanResult::FAILURE;
            break;
        }

        if (indexed_private_txs.has_value()) {
            for (const auto& indexed_tx : *indexed_private_txs) {
                if (!hydrate_wallet_history) {
                    if (SyncPrivateCompactEffects(indexed_tx.txid, indexed_tx.effects, TxStateConfirmed{block_hash, block_height, indexed_tx.block_position}) == PrivateCompactProbeResult::SCAN_ERROR) {
                        WalletLogPrintf("Private note recovery stopped at block %d: Orchard compact scan failed\n", block_height);
                        result.last_failed_block = block_hash;
                        result.status = ScanResult::FAILURE;
                        break;
                    }
                    continue;
                }

                bool spends_wallet_private_note{false};
                {
                    LOCK(cs_wallet);
                    for (const auto& action : indexed_tx.effects.actions) {
                        if (mapPrivateNoteNullifiers.find(action.nullifier) != mapPrivateNoteNullifiers.end()) {
                            spends_wallet_private_note = true;
                            break;
                        }
                    }
                }

                std::vector<PrivateOrchardCompactMatch> compact_matches;
                if (!spends_wallet_private_note) {
                    const PrivateCompactProbeResult probe_result{ProbePrivateCompactEffects(indexed_tx.effects, compact_matches)};
                    if (probe_result == PrivateCompactProbeResult::SCAN_ERROR) {
                        result.last_failed_block = block_hash;
                        result.status = ScanResult::FAILURE;
                        break;
                    }
                    if (probe_result == PrivateCompactProbeResult::NO_MATCH) continue;
                }

                const CTransactionRef tx_ref{chain().getOrchardTransaction(block_hash, indexed_tx.block_position)};
                LOCK(cs_wallet);
                bool still_active{false};
                chain().findBlock(block_hash, FoundBlock().inActiveChain(still_active));
                if (!still_active || indexed_tx.block_position < 0) {
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                if (!tx_ref || tx_ref->GetHash() != indexed_tx.txid || !tx_ref->HasPrivateBundle() ||
                    tx_ref->m_private_bundle->GetEffectsHash() != indexed_tx.effects_hash) {
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                SyncTransaction(tx_ref, TxStateConfirmed{block_hash, block_height, indexed_tx.block_position}, /*update_tx=*/true, /*rescanning_old_block=*/true);
            }
            if (result.status == ScanResult::FAILURE) break;
        }

        result.last_scanned_block = block_hash;
        result.last_scanned_height = block_height;

        if (max_height && block_height >= *max_height) {
            break;
        }
        if (!next_block) {
            break;
        }
        block_hash = next_block_hash;
        ++block_height;
        progress_current = chain().guessVerificationProgress(block_hash);
    }

    private_rescan_keys.Clear();
    if (fAbortRescan || chain().shutdownRequested()) {
        result.status = ScanResult::USER_ABORT;
    }
    if (result.status == ScanResult::SUCCESS && max_height &&
        (!result.last_scanned_height || *result.last_scanned_height != *max_height || result.last_scanned_block != end_hash)) {
        WalletLogPrintf("Private note recovery did not reach its exact target %d (block identifier redacted)\n", *max_height);
        result.last_failed_block = end_hash;
        result.status = ScanResult::FAILURE;
    }
    bool target_still_active{false};
    if (result.status == ScanResult::SUCCESS) {
        chain().findBlock(end_hash, FoundBlock().inActiveChain(target_still_active));
        if (!target_still_active) {
            result.last_failed_block = end_hash;
            result.status = ScanResult::FAILURE;
        }
    }
    if ((progress_fn || show_progress) && result.status == ScanResult::SUCCESS) {
        report_scan_progress(100);
    }
    WalletLogPrintf("Private note recovery completed with status %d at height %d\n",
                    result.status, result.last_scanned_height.value_or(-1));
    return result;
}

util::Result<void> CWallet::CatchUpPrivateNotesAfterUnlock()
{
    if (!HaveChain()) return {};

    CPrivateScanObligation restore_obligation;
    CPrivateScanObligation locked_live_obligation;
    int stop_height{-1};
    uint256 stop_block;
    {
        LOCK(cs_wallet);
        if (IsLocked()) return util::Error{_("Wallet is locked.")};
        const CPrivateWalletChain& private_chain{m_orchard_keyman.GetChain()};
        restore_obligation = private_chain.private_restore_scan;
        locked_live_obligation = private_chain.private_locked_live_scan;
        stop_height = m_last_block_processed_height;
        stop_block = m_last_block_processed;
    }
    auto replay_mempool = [&] {
        WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));
    };
    if (!restore_obligation.IsPending() && !locked_live_obligation.IsPending()) {
        replay_mempool();
        return {};
    }

    const int private_activation_height{Params().GetConsensus().privateTxActivationHeight};
    if (private_activation_height < 0 || stop_height < 0 || stop_block.IsNull()) {
        return util::Error{_("The active chain target is unavailable; private wallet recovery remains pending.")};
    }
    if (!chain().hasOrchardIndex()) {
        return util::Error{_("The private wallet index is not available; private notes received while locked remain pending.")};
    }
    const std::optional<int> indexed_height{chain().getSyncedOrchardIndexHeight()};
    if (!indexed_height || *indexed_height < stop_height) {
        return util::Error{_("The private wallet index is still catching up; private notes received while locked remain pending.")};
    }

    WalletRescanReserver reserver(*this);
    if (!reserver.reserve(/*with_passphrase=*/true)) {
        return util::Error{_("Wallet is currently rescanning; private note catch-up remains pending.")};
    }

    auto bind_obligation_to_active_chain = [&](bool locked_live, CPrivateScanObligation& obligation) -> util::Result<void> {
        if (!obligation.IsPending()) return {};
        const int start_height{std::max(obligation.start_height, private_activation_height)};
        if (start_height > stop_height) return util::Error{_("The private wallet recovery range is invalid.")};
        const uint256 start_block{chain().getBlockHash(start_height)};
        if (start_block.IsNull()) return util::Error{_("The private wallet recovery start block is unavailable.")};

        LOCK(cs_wallet);
        CPrivateWalletChain private_chain{m_orchard_keyman.GetChain()};
        CPrivateScanObligation& current{locked_live ? private_chain.private_locked_live_scan : private_chain.private_restore_scan};
        if (!current.IsPending() || current.generation != obligation.generation) {
            return util::Error{_("Private wallet recovery changed while it was being prepared; the newer work remains pending.")};
        }
        current.start_height = start_height;
        current.start_block = start_block;
        current.target_height = stop_height;
        current.target_block = stop_block;
        ++current.generation;
        if (current.generation == 0) current.generation = 1;
        private_chain.Normalize();
        WalletBatch batch(GetDatabase());
        if (!PersistPrivateChain(batch, private_chain)) {
            return util::Error{_("Could not save the exact private wallet recovery target.")};
        }
        LoadPrivateChain(private_chain);
        obligation = current;
        return {};
    };

    if (auto bound = bind_obligation_to_active_chain(/*locked_live=*/false, restore_obligation); !bound) return bound;
    if (auto bound = bind_obligation_to_active_chain(/*locked_live=*/true, locked_live_obligation); !bound) return bound;

    auto scan_obligation = [&](const CPrivateScanObligation& obligation, bool hydrate_wallet_history) -> util::Result<void> {
        if (!obligation.IsPending()) return {};
        const ScanResult result{ScanPrivateNotesFromIndex(
            obligation.start_block,
            obligation.start_height,
            std::optional<int>{obligation.target_height},
            reserver,
            /*require_private_index=*/true,
            /*show_progress=*/false,
            hydrate_wallet_history,
            /*progress_fn=*/{},
            obligation.target_block)};
        if (result.status != ScanResult::SUCCESS ||
            !result.last_scanned_height || *result.last_scanned_height != obligation.target_height ||
            result.last_scanned_block != obligation.target_block) {
            return util::Error{_("Private wallet recovery did not complete on its persisted chain target.")};
        }
        return {};
    };

    if (auto scanned = scan_obligation(restore_obligation, /*hydrate_wallet_history=*/false); !scanned) return scanned;

    auto commit_completion = [&](bool locked_live, const CPrivateScanObligation& completed) -> util::Result<void> {
        if (!completed.IsPending()) return {};
        LOCK(cs_wallet);
        CPrivateWalletChain private_chain{m_orchard_keyman.GetChain()};
        CPrivateScanObligation& current{locked_live ? private_chain.private_locked_live_scan : private_chain.private_restore_scan};
        if (!current.IsPending() || current.generation != completed.generation ||
            current.target_height != completed.target_height || current.target_block != completed.target_block) {
            return util::Error{_("New private wallet work arrived during recovery; it remains pending.")};
        }
        current.Clear();
        private_chain.Normalize();

        SeedHistoryState updated_state{m_seed_history_state};
        bool update_seed_state{false};
        if (!locked_live && updated_state.m_mode == SeedHistoryMode::AVAILABLE_BALANCE) {
            updated_state.MarkFunds(/*orchard=*/true, SeedRecoveryStatus::COMPLETE, completed.target_height, completed.target_block);
            update_seed_state = true;
        } else if (locked_live && updated_state.m_mode == SeedHistoryMode::FULL_HISTORY) {
            updated_state.m_full_history_height = completed.target_height;
            updated_state.m_full_history_block = completed.target_block;
            updated_state.MarkHistory(/*orchard=*/false, SeedRecoveryStatus::COMPLETE, completed.target_height, completed.target_block);
            if (updated_state.m_orchard.m_explicit_history.m_status != SeedRecoveryStatus::NOT_APPLICABLE) {
                updated_state.MarkHistory(/*orchard=*/true, SeedRecoveryStatus::COMPLETE, completed.target_height, completed.target_block);
            }
            update_seed_state = true;
        }

        WalletBatch batch(GetDatabase());
        if (!batch.TxnBegin() || !PersistPrivateChain(batch, private_chain) ||
            (update_seed_state && !batch.WriteSeedHistoryState(updated_state)) || !batch.TxnCommit()) {
            batch.TxnAbort();
            return util::Error{_("Private notes were recovered, but the recovery checkpoint could not be saved atomically.")};
        }
        LoadPrivateChain(private_chain);
        if (update_seed_state) m_seed_history_state = updated_state;
        return {};
    };

    if (auto committed = commit_completion(/*locked_live=*/false, restore_obligation); !committed) return committed;
    if (auto scanned = scan_obligation(locked_live_obligation, /*hydrate_wallet_history=*/true); !scanned) return scanned;
    if (auto committed = commit_completion(/*locked_live=*/true, locked_live_obligation); !committed) return committed;

    replay_mempool();
    WalletLogPrintf("Private wallet obligations completed on exact target %d after unlock (block identifier redacted)\n", stop_height);
    return {};
}

util::Result<void> CWallet::RestoreSeedHistory(bool wait_for_indexes, bool show_progress, ScanProgressFn progress_fn)
{
    if (!HaveChain()) return util::Error{_("Cannot restore wallet history without chain access.")};

    {
        LOCK(cs_wallet);
        if (IsLocked()) return util::Error{_("Wallet is locked.")};
        if (m_seed_history_state.m_mode != SeedHistoryMode::AVAILABLE_BALANCE) return {};
    }

    BlockUntilSyncedToCurrentChain();

    WalletRescanReserver reserver(*this);
    if (!reserver.reserve(/*with_passphrase=*/true)) {
        return util::Error{_("Wallet is currently rescanning; automatic history recovery remains pending.")};
    }
    fAbortRescan = false;
    if (!TopUpSeedRestoreKeyPool()) {
        return util::Error{_("Could not prepare wallet address discovery for automatic history recovery.")};
    }

    int start_height{0};
    uint256 scanned_anchor;
    while (!chain().shutdownRequested() && !IsAbortingRescan()) {
        int stop_height{-1};
        uint256 stop_block;
        bool has_private_seed{false};
        {
            LOCK(cs_wallet);
            stop_height = m_last_block_processed_height;
            stop_block = m_last_block_processed;
            has_private_seed = !m_orchard_keyman.GetChain().hd_seed_id.IsNull();
        }
        if (stop_height < 0 || stop_block.IsNull()) {
            return util::Error{_("The active chain target is unavailable; automatic wallet history recovery remains pending.")};
        }
        if (start_height > 0 &&
            (stop_height < start_height - 1 || chain().getBlockHash(start_height - 1) != scanned_anchor)) {
            start_height = 0;
            scanned_anchor.SetNull();
        }

        if (stop_height > 0) {
            if (!chain().hasBlocks(stop_block, start_height, stop_height)) {
                return util::Error{PrunedWalletRecoveryError()};
            }
            if (!chain().hasTransparentHistoryIndex()) {
                return util::Error{_("The transparent history index is not available. Restart Nito Core with -transparenthistoryindex=1 to restore a recovery phrase.")};
            }
            const int private_activation_height{Params().GetConsensus().privateTxActivationHeight};
            if (has_private_seed && private_activation_height >= 0 && stop_height >= private_activation_height &&
                !chain().hasOrchardIndex()) {
                return util::Error{_("The private wallet index is not available. Restart Nito Core with -orchardindex=1 to restore a recovery phrase.")};
            }

            auto indexes_ready{CheckHistoryRescanIndexesReady(stop_height)};
            while (!indexes_ready) {
                if (!wait_for_indexes) return indexes_ready;
                if (chain().shutdownRequested() || IsAbortingRescan()) {
                    return util::Error{_("Automatic wallet history recovery was interrupted while waiting for wallet indexes.")};
                }

                if (progress_fn) {
                    int index_height{chain().getTransparentHistoryIndexHeight().value_or(0)};
                    if (has_private_seed && private_activation_height >= 0 && stop_height >= private_activation_height) {
                        index_height = std::min(index_height, chain().getOrchardIndexHeight().value_or(0));
                    }
                    const int progress_target{std::max(stop_height, 1)};
                    progress_fn(std::clamp((std::max(index_height, 0) * 10) / progress_target, 0, 10));
                }
                UninterruptibleSleep(100ms);
                indexes_ready = CheckHistoryRescanIndexesReady(stop_height);
            }
        }

        uint256 start_block;
        if (!chain().findAncestorByHeight(stop_block, start_height, FoundBlock().hash(start_block)) || start_block.IsNull()) {
            return util::Error{_("Could not find the automatic wallet history recovery start block.")};
        }

        SeedHistoryState pending_state;
        {
            LOCK(cs_wallet);
            pending_state = m_seed_history_state;
        }
        pending_state.MarkFunds(/*orchard=*/false, SeedRecoveryStatus::PENDING, stop_height, stop_block);
        pending_state.MarkHistory(/*orchard=*/false, SeedRecoveryStatus::PENDING, stop_height, stop_block);
        if (has_private_seed) {
            pending_state.MarkFunds(/*orchard=*/true, SeedRecoveryStatus::PENDING, stop_height, stop_block);
            pending_state.MarkHistory(/*orchard=*/true, SeedRecoveryStatus::PENDING, stop_height, stop_block);
        }
        if (!SetSeedHistoryState(pending_state)) {
            return util::Error{_("Could not save the pending automatic wallet history recovery target.")};
        }

        if (stop_height == 0) {
            LOCK(cs_wallet);
            if (m_last_block_processed_height == stop_height && m_last_block_processed == stop_block) {
                if (!SetSeedHistoryState(SeedHistoryState::FullHistory(stop_height, stop_block, has_private_seed))) {
                    return util::Error{_("Wallet history was restored, but its completion state could not be saved.")};
                }
                chain().requestMempoolTransactions(*this);
                if (progress_fn) progress_fn(100);
                return {};
            }
            continue;
        }

        ScanProgressFn mapped_progress;
        if (progress_fn) {
            mapped_progress = [&](int value) {
                progress_fn(10 + (std::clamp(value, 0, 100) * 90) / 100);
            };
        }
        const ScanResult scan_result{ScanWalletHistoryFromIndexes(
            start_block,
            start_height,
            stop_height,
            stop_block,
            reserver,
            /*fUpdate=*/true,
            show_progress,
            mapped_progress)};

        if (scan_result.status != ScanResult::SUCCESS ||
            !scan_result.last_scanned_height || *scan_result.last_scanned_height != stop_height ||
            scan_result.last_scanned_block != stop_block) {
            SeedHistoryState failed_state{pending_state};
            failed_state.MarkFunds(/*orchard=*/false, SeedRecoveryStatus::FAILED, stop_height, stop_block);
            failed_state.MarkHistory(/*orchard=*/false, SeedRecoveryStatus::FAILED, stop_height, stop_block);
            if (has_private_seed) {
                failed_state.MarkFunds(/*orchard=*/true, SeedRecoveryStatus::FAILED, stop_height, stop_block);
                failed_state.MarkHistory(/*orchard=*/true, SeedRecoveryStatus::FAILED, stop_height, stop_block);
            }
            if (!SetSeedHistoryState(failed_state)) {
                return util::Error{_("Automatic wallet history recovery failed and its failure state could not be saved.")};
            }
            if (scan_result.status == ScanResult::USER_ABORT) {
                return util::Error{_("Automatic wallet history recovery was aborted.")};
            }
            return util::Error{_("Automatic wallet history recovery failed on its persisted chain target.")};
        }

        {
            LOCK(cs_wallet);
            if (m_last_block_processed_height == stop_height && m_last_block_processed == stop_block) {
                if (!SetSeedHistoryState(SeedHistoryState::FullHistory(stop_height, stop_block, has_private_seed))) {
                    return util::Error{_("Wallet history was restored, but its completion state could not be saved.")};
                }
                chain().requestMempoolTransactions(*this);
                WalletLogPrintf("Automatic wallet history recovery completed through height %d (block identifier redacted)\n", stop_height);
                if (progress_fn) progress_fn(100);
                return {};
            }
        }

        // Blocks can continue arriving while recovery runs. Scan only the new
        // suffix, and do not publish a full-history checkpoint until the
        // wallet and the persisted target are identical under cs_wallet.
        scanned_anchor = stop_block;
        start_height = stop_height + 1;
    }

    return util::Error{_("Automatic wallet history recovery was interrupted.")};
}

util::Result<void> CWallet::CatchUpWalletAfterUnlock()
{
    if (auto private_catchup = CatchUpPrivateNotesAfterUnlock(); !private_catchup) {
        return private_catchup;
    }
    return RestoreSeedHistory(/*wait_for_indexes=*/false, /*show_progress=*/false);
}

bool CWallet::MarkPrivateScanPending(int start_height, int target_height, const uint256& target_block)
{
    if (start_height < 0 || target_height < start_height || target_block.IsNull()) return false;
    const uint256 start_block{chain().getBlockHash(start_height)};
    if (start_block.IsNull()) return false;
    LOCK(cs_wallet);
    CPrivateWalletChain private_chain{m_orchard_keyman.GetChain()};
    if (private_chain.hd_seed_id.IsNull()) return false;
    private_chain.private_restore_scan.Mark(start_height, start_block, target_height, target_block);
    private_chain.Normalize();
    SeedHistoryState updated_state{m_seed_history_state};
    if (updated_state.m_mode == SeedHistoryMode::AVAILABLE_BALANCE) {
        updated_state.MarkFunds(/*orchard=*/true, SeedRecoveryStatus::PENDING, target_height, target_block);
    }
    WalletBatch batch(GetDatabase());
    if (!batch.TxnBegin() || !PersistPrivateChain(batch, private_chain) ||
        (updated_state.m_mode == SeedHistoryMode::AVAILABLE_BALANCE && !batch.WriteSeedHistoryState(updated_state)) ||
        !batch.TxnCommit()) {
        batch.TxnAbort();
        return false;
    }
    LoadPrivateChain(private_chain);
    if (updated_state.m_mode == SeedHistoryMode::AVAILABLE_BALANCE) m_seed_history_state = updated_state;
    WalletLogPrintf("Private balance recovery marked pending from %d through %d (generation %u; block identifiers redacted)\n",
                    start_height,
                    target_height,
                    static_cast<unsigned>(private_chain.private_restore_scan.generation));
    return true;
}

bool CWallet::MarkPrivateLockedScanPending(int start_height, int target_height, const uint256& target_block)
{
    if (start_height < 0 || target_height < start_height || target_block.IsNull()) return false;
    uint256 start_block;
    if (!chain().findAncestorByHeight(target_block, start_height, FoundBlock().hash(start_block)) || start_block.IsNull()) return false;

    LOCK(cs_wallet);
    CPrivateWalletChain private_chain{m_orchard_keyman.GetChain()};
    if (private_chain.hd_seed_id.IsNull()) return false;
    private_chain.private_locked_live_scan.Mark(start_height, start_block, target_height, target_block);
    private_chain.Normalize();

    WalletBatch batch(GetDatabase());
    if (!batch.TxnBegin() || !PersistPrivateChain(batch, private_chain) || !batch.TxnCommit()) {
        batch.TxnAbort();
        return false;
    }
    LoadPrivateChain(private_chain);
    WalletLogPrintf("Private wallet live catch-up marked pending from %d through %d while encrypted keys are locked (generation %u; block identifiers redacted)\n",
                    start_height,
                    target_height,
                    static_cast<unsigned>(private_chain.private_locked_live_scan.generation));
    return true;
}

util::Result<void> CWallet::CheckHistoryRescanIndexesReady(int stop_height, std::optional<bool> require_private_index)
{
    if (stop_height < 0) return {};

    auto index_progress = [&](std::optional<int> height) {
        const int clamped_height{std::clamp(height.value_or(0), 0, stop_height)};
        const int progress_target{std::max(stop_height, 1)};
        const double progress{std::clamp(100.0 * static_cast<double>(clamped_height) / progress_target, 0.0, 100.0)};
        return std::tuple<int, double>{clamped_height, progress};
    };

    if (!chain().hasTransparentHistoryIndex()) {
        return util::Error{_("The transparent history index is not available. Restart Nito Core with -transparenthistoryindex=1 before wallet recovery can complete.")};
    }
    const std::optional<int> synced_history_height{chain().getSyncedTransparentHistoryIndexHeight()};
    if (!synced_history_height || *synced_history_height < stop_height) {
        const auto [index_height, progress]{index_progress(chain().getTransparentHistoryIndexHeight())};
        return util::Error{strprintf(_("The transparent history index is being prepared for wallet recovery. Progress: %.1f%% (%d/%d)."), progress, index_height, stop_height)};
    }

    const int private_activation_height{Params().GetConsensus().privateTxActivationHeight};
    const bool wallet_has_private_seed{WITH_LOCK(cs_wallet, return !m_orchard_keyman.GetChain().hd_seed_id.IsNull())};
    const bool needs_private_index{
        private_activation_height >= 0 &&
        stop_height >= private_activation_height &&
        require_private_index.value_or(wallet_has_private_seed)};
    if (needs_private_index) {
        if (!chain().hasOrchardIndex()) {
            return util::Error{_("The private wallet index is not available. Restart Nito Core with private wallet indexing enabled (-orchardindex=1) before wallet recovery can complete.")};
        }
        const std::optional<int> synced_orchard_height{chain().getSyncedOrchardIndexHeight()};
        if (!synced_orchard_height || *synced_orchard_height < stop_height) {
            const auto [index_height, progress]{index_progress(chain().getOrchardIndexHeight())};
            return util::Error{strprintf(_("The private wallet index is being prepared for wallet recovery. Progress: %.1f%% (%d/%d)."), progress, index_height, stop_height)};
        }
    }

    return {};
}

CWallet::ScanResult CWallet::ScanTransparentHistoryFromIndex(const uint256& start_block, int start_height, int stop_height, const uint256& stop_block, const WalletRescanReserver& reserver, bool fUpdate, bool show_progress, CWallet::ScanProgressFn progress_fn)
{
    assert(reserver.isReserved());

    ScanResult result;
    bool stop_block_active{false};
    chain().findBlock(stop_block, FoundBlock().inActiveChain(stop_block_active));
    if (stop_height < 0 || stop_block.IsNull() || !stop_block_active || chain().getBlockHash(stop_height) != stop_block) {
        result.last_failed_block = start_block;
        result.status = ScanResult::FAILURE;
        return result;
    }
    if (start_height > stop_height) {
        result.last_scanned_block = stop_block;
        result.last_scanned_height = stop_height;
        return result;
    }

    auto report_scan_progress = [&](int progress) {
        const int clamped_progress{std::max(0, std::min(100, progress))};
        if (progress_fn) progress_fn(clamped_progress);
        if (show_progress) {
            ShowProgress(strprintf("%s " + _("Restoring complete wallet history...").translated, GetDisplayName()), clamped_progress);
        }
    };

    if (!chain().hasTransparentHistoryIndex()) {
        WalletLogPrintf("Transparent history rebuild stopped at block %s: transparent history index is unavailable\n", start_block.ToString());
        result.last_failed_block = start_block;
        result.status = ScanResult::FAILURE;
        return result;
    }

    fAbortRescan = false;
    report_scan_progress(0);

    if (fUpdate && !TopUpSeedRestoreKeyPool()) {
        WalletLogPrintf("Transparent history rebuild stopped: unable to top up wallet script cache before querying the transparent history index\n");
        result.last_failed_block = start_block;
        result.status = ScanResult::FAILURE;
        return result;
    }

    std::set<CScript> queried_scripts;
    const auto initial_scripts{CollectWalletScriptPubKeys(*this)};
    if (initial_scripts.empty()) {
        bool target_still_active{false};
        chain().findBlock(stop_block, FoundBlock().inActiveChain(target_still_active));
        if (!target_still_active || chain().getBlockHash(stop_height) != stop_block) {
            result.last_failed_block = stop_block;
            result.status = ScanResult::FAILURE;
        } else {
            result.last_scanned_block = stop_block;
            result.last_scanned_height = stop_height;
            report_scan_progress(100);
        }
        return result;
    }

    struct MatchedBlock {
        uint256 hash;
        std::map<int, uint256> txids_by_position;
    };

    size_t pass{0};
    while (result.status == ScanResult::SUCCESS) {
        const auto scripts{CollectWalletScriptPubKeys(*this)};
        std::set<CScript> new_scripts;
        std::set_difference(scripts.begin(), scripts.end(),
                            queried_scripts.begin(), queried_scripts.end(),
                            std::inserter(new_scripts, new_scripts.end()));
        if (new_scripts.empty()) break;

        queried_scripts.insert(new_scripts.begin(), new_scripts.end());
        ++pass;
        WalletLogPrintf("Transparent history rebuild pass %u querying %u new wallet scripts (%u total) from height %d to %d\n",
                        static_cast<unsigned>(pass),
                        static_cast<unsigned>(new_scripts.size()),
                        static_cast<unsigned>(queried_scripts.size()),
                        start_height,
                        stop_height);

        const auto indexed_events{chain().getTransparentHistory(new_scripts, start_height, stop_height)};
        if (!indexed_events) {
            WalletLogPrintf("Transparent history rebuild stopped: transparent history index is not ready through height %d\n", stop_height);
            result.last_failed_block = start_block;
            result.status = ScanResult::FAILURE;
            break;
        }

        std::map<int, MatchedBlock> matched_blocks;
        for (const interfaces::TransparentHistoryEntry& event : *indexed_events) {
            if (event.block.height < start_height || event.block.height > stop_height || event.block_position < 0) continue;
            auto [block_it, inserted_block] = matched_blocks.emplace(event.block.height, MatchedBlock{event.block.hash, {}});
            if (!inserted_block && block_it->second.hash != event.block.hash) {
                result.last_failed_block = event.block.hash;
                result.status = ScanResult::FAILURE;
                break;
            }
            auto [tx_it, inserted_tx] = block_it->second.txids_by_position.emplace(event.block_position, event.txid);
            if (!inserted_tx && tx_it->second != event.txid) {
                result.last_failed_block = event.block.hash;
                result.status = ScanResult::FAILURE;
                break;
            }
        }
        if (result.status != ScanResult::SUCCESS) break;

        const int progress_range{std::max(1, stop_height - start_height + 1)};
        for (const auto& [height, match] : matched_blocks) {
            if (fAbortRescan || chain().shutdownRequested()) {
                result.status = ScanResult::USER_ABORT;
                break;
            }

            bool block_still_active{false};
            CBlock block;
            chain().findBlock(match.hash, FoundBlock().inActiveChain(block_still_active).data(block));
            if (!block_still_active || block.IsNull()) {
                result.last_failed_block = match.hash;
                result.status = ScanResult::FAILURE;
                break;
            }

            LOCK(cs_wallet);
            for (const auto& [pos, expected_txid] : match.txids_by_position) {
                if (pos < 0 || static_cast<size_t>(pos) >= block.vtx.size()) {
                    result.last_failed_block = match.hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                const CTransactionRef& tx_ref{block.vtx[pos]};
                if (!tx_ref || tx_ref->GetHash() != expected_txid) {
                    result.last_failed_block = match.hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                SyncTransaction(tx_ref, TxStateConfirmed{match.hash, height, pos}, fUpdate, /*rescanning_old_block=*/true, /*scan_private_bundles=*/false);
            }
            if (result.status != ScanResult::SUCCESS) break;

            result.last_scanned_block = match.hash;
            result.last_scanned_height = height;
            report_scan_progress(std::max(1, std::min(99, static_cast<int>(((height - start_height + 1) * 99) / progress_range))));
        }
        if (result.status == ScanResult::SUCCESS && fUpdate && !TopUpSeedRestoreKeyPool()) {
            WalletLogPrintf("Transparent history rebuild stopped: unable to top up wallet script cache after processing matched history\n");
            result.last_failed_block = result.last_scanned_block.IsNull() ? start_block : result.last_scanned_block;
            result.status = ScanResult::FAILURE;
        }
    }

    if (result.status == ScanResult::SUCCESS) {
        bool target_still_active{false};
        chain().findBlock(stop_block, FoundBlock().inActiveChain(target_still_active));
        if (!target_still_active || chain().getBlockHash(stop_height) != stop_block) {
            result.last_failed_block = stop_block;
            result.status = ScanResult::FAILURE;
        } else {
            result.last_scanned_block = stop_block;
            result.last_scanned_height = stop_height;
            WalletLogPrintf("Transparent history rebuild completed after %u script discovery passes (%u scripts queried)\n",
                            static_cast<unsigned>(pass),
                            static_cast<unsigned>(queried_scripts.size()));
        }
    }
    if (result.status == ScanResult::SUCCESS) report_scan_progress(100);
    return result;
}

CWallet::ScanResult CWallet::ScanWalletHistoryFromIndexes(const uint256& start_block, int start_height, int stop_height, const uint256& stop_block, const WalletRescanReserver& reserver, bool fUpdate, bool show_progress, CWallet::ScanProgressFn progress_fn)
{
    assert(reserver.isReserved());

    ScanResult result;
    bool stop_block_active{false};
    chain().findBlock(stop_block, FoundBlock().inActiveChain(stop_block_active));
    if (stop_height < 0 || stop_block.IsNull() || !stop_block_active || chain().getBlockHash(stop_height) != stop_block) {
        result.last_failed_block = start_block;
        result.status = ScanResult::FAILURE;
        return result;
    }

    const int private_activation_height{Params().GetConsensus().privateTxActivationHeight};
    const bool needs_private_history{
        private_activation_height >= 0 &&
        stop_height >= private_activation_height &&
        WITH_LOCK(cs_wallet, return !m_orchard_keyman.GetChain().hd_seed_id.IsNull())};

    auto report_history_progress = [&](int progress) {
        const int clamped_progress{std::max(0, std::min(100, progress))};
        if (progress_fn) progress_fn(clamped_progress);
        if (show_progress) {
            ShowProgress(strprintf("%s " + _("Restoring complete wallet history...").translated, GetDisplayName()), clamped_progress);
        }
    };

    CWallet::ScanProgressFn transparent_progress = [&](int value) {
        report_history_progress(needs_private_history ? (std::clamp(value, 0, 100) * 60) / 100 : std::clamp(value, 0, 100));
    };
    result = ScanTransparentHistoryFromIndex(start_block, start_height, stop_height, stop_block, reserver, fUpdate, /*show_progress=*/false, transparent_progress);
    if (result.status != ScanResult::SUCCESS) {
        return result;
    }

    if (needs_private_history) {
        const int private_start_height{std::max(start_height, private_activation_height)};
        uint256 private_start_block;
        if (!chain().findAncestorByHeight(stop_block, private_start_height, FoundBlock().hash(private_start_block))) {
            result.last_failed_block = stop_block;
            result.status = ScanResult::FAILURE;
            return result;
        }
        CWallet::ScanProgressFn private_progress = [&](int value) {
            report_history_progress(60 + (std::clamp(value, 0, 100) * 40) / 100);
        };
        result = ScanPrivateNotesFromIndex(private_start_block,
                                           private_start_height,
                                           stop_height,
                                           reserver,
                                           /*require_private_index=*/true,
                                           /*show_progress=*/false,
                                           /*hydrate_wallet_history=*/true,
                                           private_progress,
                                           stop_block);
        if (result.status != ScanResult::SUCCESS) {
            return result;
        }
    }

    bool target_still_active{false};
    chain().findBlock(stop_block, FoundBlock().inActiveChain(target_still_active));
    if (!target_still_active || chain().getBlockHash(stop_height) != stop_block) {
        result.last_failed_block = stop_block;
        result.status = ScanResult::FAILURE;
        return result;
    }
    result.last_scanned_block = stop_block;
    result.last_scanned_height = stop_height;
    report_history_progress(100);
    return result;
}

/**
 * Scan the block chain (starting in start_block) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated. If max_height is not set, the
 * mempool will be scanned as well.
 *
 * @param[in] start_block Scan starting block. If block is not on the active
 *                        chain, the scan will return SUCCESS immediately.
 * @param[in] start_height Height of start_block
 * @param[in] max_height  Optional max scanning height. If unset there is
 *                        no maximum and scanning can continue to the tip
 *
 * @return ScanResult returning scan information and indicating success or
 *         failure. Return status will be set to SUCCESS if scan was
 *         successful. FAILURE if a complete rescan was not possible (due to
 *         pruning or corruption). USER_ABORT if the rescan was aborted before
 *         it could complete.
 *
 * @pre Caller needs to make sure start_block (and the optional stop_block) are on
 * the main chain after to the addition of any new keys you want to detect
 * transactions for.
 */
CWallet::ScanResult CWallet::ScanForWalletTransactions(const uint256& start_block, int start_height, std::optional<int> max_height, const WalletRescanReserver& reserver, bool fUpdate, const bool save_progress, bool require_filter_index, bool require_private_index, bool show_progress, CWallet::ScanProgressFn progress_fn, PrivateRescanMode private_rescan_mode)
{
    constexpr auto INTERVAL_TIME{60s};
    auto current_time{reserver.now()};
    auto start_time{reserver.now()};

    assert(reserver.isReserved());

    uint256 block_hash = start_block;
    ScanResult result;

    std::unique_ptr<FastWalletRescanFilter> fast_rescan_filter;
    if (!IsLegacy() && chain().hasBlockFilterIndex(BlockFilterType::BASIC)) {
        fast_rescan_filter = std::make_unique<FastWalletRescanFilter>(*this);
    }
    const int private_activation_height{Params().GetConsensus().privateTxActivationHeight};
    bool scan_private_bundles{
        private_activation_height >= 0 &&
        WITH_LOCK(cs_wallet, return !m_orchard_keyman.GetChain().hd_seed_id.IsNull())};
    uint256 tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
    uint256 end_hash = max_height ? chain().getBlockHash(*max_height) : tip_hash;
    const int end_height{max_height.value_or(WITH_LOCK(cs_wallet, return GetLastBlockHeight()))};
    if (scan_private_bundles &&
        private_rescan_mode == PrivateRescanMode::DEFER_WHILE_LOCKED &&
        WITH_LOCK(cs_wallet, return !CanViewPrivateData()) &&
        end_height >= private_activation_height) {
        const int private_start_height{std::max(start_height, private_activation_height)};
        if (private_start_height <= end_height) {
            if (!MarkPrivateLockedScanPending(private_start_height, end_height, end_hash)) {
                WalletLogPrintf("Rescan stopped at block %d: deferred private wallet catch-up could not be saved\n", private_start_height);
                result.last_failed_block = chain().getBlockHash(private_start_height);
                result.status = ScanResult::FAILURE;
                return result;
            }
            scan_private_bundles = false;
            WalletLogPrintf("Orchard rescan deferred while encrypted keys are locked; transparent rescan continues from %d through %d\n",
                            private_start_height,
                            end_height);
        }
    }
    class PrivateRescanViewingKeysGuard
    {
    public:
        explicit PrivateRescanViewingKeysGuard(CWallet& wallet) : m_wallet{wallet} {}
        ~PrivateRescanViewingKeysGuard() { Clear(); }

        bool Prepare(bool deep_scan)
        {
            LOCK(m_wallet.cs_wallet);
            m_active = m_wallet.PreparePrivateRescanViewingKeys(deep_scan);
            return m_active;
        }

        void Clear()
        {
            if (!m_active) return;
            LOCK(m_wallet.cs_wallet);
            m_wallet.ClearPrivateRescanViewingKeys();
            m_active = false;
        }

    private:
        CWallet& m_wallet;
        bool m_active{false};
    };
    PrivateRescanViewingKeysGuard private_rescan_keys{*this};
    bool private_rescan_cache_prepared{false};

    if (require_filter_index && !fast_rescan_filter) {
        WalletLogPrintf("Fast mnemonic rescan stopped at block %s: block filter index is unavailable\n", start_block.ToString());
        result.last_failed_block = start_block;
        result.status = ScanResult::FAILURE;
        return result;
    }

    WalletLogPrintf("Rescan started from block %s... (%s, private keys: %s)\n", start_block.ToString(),
                    fast_rescan_filter ? "fast variant using block filters" : "slow variant inspecting all blocks",
                    private_rescan_cache_prepared ? "cached" : "uncached");

    fAbortRescan = false;
    auto report_rescan_progress = [&](int progress) {
        const int clamped_progress{std::max(0, std::min(100, progress))};
        if (progress_fn) progress_fn(clamped_progress);
        if (show_progress) {
            ShowProgress(strprintf("%s " + _("Rescanning…").translated, GetDisplayName()), clamped_progress);
        }
    };

    if (show_progress || progress_fn) {
        report_rescan_progress(0); // show rescan progress in GUI as dialog or on splashscreen, if rescan required on startup (e.g. due to corruption)
    }
    double progress_begin = chain().guessVerificationProgress(block_hash);
    double progress_end = chain().guessVerificationProgress(end_hash);
    double progress_current = progress_begin;
    int block_height = start_height;

    bool skip_main_loop{false};
    auto scan_indexed_transparent_range = [&](int range_start, int range_stop, bool require_range_index) {
        static constexpr int FILTER_RANGE_CHUNK{10000};
        int next_height{range_start};

        while (next_height <= range_stop && !fAbortRescan && !chain().shutdownRequested()) {
            const int chunk_stop{std::min(range_stop, next_height + FILTER_RANGE_CHUNK - 1)};
            fast_rescan_filter->UpdateIfNeeded();
            const auto matches{fast_rescan_filter->MatchBlockRange(next_height, chunk_stop)};
            if (!matches) {
                if (require_range_index) {
                    result.last_failed_block = chain().getBlockHash(next_height);
                    result.status = ScanResult::FAILURE;
                }
                return false;
            }

            bool restart_chunk{false};
            for (const auto& match : *matches) {
                if (fAbortRescan || chain().shutdownRequested()) return false;

                CBlock block;
                bool block_still_active{false};
                chain().findBlock(match.hash, FoundBlock().inActiveChain(block_still_active).data(block));
                if (!block_still_active || block.IsNull()) {
                    result.last_failed_block = match.hash;
                    result.status = ScanResult::FAILURE;
                    return false;
                }

                {
                    LOCK(cs_wallet);
                    for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                        SyncTransaction(block.vtx[posInBlock], TxStateConfirmed{match.hash, match.height, static_cast<int>(posInBlock)}, fUpdate, /*rescanning_old_block=*/true,
                                        /*scan_private_bundles=*/scan_private_bundles);
                    }
                }

                result.last_scanned_block = match.hash;
                result.last_scanned_height = match.height;

                if (fast_rescan_filter->UpdateIfNeeded()) {
                    next_height = match.height + 1;
                    restart_chunk = true;
                    break;
                }
            }
            if (restart_chunk) continue;

            result.last_scanned_block = chain().getBlockHash(chunk_stop);
            result.last_scanned_height = chunk_stop;
            progress_current = chain().guessVerificationProgress(result.last_scanned_block);
            if (progress_end - progress_begin > 0.0) {
                m_scanning_progress = (progress_current - progress_begin) / (progress_end - progress_begin);
                report_rescan_progress(std::max(1, std::min(99, (int)(m_scanning_progress * 100))));
            }
            next_height = chunk_stop + 1;
        }

        return !fAbortRescan && !chain().shutdownRequested() && result.status != ScanResult::FAILURE;
    };

    if (fast_rescan_filter && max_height) {
        int indexed_transparent_stop{*max_height};
        if (scan_private_bundles && private_activation_height >= 0) {
            indexed_transparent_stop = std::min(indexed_transparent_stop, private_activation_height - 1);
        }
        if (indexed_transparent_stop >= block_height) {
            WalletLogPrintf("Fast mnemonic rescan: scanning transparent filters by range from %d to %d\n", block_height, indexed_transparent_stop);
            if (!scan_indexed_transparent_range(block_height, indexed_transparent_stop, require_filter_index)) {
                skip_main_loop = result.status == ScanResult::FAILURE;
            } else if (indexed_transparent_stop >= *max_height) {
                skip_main_loop = true;
            } else {
                block_height = indexed_transparent_stop + 1;
                block_hash = chain().getBlockHash(block_height);
                progress_current = chain().guessVerificationProgress(block_hash);
            }
        }
    }

    while (!skip_main_loop && !fAbortRescan && !chain().shutdownRequested()) {
        if (progress_end - progress_begin > 0.0) {
            m_scanning_progress = (progress_current - progress_begin) / (progress_end - progress_begin);
        } else { // avoid divide-by-zero for single block scan range (i.e. start and stop hashes are equal)
            m_scanning_progress = 0;
        }
        if (block_height % 100 == 0 && progress_end - progress_begin > 0.0) {
            report_rescan_progress(std::max(1, std::min(99, (int)(m_scanning_progress * 100))));
        }

        bool next_interval = reserver.now() >= current_time + INTERVAL_TIME;
        if (next_interval) {
            current_time = reserver.now();
            WalletLogPrintf("Still rescanning. At block %d. Progress=%f\n", block_height, progress_current);
        }

        if (fast_rescan_filter) {
            fast_rescan_filter->UpdateIfNeeded();
        }

        bool fetch_block{true};
        std::optional<std::vector<interfaces::OrchardIndexedTransaction>> indexed_private_txs;
        const bool scan_private_activation_range{scan_private_bundles && block_height >= private_activation_height};
        const bool require_indexed_private_range{require_private_index && block_height >= private_activation_height};
        const bool require_block_filter_for_block{require_filter_index};
        if (scan_private_activation_range && !private_rescan_cache_prepared) {
            private_rescan_cache_prepared = private_rescan_keys.Prepare(/*deep_scan=*/true);
            if (!private_rescan_cache_prepared) {
                WalletLogPrintf("Fast rescan stopped at block %d: Orchard viewing keys could not be prepared\n", block_height);
                result.last_failed_block = block_hash;
                result.status = ScanResult::FAILURE;
                break;
            }
        }
        if (fast_rescan_filter) {
            auto matches_block{fast_rescan_filter->MatchesBlock(block_hash)};
            while (!matches_block.has_value() && require_block_filter_for_block && !fAbortRescan && !chain().shutdownRequested()) {
                if (reserver.now() >= current_time + INTERVAL_TIME) {
                    current_time = reserver.now();
                    WalletLogPrintf("Waiting for block filter index at block %d [%s]\n", block_height, block_hash.ToString());
                    if (progress_end - progress_begin > 0.0) {
                        report_rescan_progress(std::max(1, std::min(99, (int)(m_scanning_progress * 100))));
                    }
                }
                UninterruptibleSleep(100ms);
                matches_block = fast_rescan_filter->MatchesBlock(block_hash);
            }
            if (matches_block.has_value()) {
                if (*matches_block) {
                    LogPrint(BCLog::SCAN, "Fast rescan: inspect block %d [%s] (filter matched)\n", block_height, block_hash.ToString());
                } else if (scan_private_activation_range) {
                    indexed_private_txs = chain().getOrchardBlockTransactions(block_hash);
                    while (!indexed_private_txs.has_value() && require_indexed_private_range && !fAbortRescan && !chain().shutdownRequested()) {
                        if (reserver.now() >= current_time + INTERVAL_TIME) {
                            current_time = reserver.now();
                            WalletLogPrintf("Waiting for private wallet index at block %d (block identifier redacted)\n", block_height);
                            if (progress_end - progress_begin > 0.0) {
                                report_rescan_progress(std::max(1, std::min(99, (int)(m_scanning_progress * 100))));
                            }
                        }
                        UninterruptibleSleep(100ms);
                        indexed_private_txs = chain().getOrchardBlockTransactions(block_hash);
                    }
                    if (indexed_private_txs.has_value()) {
                        fetch_block = false;
                    } else if (require_indexed_private_range) {
                        WalletLogPrintf("Fast rescan stopped at block %d: private wallet index is not ready (block identifier redacted)\n", block_height);
                        result.last_failed_block = block_hash;
                        result.status = ScanResult::FAILURE;
                        break;
                    } else {
                        LogPrint(BCLog::SCAN, "Fast rescan: inspect block %d [%s] (private wallet index not available)\n", block_height, block_hash.ToString());
                    }
                } else {
                    result.last_scanned_block = block_hash;
                    result.last_scanned_height = block_height;
                    fetch_block = false;
                }
            } else if (require_block_filter_for_block) {
                WalletLogPrintf("Fast mnemonic rescan stopped at block %d: block filter is not available for %s\n", block_height, block_hash.ToString());
                result.last_failed_block = block_hash;
                result.status = ScanResult::FAILURE;
                break;
            } else {
                LogPrint(BCLog::SCAN, "Fast rescan: inspect block %d [%s] (WARNING: block filter not found!)\n", block_height, block_hash.ToString());
            }
        }

        // Find next block separately from reading data above, because reading
        // is slow and there might be a reorg while it is read.
        bool block_still_active = false;
        bool next_block = false;
        uint256 next_block_hash;
        chain().findBlock(block_hash, FoundBlock().inActiveChain(block_still_active).nextBlock(FoundBlock().inActiveChain(next_block).hash(next_block_hash)));

        if (fetch_block) {
            // Read block data
            CBlock block;
            chain().findBlock(block_hash, FoundBlock().data(block));

            if (!block.IsNull()) {
                LOCK(cs_wallet);
                if (!block_still_active) {
                    // Abort scan if current block is no longer active, to prevent
                    // marking transactions as coming from the wrong block.
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                    SyncTransaction(block.vtx[posInBlock], TxStateConfirmed{block_hash, block_height, static_cast<int>(posInBlock)}, fUpdate, /*rescanning_old_block=*/true,
                                    /*scan_private_bundles=*/scan_private_bundles);
                }
                // scan succeeded, record block as most recent successfully scanned
                result.last_scanned_block = block_hash;
                result.last_scanned_height = block_height;

                if (save_progress && next_interval) {
                    CBlockLocator loc = m_chain->getActiveChainLocator(block_hash);

                    if (!loc.IsNull()) {
                        WalletLogPrintf("Saving scan progress %d.\n", block_height);
                        WalletBatch batch(GetDatabase());
                        batch.WriteBestBlock(loc);
                    }
                }
            } else {
                // could not scan block, keep scanning but record this block as the most recent failure
                result.last_failed_block = block_hash;
                result.status = ScanResult::FAILURE;
            }
        } else if (indexed_private_txs.has_value()) {
            CBlock block;
            if (!block_still_active) {
                result.last_failed_block = block_hash;
                result.status = ScanResult::FAILURE;
                break;
            }
            for (const auto& indexed_tx : *indexed_private_txs) {
                bool spends_wallet_private_note{false};
                {
                    LOCK(cs_wallet);
                    spends_wallet_private_note = std::any_of(indexed_tx.effects.actions.begin(), indexed_tx.effects.actions.end(),
                        [&](const auto& action) { return mapPrivateNoteNullifiers.count(action.nullifier) != 0; });
                }
                std::vector<PrivateOrchardCompactMatch> compact_matches;
                if (!spends_wallet_private_note) {
                    const PrivateCompactProbeResult probe_result{ProbePrivateCompactEffects(indexed_tx.effects, compact_matches)};
                    if (probe_result == PrivateCompactProbeResult::SCAN_ERROR) {
                        result.last_failed_block = block_hash;
                        result.status = ScanResult::FAILURE;
                        break;
                    }
                    if (probe_result == PrivateCompactProbeResult::NO_MATCH) continue;
                }
                if (block.IsNull()) {
                    chain().findBlock(block_hash, FoundBlock().data(block));
                }
                LOCK(cs_wallet);
                bool still_active{false};
                chain().findBlock(block_hash, FoundBlock().inActiveChain(still_active));
                if (!still_active || block.IsNull()) {
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                const int posInBlock{indexed_tx.block_position};
                if (posInBlock < 0 || static_cast<size_t>(posInBlock) >= block.vtx.size()) {
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                const CTransactionRef& tx_ref = block.vtx[posInBlock];
                if (!tx_ref || tx_ref->GetHash() != indexed_tx.txid || !tx_ref->HasPrivateBundle() ||
                    tx_ref->m_private_bundle->GetEffectsHash() != indexed_tx.effects_hash) {
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                SyncTransaction(tx_ref, TxStateConfirmed{block_hash, block_height, posInBlock}, fUpdate, /*rescanning_old_block=*/true,
                                /*scan_private_bundles=*/scan_private_bundles);
            }
            if (result.status == ScanResult::FAILURE) break;
            result.last_scanned_block = block_hash;
            result.last_scanned_height = block_height;

            if (save_progress && next_interval) {
                CBlockLocator loc = m_chain->getActiveChainLocator(block_hash);

                if (!loc.IsNull()) {
                    WalletLogPrintf("Saving scan progress %d.\n", block_height);
                    WalletBatch batch(GetDatabase());
                    batch.WriteBestBlock(loc);
                }
            }
        }
        if (max_height && block_height >= *max_height) {
            break;
        }
        {
            if (!next_block) {
                // break successfully when rescan has reached the tip, or
                // previous block is no longer on the chain due to a reorg
                break;
            }

            // increment block and verification progress
            block_hash = next_block_hash;
            ++block_height;
            progress_current = chain().guessVerificationProgress(block_hash);

            // handle updated tip hash
            const uint256 prev_tip_hash = tip_hash;
            tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
            if (!max_height && prev_tip_hash != tip_hash) {
                // in case the tip has changed, update progress max
                progress_end = chain().guessVerificationProgress(tip_hash);
            }
        }
    }
    private_rescan_keys.Clear();
    if (!max_height) {
        WalletLogPrintf("Scanning current mempool transactions.\n");
        WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));
    }
    if (show_progress || progress_fn) {
        report_rescan_progress(100); // hide progress dialog in GUI
    }
    if (block_height && fAbortRescan) {
        WalletLogPrintf("Rescan aborted at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else if (block_height && chain().shutdownRequested()) {
        WalletLogPrintf("Rescan interrupted by shutdown request at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else {
        WalletLogPrintf("Rescan completed in %15dms\n", Ticks<std::chrono::milliseconds>(reserver.now() - start_time));
    }
    return result;
}

bool CWallet::SubmitTxMemoryPoolAndRelay(CWalletTx& wtx, std::string& err_string, bool relay) const
{
    AssertLockHeld(cs_wallet);

    // Can't relay if wallet is not broadcasting
    if (!GetBroadcastTransactions()) return false;
    // Don't relay abandoned transactions
    if (wtx.isAbandoned()) return false;
    // Don't try to submit coinbase transactions. These would fail anyway but would
    // cause log spam.
    if (wtx.IsCoinBase()) return false;
    // Don't try to submit conflicted or confirmed transactions.
    if (GetTxDepthInMainChain(wtx) != 0) return false;

    // Submit transaction to mempool for relay
    if (wtx.tx && wtx.tx->HasPrivateBundle()) {
        WalletLogPrintf("Submitting private transaction to mempool for relay (identifier redacted)\n");
    } else {
        WalletLogPrintf("Submitting wtx %s to mempool for relay\n", wtx.GetHash().ToString());
    }
    // We must set TxStateInMempool here. Even though it will also be set later by the
    // entered-mempool callback, if we did not there would be a race where a
    // user could call sendmoney in a loop and hit spurious out of funds errors
    // because we think that this newly generated transaction's change is
    // unavailable as we're not yet aware that it is in the mempool.
    //
    // If broadcast fails for any reason, trying to set wtx.m_state here would be incorrect.
    // If transaction was previously in the mempool, it should be updated when
    // TransactionRemovedFromMempool fires.
    bool ret = chain().broadcastTransaction(wtx.tx, m_default_max_tx_fee, relay, err_string);
    if (ret) wtx.m_state = TxStateInMempool{};
    return ret;
}

std::set<uint256> CWallet::GetTxConflicts(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    const uint256 myHash{wtx.GetHash()};
    std::set<uint256> result{GetConflicts(myHash)};
    result.erase(myHash);
    return result;
}

bool CWallet::ShouldResend() const
{
    // Don't attempt to resubmit if the wallet is configured to not broadcast
    if (!fBroadcastTransactions) return false;

    // During reindex, importing and IBD, old wallet transactions become
    // unconfirmed. Don't resend them as that would spam other nodes.
    // We only allow forcing mempool submission when not relaying to avoid this spam.
    if (!chain().isReadyToBroadcast()) return false;

    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (NodeClock::now() < m_next_resend) return false;

    return true;
}

NodeClock::time_point CWallet::GetDefaultNextResend() { return FastRandomContext{}.rand_uniform_delay(NodeClock::now() + 12h, 24h); }

// Resubmit transactions from the wallet to the mempool, optionally asking the
// mempool to relay them. On startup, we will do this for all unconfirmed
// transactions but will not ask the mempool to relay them. We do this on startup
// to ensure that our own mempool is aware of our transactions. There
// is a privacy side effect here as not broadcasting on startup also means that we won't
// inform the world of our wallet's state, particularly if the wallet (or node) is not
// yet synced.
//
// Otherwise this function is called periodically in order to relay our unconfirmed txs.
// We do this on a random timer to slightly obfuscate which transactions
// come from our wallet.
//
// TODO: Ideally, we'd only resend transactions that we think should have been
// mined in the most recent block. Any transaction that wasn't in the top
// blockweight of transactions in the mempool shouldn't have been mined,
// and so is probably just sitting in the mempool waiting to be confirmed.
// Rebroadcasting does nothing to speed up confirmation and only damages
// privacy.
//
// The `force` option results in all unconfirmed transactions being submitted to
// the mempool. This does not necessarily result in those transactions being relayed,
// that depends on the `relay` option. Periodic rebroadcast uses the pattern
// relay=true force=false, while loading into the mempool
// (on start, or after import) uses relay=false force=true.
void CWallet::ResubmitWalletTransactions(bool relay, bool force)
{
    // Don't attempt to resubmit if the wallet is configured to not broadcast,
    // even if forcing.
    if (!fBroadcastTransactions) return;

    int submitted_tx_count = 0;

    { // cs_wallet scope
        LOCK(cs_wallet);

        // First filter for the transactions we want to rebroadcast.
        // We use a set with WalletTxOrderComparator so that rebroadcasting occurs in insertion order
        std::set<CWalletTx*, WalletTxOrderComparator> to_submit;
        for (auto& [txid, wtx] : mapWallet) {
            // Only rebroadcast unconfirmed txs
            if (!wtx.isUnconfirmed()) continue;

            // Attempt to rebroadcast all txes more than 5 minutes older than
            // the last block, or all txs if forcing.
            if (!force && wtx.nTimeReceived > m_best_block_time - 5 * 60) continue;
            to_submit.insert(&wtx);
        }
        // Now try submitting the transactions to the memory pool and (optionally) relay them.
        for (auto wtx : to_submit) {
            std::string unused_err_string;
            if (SubmitTxMemoryPoolAndRelay(*wtx, unused_err_string, relay)) ++submitted_tx_count;
        }
    } // cs_wallet

    if (submitted_tx_count > 0) {
        WalletLogPrintf("%s: resubmit %u unconfirmed transactions\n", __func__, submitted_tx_count);
    }
}

/** @} */ // end of mapWallet

void MaybeResendWalletTxs(WalletContext& context)
{
    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        if (!pwallet->ShouldResend()) continue;
        pwallet->ResubmitWalletTransactions(/*relay=*/true, /*force=*/false);
        pwallet->SetNextResend();
    }
}

void MaybeCatchUpPrivateWallets(WalletContext& context)
{
    for (const std::shared_ptr<CWallet>& wallet : GetWallets(context)) {
        if (wallet->IsLocked()) continue;
        if (auto catchup = wallet->CatchUpWalletAfterUnlock(); !catchup) {
            wallet->WalletLogPrintf("Periodic wallet recovery remains pending: %s\n", util::ErrorString(catchup).original);
        }
    }
}


/** @defgroup Actions
 *
 * @{
 */

bool CWallet::SignTransaction(CMutableTransaction& tx) const
{
    AssertLockHeld(cs_wallet);

    // Build coins map
    std::map<COutPoint, Coin> coins;
    for (auto& input : tx.vin) {
        const auto mi = mapWallet.find(input.prevout.hash);
        if(mi == mapWallet.end() || input.prevout.n >= mi->second.tx->vout.size()) {
            return false;
        }
        const CWalletTx& wtx = mi->second;
        int prev_height = wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height : 0;
        coins[input.prevout] = Coin(wtx.tx->vout[input.prevout.n], prev_height, wtx.IsCoinBase());
    }
    std::map<int, bilingual_str> input_errors;
    return SignTransaction(tx, coins, SIGHASH_DEFAULT, input_errors);
}

bool CWallet::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    // Try to sign with all ScriptPubKeyMans
    for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
        // spk_man->SignTransaction will return true if the transaction is complete,
        // so we can exit early and return true if that happens
        if (spk_man->SignTransaction(tx, coins, sighash, input_errors)) {
            return true;
        }
    }

    // At this point, one input was not fully signed otherwise we would have exited already
    return false;
}

namespace {
bool PSBTInputHasAnySignature(const PSBTInput& input)
{
    return !input.final_script_sig.empty() ||
        !input.final_script_witness.IsNull() ||
        !input.partial_sigs.empty() ||
        !input.m_tap_key_sig.empty() ||
        !input.m_tap_script_sigs.empty();
}

bool SignNitoPrivateSigningMaterial(const CWallet& wallet, PartiallySignedTransaction& psbtx, const std::optional<uint256>& expected_intent_hash, std::string& error) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (!psbtx.HasNitoPrivateSigningMaterial()) return true;
    if (!psbtx.tx) {
        error = "Nito Orchard signing material without unsigned transaction";
        return false;
    }
    if (psbtx.tx->HasPrivateAuth()) {
        error = "Nito Orchard signing material must not be mixed with existing private authorization";
        return false;
    }
    for (const PSBTInput& input : psbtx.inputs) {
        if (PSBTInputHasAnySignature(input)) {
            error = "Nito Orchard signing material cannot be applied after transparent signatures";
            return false;
        }
    }

    std::optional<uint256> actual_intent_hash;
    try {
        actual_intent_hash = psbtx.GetNitoPrivateIntentHash();
    } catch (const std::ios_base::failure& e) {
        error = e.what();
        return false;
    }
    if (!expected_intent_hash || !actual_intent_hash || *expected_intent_hash != *actual_intent_hash) {
        error = "Nito Orchard PSBT private intent was not reviewed or changed after review";
        return false;
    }

    NitoPrivatePSBTSigningData signing_data;
    try {
        signing_data = psbtx.GetNitoPrivateSigningData();
    } catch (const std::ios_base::failure& e) {
        error = e.what();
        return false;
    }
    if (!signing_data.IsComplete() || !signing_data.plan) {
        error = "Nito Orchard signing material is incomplete";
        return false;
    }
    if (signing_data.plan->version != 1) {
        error = "unsupported Nito Orchard signing plan version";
        return false;
    }
    if (signing_data.plan->spend_count == 0) {
        error = "Nito Orchard signing plan has no private spends";
        return false;
    }
    if (signing_data.plan->spend_count + signing_data.plan->output_count > 100) {
        error = "Nito Orchard signing plan action count is too large";
        return false;
    }
    if (!MoneyRangeSigned(signing_data.plan->value_balance)) {
        error = "Nito Orchard signing plan value balance is out of range";
        return false;
    }

    BIP39Seed derived_seed{};
    BIP39SeedGuard derived_seed_guard{derived_seed};
    bilingual_str seed_error;
    if (!wallet.GetBIP39DerivedSeed(derived_seed, seed_error)) {
        error = seed_error.original.empty() ? "unable to load private wallet seed" : seed_error.original;
        return false;
    }

    std::vector<std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE>> spending_keys(signing_data.spends.size());
    std::vector<PrivateOrchardSpendInfo> spend_infos;
    spend_infos.reserve(signing_data.spends.size());
    std::vector<PrivateOrchardOutputInfo> output_infos;
    output_infos.reserve(signing_data.outputs.size());

    auto cleanse_keys = [&]() {
        for (auto& key : spending_keys) {
            memory_cleanse(key.data(), key.size());
        }
        ClearBIP39Seed(derived_seed);
    };

    size_t key_index{0};
    for (const auto& [spend_index, material] : signing_data.spends) {
        if (spend_index != key_index) {
            error = "Nito Orchard spend material indexes are not contiguous";
            cleanse_keys();
            return false;
        }
        if (material.version != 1) {
            error = "unsupported Nito Orchard spend material version";
            cleanse_keys();
            return false;
        }
        if (material.value <= 0 || !MoneyRange(material.value)) {
            error = "Nito Orchard spend material value is out of range";
            cleanse_keys();
            return false;
        }
        if (material.commitment_index > std::numeric_limits<uint32_t>::max()) {
            error = "Nito Orchard spend material position exceeds builder limit";
            cleanse_keys();
            return false;
        }
        if (material.recipient_raw.size() != NITO_ORCHARD_RAW_ADDRESS_SIZE ||
            material.rho.size() != NITO_ORCHARD_RHO_SIZE ||
            material.rseed.size() != NITO_ORCHARD_RSEED_SIZE ||
            material.merkle_path.size() != NITO_ORCHARD_MERKLE_PATH_SIZE) {
            error = "Nito Orchard spend material has invalid note or witness size";
            cleanse_keys();
            return false;
        }

        const auto note_it = wallet.mapPrivateNotes.find(material.cmx);
        if (note_it == wallet.mapPrivateNotes.end()) {
            error = "Nito Orchard spend material does not belong to this wallet";
            cleanse_keys();
            return false;
        }
        const CPrivateWalletNote& wallet_note = note_it->second;
        const uint32_t material_derivation_version{material.derivation_version == 0 ? 1 : material.derivation_version};
        if (wallet_note.nullifier != material.nullifier ||
            wallet_note.value != material.value ||
            wallet_note.derivation_version != material_derivation_version ||
            wallet_note.account != material.account ||
            wallet_note.internal != material.internal ||
            wallet_note.diversifier_index != material.diversifier_index ||
            wallet_note.commitment_index != material.commitment_index ||
            wallet_note.action_index != material.action_index ||
            wallet_note.recipient_raw != material.recipient_raw ||
            wallet_note.rho != material.rho ||
            wallet_note.rseed != material.rseed) {
            error = "Nito Orchard spend material does not match the wallet note";
            cleanse_keys();
            return false;
        }

        uint256 cmx;
        auto cmx_result = ComputePrivateOrchardNoteCommitment(
            Span<const unsigned char>{material.recipient_raw},
            material.value,
            Span<const unsigned char>{material.rho},
            Span<const unsigned char>{material.rseed},
            cmx,
            error);
        if (cmx_result != PrivateOrchardBuildResult::OK || cmx != material.cmx) {
            if (error.empty()) error = "Nito Orchard spend material note commitment mismatch";
            cleanse_keys();
            return false;
        }

        PrivateOrchardKeyPath path{material.account, material.internal, material.diversifier_index, material_derivation_version};
        auto key_result = DeriveNitoPrivateOrchardSpendingKey(derived_seed, path, spending_keys[key_index], error);
        if (key_result != PrivateOrchardBuildResult::OK) {
            if (error.empty()) error = "failed to derive Nito Orchard spend key for PSBT";
            cleanse_keys();
            return false;
        }

        spend_infos.push_back(PrivateOrchardSpendInfo{
            Span<const unsigned char>{spending_keys[key_index].data(), spending_keys[key_index].size()},
            Span<const unsigned char>{material.recipient_raw},
            material.value,
            Span<const unsigned char>{material.rho},
            Span<const unsigned char>{material.rseed},
            static_cast<uint32_t>(material.commitment_index),
            Span<const unsigned char>{material.merkle_path},
        });
        ++key_index;
    }

    for (const auto& [output_index, material] : signing_data.outputs) {
        if (output_index != output_infos.size()) {
            error = "Nito Orchard output material indexes are not contiguous";
            cleanse_keys();
            return false;
        }
        if (material.version != 1) {
            error = "unsupported Nito Orchard output material version";
            cleanse_keys();
            return false;
        }
        if (material.recipient_raw.size() != NITO_ORCHARD_RAW_ADDRESS_SIZE) {
            error = "Nito Orchard output material has invalid recipient size";
            cleanse_keys();
            return false;
        }
        if (material.value <= 0 || !MoneyRange(material.value)) {
            error = "Nito Orchard output material value is out of range";
            cleanse_keys();
            return false;
        }
        output_infos.push_back(PrivateOrchardOutputInfo{
            Span<const unsigned char>{material.recipient_raw},
            material.value,
            material.ovk_internal,
        });
    }

    auto sighash_callback = [&psbtx](const CPrivateBundle& effects_bundle, uint256& sighash_out, std::string& sighash_error) {
        CMutableTransaction sighash_tx{*psbtx.tx};
        sighash_tx.m_private_bundle = effects_bundle;
        sighash_out = PrivateBundleSighash(sighash_tx);
        sighash_error.clear();
        return true;
    };

    CPrivateBundle bundle;
    auto build_result = BuildPrivateOrchardBundleWithSighashCallback(
        Span<const PrivateOrchardSpendInfo>{spend_infos},
        Span<const PrivateOrchardOutputInfo>{output_infos},
        signing_data.plan->anchor,
        sighash_callback,
        bundle,
        error);
    cleanse_keys();
    if (build_result != PrivateOrchardBuildResult::OK) {
        if (error.empty()) error = "failed to build Nito Orchard bundle from PSBT signing material";
        return false;
    }
    if (bundle.GetValueBalance() != signing_data.plan->value_balance) {
        error = "Nito Orchard signing plan value balance mismatch";
        return false;
    }

    psbtx.tx->m_private_bundle = std::move(bundle);
    std::string verify_error;
    if (VerifyPrivateOrchardBundle(CTransaction(*psbtx.tx), verify_error) != PrivateOrchardVerifyResult::OK) {
        error = verify_error.empty() ? "Nito Orchard PSBT bundle verification failed" : verify_error;
        psbtx.tx->m_private_bundle.reset();
        return false;
    }

    psbtx.ClearNitoPrivateSigningMaterialProprietary();
    psbtx.SetNitoPrivateAuthProprietaryFromTx();
    return true;
}
} // namespace

TransactionError CWallet::FillPSBT(PartiallySignedTransaction& psbtx, bool& complete, int sighash_type, bool sign, bool bip32derivs, size_t * n_signed, bool finalize, std::optional<uint256> private_intent_hash) const
{
    if (n_signed) {
        *n_signed = 0;
    }
    LOCK(cs_wallet);
    // Get all of the previous transactions
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        const CTxIn& txin = psbtx.tx->vin[i];
        PSBTInput& input = psbtx.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        // If we have no utxo, grab it from the wallet.
        if (!input.non_witness_utxo) {
            const uint256& txhash = txin.prevout.hash;
            const auto it = mapWallet.find(txhash);
            if (it != mapWallet.end()) {
                const CWalletTx& wtx = it->second;
                // We only need the non_witness_utxo, which is a superset of the witness_utxo.
                //   The signing code will switch to the smaller witness_utxo if this is ok.
                input.non_witness_utxo = wtx.tx;
            }
        }
    }

    if (sign) {
        std::string private_sign_error;
        if (!SignNitoPrivateSigningMaterial(*this, psbtx, private_intent_hash, private_sign_error)) {
            WalletLogPrintf("Nito Orchard PSBT signing failed: %s\n", private_sign_error);
            return TransactionError::INVALID_PSBT;
        }
    }

    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);

    // Fill in information from ScriptPubKeyMans
    for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
        int n_signed_this_spkm = 0;
        TransactionError res = spk_man->FillPSBT(psbtx, txdata, sighash_type, sign, bip32derivs, &n_signed_this_spkm, finalize);
        if (res != TransactionError::OK) {
            return res;
        }

        if (n_signed) {
            (*n_signed) += n_signed_this_spkm;
        }
    }

    RemoveUnnecessaryTransactions(psbtx, sighash_type);

    // Complete if every input is now signed
    complete = true;
    for (const auto& input : psbtx.inputs) {
        complete &= PSBTInputSigned(input);
    }
    if (psbtx.HasNitoPrivateSigningMaterial()) {
        complete = false;
    }
    if (psbtx.tx->HasPrivateBundle()) {
        psbtx.ApplyNitoPrivateAuthProprietary();
        if (!psbtx.tx->HasPrivateAuth()) {
            complete = false;
        } else {
            std::string private_error;
            if (VerifyPrivateOrchardBundle(CTransaction(*psbtx.tx), private_error) != PrivateOrchardVerifyResult::OK) {
                complete = false;
            }
        }
    }

    return TransactionError::OK;
}

SigningResult CWallet::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    SignatureData sigdata;
    CScript script_pub_key = GetScriptForDestination(pkhash);
    for (const auto& spk_man_pair : m_spk_managers) {
        if (spk_man_pair.second->CanProvide(script_pub_key, sigdata)) {
            LOCK(cs_wallet);  // DescriptorScriptPubKeyMan calls IsLocked which can lock cs_wallet in a deadlocking order
            return spk_man_pair.second->SignMessage(message, pkhash, str_sig);
        }
    }
    return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
}

OutputType CWallet::TransactionChangeType(const std::optional<OutputType>& change_type, const std::vector<CRecipient>& vecSend) const
{
    // Preserve an explicit operator or internal caller override.
    if (change_type) {
        return *change_type;
    }

    // if m_default_address_type is legacy, use legacy address as change.
    if (m_default_address_type == OutputType::LEGACY) {
        return OutputType::LEGACY;
    }

    bool any_tr{false};
    bool any_wpkh{false};
    bool any_sh{false};
    bool any_pkh{false};

    for (const auto& recipient : vecSend) {
        if (std::get_if<WitnessV1Taproot>(&recipient.dest)) {
            any_tr = true;
        } else if (std::get_if<WitnessV0KeyHash>(&recipient.dest)) {
            any_wpkh = true;
        } else if (std::get_if<ScriptHash>(&recipient.dest)) {
            any_sh = true;
        } else if (std::get_if<PKHash>(&recipient.dest)) {
            any_pkh = true;
        }
    }

    const bool has_bech32m_spkman(GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true));
    if (has_bech32m_spkman && any_tr) {
        // Currently tr is the only type supported by the BECH32M spkman
        return OutputType::BECH32M;
    }
    const bool has_bech32_spkman(GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
    if (has_bech32_spkman && any_wpkh) {
        // Currently wpkh is the only type supported by the BECH32 spkman
        return OutputType::BECH32;
    }
    const bool has_p2sh_segwit_spkman(GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/true));
    if (has_p2sh_segwit_spkman && any_sh) {
        // Currently sh_wpkh is the only type supported by the P2SH_SEGWIT spkman
        // As of 2021 about 80% of all SH are wrapping WPKH, so use that
        return OutputType::P2SH_SEGWIT;
    }
    const bool has_legacy_spkman(GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/true));
    if (has_legacy_spkman && any_pkh) {
        // Currently pkh is the only type supported by the LEGACY spkman
        return OutputType::LEGACY;
    }

    if (has_bech32m_spkman) {
        return OutputType::BECH32M;
    }
    if (has_bech32_spkman) {
        return OutputType::BECH32;
    }
    // else use m_default_address_type for change
    return m_default_address_type;
}

static bilingual_str PrivateBroadcastErrorString(const std::string& err_string)
{
    if (err_string.find("bad-private-nullifier-spent") != std::string::npos) {
        return _("A selected private note has already been spent by another transaction. Wait for the wallet to synchronize or for the next block, then create a new private transaction.");
    }
    return Untranslated(err_string.empty() ? "Nito.network private transaction cannot be broadcast immediately" : err_string);
}

util::Result<void> CWallet::CommitTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm)
{
    LOCK(cs_wallet);
    if (tx->HasPrivateBundle()) {
        WalletLogPrintf("CommitTransaction: private transaction payload and identifiers redacted\n");
    } else {
        WalletLogPrintf("CommitTransaction:\n%s", tx->ToString()); // NOLINT(nito-unterminated-logprintf)
    }

    // Add tx to wallet, because if it has change it's also ours,
    // otherwise just for transaction history.
    CWalletTx* wtx = AddToWallet(tx, TxStateInactive{}, [&](CWalletTx& wtx, bool new_tx) {
        CHECK_NONFATAL(wtx.mapValue.empty());
        CHECK_NONFATAL(wtx.vOrderForm.empty());
        wtx.mapValue = std::move(mapValue);
        wtx.vOrderForm = std::move(orderForm);
        wtx.fTimeReceivedIsTxTime = true;
        wtx.fFromMe = true;
        return true;
    });

    // wtx can only be null if the db write failed.
    if (!wtx) {
        throw std::runtime_error(std::string(__func__) + ": Wallet db error, transaction commit failed");
    }

    // Notify that old coins are spent
    for (const CTxIn& txin : tx->vin) {
        CWalletTx &coin = mapWallet.at(txin.prevout.hash);
        coin.MarkDirty();
        NotifyTransactionChanged(coin.GetHash(), CT_UPDATED);
    }

    if (!fBroadcastTransactions) {
        // Don't submit tx to the mempool
        if (tx->HasPrivateBundle()) {
            AbandonTransaction(tx->GetHash());
            return util::Error{_("Nito.network private transactions must be broadcast immediately so private notes are not locked locally without relay.")};
        }
        return {};
    }

    std::string err_string;
    if (!SubmitTxMemoryPoolAndRelay(*wtx, err_string, true)) {
        WalletLogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", err_string);
        if (tx->HasPrivateBundle()) {
            AbandonTransaction(tx->GetHash());
            return util::Error{PrivateBroadcastErrorString(err_string)};
        }
        // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
        return {};
    }

    if (tx->HasPrivateBundle()) {
        SyncPrivateTransaction(*tx, TxStateInMempool{}, /*deep_scan=*/false);
        WalletBatch batch(GetDatabase());
        RefreshPrivateSpentState(&batch);
    }

    return {};
}

DBErrors CWallet::LoadWallet()
{
    LOCK(cs_wallet);

    Assert(m_spk_managers.empty());
    Assert(m_wallet_flags == 0);
    DBErrors nLoadWalletRet = WalletBatch(GetDatabase()).LoadWallet(this);
    if (nLoadWalletRet == DBErrors::NEED_REWRITE)
    {
        if (GetDatabase().Rewrite("\x04pool"))
        {
            for (const auto& spk_man_pair : m_spk_managers) {
                spk_man_pair.second->RewriteDB();
            }
        }
    }

    if (m_spk_managers.empty()) {
        assert(m_external_spk_managers.empty());
        assert(m_internal_spk_managers.empty());
    }

    return nLoadWalletRet;
}

util::Result<void> CWallet::RemoveTxs(std::vector<uint256>& txs_to_remove)
{
    AssertLockHeld(cs_wallet);
    WalletBatch batch(GetDatabase());
    if (!batch.TxnBegin()) return util::Error{_("Error starting db txn for wallet transactions removal")};

    // Check for transaction existence and remove entries from disk
    using TxIterator = std::unordered_map<uint256, CWalletTx, SaltedTxidHasher>::const_iterator;
    std::vector<TxIterator> erased_txs;
    bilingual_str str_err;
    for (const uint256& hash : txs_to_remove) {
        auto it_wtx = mapWallet.find(hash);
        if (it_wtx == mapWallet.end()) {
            str_err = strprintf(_("Transaction %s does not belong to this wallet"), hash.GetHex());
            break;
        }
        if (!batch.EraseTx(hash)) {
            str_err = strprintf(_("Failure removing transaction: %s"), hash.GetHex());
            break;
        }
        erased_txs.emplace_back(it_wtx);
    }

    // Roll back removals in case of an error
    if (!str_err.empty()) {
        batch.TxnAbort();
        return util::Error{str_err};
    }

    // Dump changes to disk
    if (!batch.TxnCommit()) return util::Error{_("Error committing db txn for wallet transactions removal")};

    // Update the in-memory state and notify upper layers about the removals
    for (const auto& it : erased_txs) {
        const uint256 hash{it->first};
        wtxOrdered.erase(it->second.m_it_wtxOrdered);
        for (const auto& txin : it->second.tx->vin)
            mapTxSpends.erase(txin.prevout);
        mapWallet.erase(it);
        NotifyTransactionChanged(hash, CT_DELETED);
    }

    MarkDirty();

    return {}; // all good
}

bool CWallet::SetAddressBookWithDB(WalletBatch& batch, const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& new_purpose)
{
    bool fUpdated = false;
    bool is_mine;
    std::optional<AddressPurpose> purpose;
    {
        LOCK(cs_wallet);
        std::map<CTxDestination, CAddressBookData>::iterator mi = m_address_book.find(address);
        fUpdated = mi != m_address_book.end() && !mi->second.IsChange();

        CAddressBookData& record = mi != m_address_book.end() ? mi->second : m_address_book[address];
        record.SetLabel(strName);
        is_mine = IsMine(address) != ISMINE_NO;
        if (new_purpose) { /* update purpose only if requested */
            record.purpose = new_purpose;
        }
        purpose = record.purpose;
    }

    const std::string& encoded_dest = EncodeDestination(address);
    if (new_purpose && !batch.WritePurpose(encoded_dest, PurposeToString(*new_purpose))) {
        WalletLogPrintf("Error: fail to write address book 'purpose' entry\n");
        return false;
    }
    if (!batch.WriteName(encoded_dest, strName)) {
        WalletLogPrintf("Error: fail to write address book 'name' entry\n");
        return false;
    }

    // In very old wallets, address purpose may not be recorded so we derive it from IsMine
    NotifyAddressBookChanged(address, strName, is_mine,
                             purpose.value_or(is_mine ? AddressPurpose::RECEIVE : AddressPurpose::SEND),
                             (fUpdated ? CT_UPDATED : CT_NEW));
    return true;
}

bool CWallet::SetAddressBook(const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& purpose)
{
    WalletBatch batch(GetDatabase());
    return SetAddressBookWithDB(batch, address, strName, purpose);
}

bool CWallet::LoadPrivateNote(const CPrivateWalletNote& note)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    if (note.GetId().IsNull()) {
        WalletLogPrintf("Error: private note with null commitment ignored\n");
        return false;
    }
    const auto [it, inserted] = mapPrivateNotes.emplace(note.GetId(), note);
    if (!inserted) {
        WalletLogPrintf("Error: duplicate private note commitment ignored (identifier redacted)\n");
        return false;
    }
    AddPrivateNoteNullifierIndex(it->second);
    return true;
}

bool CWallet::LoadCryptedPrivateNote(const uint256& cmx, const std::vector<unsigned char>& ciphertext)
{
    AssertLockHeld(cs_wallet);
    return mapCryptedPrivateNotes.emplace(cmx, ciphertext).second;
}

bool CWallet::WritePrivateNoteRecord(WalletBatch& batch, const CPrivateWalletNote& note)
{
    AssertLockHeld(cs_wallet);
    if (!IsCrypted()) return batch.WritePrivateNote(note);
    if (vMasterKey.empty()) return false;

    std::vector<unsigned char> ciphertext;
    if (!EncryptPrivateNotePayload(vMasterKey, note, ciphertext) ||
        !batch.WriteCryptedPrivateNote(note.GetId(), ciphertext) ||
        !batch.ErasePrivateNote(note.GetId())) {
        return false;
    }
    mapCryptedPrivateNotes[note.GetId()] = std::move(ciphertext);
    return true;
}

bool CWallet::MigratePrivateNoteEncryption()
{
    AssertLockHeld(cs_wallet);
    if (!IsCrypted()) return true;
    if (vMasterKey.empty()) return false;

    WalletBatch batch(GetDatabase());
    if (!batch.TxnBegin()) return false;
    if (!PersistPrivateChain(batch, m_orchard_keyman.GetChain())) {
        batch.TxnAbort();
        return false;
    }
    std::map<uint256, std::vector<unsigned char>> encrypted;
    for (const auto& [cmx, note] : mapPrivateNotes) {
        std::vector<unsigned char> ciphertext;
        if (!EncryptPrivateNotePayload(vMasterKey, note, ciphertext) ||
            !batch.WriteCryptedPrivateNote(cmx, ciphertext) ||
            !batch.ErasePrivateNote(cmx)) {
            batch.TxnAbort();
            return false;
        }
        encrypted.emplace(cmx, std::move(ciphertext));
    }
    if (!batch.TxnCommit()) return false;
    for (auto& [cmx, ciphertext] : encrypted) {
        mapCryptedPrivateNotes[cmx] = std::move(ciphertext);
    }
    return true;
}

void CWallet::ClearDecryptedPrivateNotes()
{
    AssertLockHeld(cs_wallet);
    for (auto& [_, note] : mapPrivateNotes) {
        auto cleanse = [](std::vector<unsigned char>& value) {
            if (!value.empty()) memory_cleanse(value.data(), value.size());
            value.clear();
        };
        cleanse(note.recipient_raw);
        cleanse(note.rho);
        cleanse(note.rseed);
        cleanse(note.memo);
        note.value = 0;
        note.nullifier.SetNull();
    }
    mapPrivateNotes.clear();
    mapPrivateNoteNullifiers.clear();
}

bool CWallet::DecryptPrivateNotes()
{
    AssertLockHeld(cs_wallet);
    if (!IsCrypted()) return true;
    if (vMasterKey.empty()) return false;

    ClearDecryptedPrivateNotes();
    bool complete{true};
    auto cleanse = [](std::vector<unsigned char>& value) {
        if (!value.empty()) memory_cleanse(value.data(), value.size());
        value.clear();
    };
    for (const auto& [cmx, ciphertext] : mapCryptedPrivateNotes) {
        CPrivateWalletNote note;
        const bool loaded{DecryptPrivateNotePayload(vMasterKey, cmx, ciphertext, note) && LoadPrivateNote(note)};
        cleanse(note.recipient_raw);
        cleanse(note.rho);
        cleanse(note.rseed);
        cleanse(note.memo);
        note.value = 0;
        note.nullifier.SetNull();
        if (!loaded) {
            complete = false;
            WalletLogPrintf("Error: unreadable encrypted private note ignored (identifier redacted)\n");
        }
    }
    return complete;
}

bool CWallet::PersistPrivateChain(WalletBatch& batch, const CPrivateWalletChain& chain)
{
    AssertLockHeld(cs_wallet);
    CPrivateWalletChain stored{chain};
    if (IsCrypted()) {
        stored.has_external_full_viewing_key = false;
        stored.has_internal_full_viewing_key = false;
        memory_cleanse(stored.external_full_viewing_key.data(), stored.external_full_viewing_key.size());
        memory_cleanse(stored.internal_full_viewing_key.data(), stored.internal_full_viewing_key.size());
    }
    return batch.WritePrivateChain(stored);
}

void CWallet::AddPrivateNoteNullifierIndex(const CPrivateWalletNote& note)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    if (!note.HasNullifier()) return;
    mapPrivateNoteNullifiers[note.nullifier] = note.GetId();
}

void CWallet::RemovePrivateNoteNullifierIndex(const CPrivateWalletNote& note)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    if (!note.HasNullifier()) return;
    const auto it = mapPrivateNoteNullifiers.find(note.nullifier);
    if (it != mapPrivateNoteNullifiers.end() && it->second == note.GetId()) {
        mapPrivateNoteNullifiers.erase(it);
    }
}

bool CWallet::LoadPrivateSpentNullifier(const CPrivateSpentNullifier& spent)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    if (spent.GetId().IsNull()) {
        WalletLogPrintf("Error: private spent nullifier with null id ignored\n");
        return false;
    }
    const auto [it, inserted] = mapPrivateSpentNullifiers.emplace(spent.GetId(), spent);
    if (!inserted) {
        WalletLogPrintf("Error: duplicate private spent nullifier ignored (identifier redacted)\n");
        return false;
    }
    return true;
}

void CWallet::LoadPrivateChain(const CPrivateWalletChain& chain)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);
    m_orchard_keyman.SetChain(chain);
}

bool CWallet::PreparePrivateViewingKeyMetadata(WalletBatch* batch, bilingual_str& error, bool require_seed)
    EXCLUSIVE_LOCKS_REQUIRED(cs_wallet)
{
    AssertLockHeld(cs_wallet);

    if (IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) || IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        if (require_seed) error = _("Nito.network private addresses require a wallet with private keys.");
        return !require_seed;
    }
    if (IsLocked()) {
        if (require_seed) error = _("Private receiving address metadata is not available yet for this encrypted wallet. Unlock the wallet once or restore it from the recovery phrase to prepare private receiving addresses.");
        return !require_seed;
    }

    CKey mnemonic_entropy;
    bilingual_str seed_error;
    if (!GetPrivateHDSeed(mnemonic_entropy, seed_error)) {
        if (require_seed) error = seed_error;
        return !require_seed;
    }

    const CKeyID active_seed_id{mnemonic_entropy.GetPubKey().GetID()};
    CPrivateWalletChain private_chain{m_orchard_keyman.GetChain()};
    const bool seed_changed{!private_chain.hd_seed_id.IsNull() && private_chain.hd_seed_id != active_seed_id};
    if (seed_changed) {
        private_chain = CPrivateWalletChain{};
    }
    if (private_chain.hd_seed_id == active_seed_id &&
        private_chain.HasFullViewingKey(/*internal=*/false) &&
        private_chain.HasFullViewingKey(/*internal=*/true)) {
        WalletBatch write_batch(GetDatabase());
        if (!PersistPrivateChain(write_batch, private_chain)) {
            error = _("Failed to sanitize persisted Nito.network private viewing metadata.");
            return false;
        }
        return true;
    }

    BIP39Seed derived_seed{};
    BIP39SeedGuard derived_seed_guard{derived_seed};
    if (!GetBIP39DerivedSeed(derived_seed, seed_error)) {
        if (require_seed) error = seed_error;
        return !require_seed;
    }

    private_chain.hd_seed_id = active_seed_id;
    std::string viewing_key_error;
    if (!PopulatePrivateViewingKeys(private_chain, derived_seed, viewing_key_error)) {
        ClearBIP39Seed(derived_seed);
        error = Untranslated(viewing_key_error.empty() ? "Private viewing key preparation failed" : viewing_key_error);
        return false;
    }
    ClearBIP39Seed(derived_seed);

    if (batch) {
        if (!PersistPrivateChain(*batch, private_chain)) {
            error = _("Failed to persist Nito.network private address chain state.");
            return false;
        }
    } else {
        WalletBatch write_batch(GetDatabase());
        if (!PersistPrivateChain(write_batch, private_chain)) {
            error = _("Failed to persist Nito.network private address chain state.");
            return false;
        }
    }
    LoadPrivateChain(private_chain);
    return true;
}

bool CWallet::HasCanonicalPrivateHDSeed() const
{
    AssertLockHeld(cs_wallet);
    const CPrivateWalletChain& chain{m_orchard_keyman.GetChain()};
    return !chain.hd_seed_id.IsNull() && chain.seed_scope != PrivateSeedScope::UNKNOWN;
}

PrivateSeedScope CWallet::GetPrivateSeedScope() const
{
    AssertLockHeld(cs_wallet);
    return m_orchard_keyman.GetChain().seed_scope;
}

bool CWallet::WriteBIP39DerivedSeedRecord(WalletBatch& batch,
                                          const CKey& mnemonic_entropy,
                                          const BIP39Seed& seed,
                                          bool passphrase_enabled,
                                          PrivateSeedScope scope,
                                          CBIP39DerivedSeedRecord& record_out,
                                          bilingual_str& error)
{
    AssertLockHeld(cs_wallet);
    auto clear_record{CreateBIP39DerivedSeedRecord(
        mnemonic_entropy.GetPubKey().GetID(), scope, passphrase_enabled, seed)};
    if (!clear_record) {
        error = util::ErrorString(clear_record);
        return false;
    }

    CBIP39DerivedSeedRecord stored_record;
    if (IsCrypted()) {
        if (vMasterKey.empty()) {
            error = Untranslated("Unlock the wallet before storing its BIP39 derived seed.");
            return false;
        }
        auto encrypted_record{EncryptBIP39DerivedSeedRecord(*clear_record, vMasterKey)};
        if (!encrypted_record) {
            error = util::ErrorString(encrypted_record);
            return false;
        }
        stored_record = std::move(*encrypted_record);
        if (!clear_record->payload.empty()) {
            memory_cleanse(clear_record->payload.data(), clear_record->payload.size());
            clear_record->payload.clear();
        }
    } else {
        stored_record = std::move(*clear_record);
    }

    if (!batch.WriteBIP39DerivedSeed(stored_record)) {
        if (!stored_record.payload.empty()) memory_cleanse(stored_record.payload.data(), stored_record.payload.size());
        error = Untranslated("Unable to persist the BIP39 derived-seed record.");
        return false;
    }
    record_out = std::move(stored_record);
    return true;
}

bool CWallet::InitializePrivateHDSeed(const CKey& hd_seed,
                                      const SecureString& bip39_passphrase,
                                      PrivateSeedScope scope,
                                      bilingual_str& error)
{
    AssertLockHeld(cs_wallet);

    if (!hd_seed.IsValid() || (scope != PrivateSeedScope::FULL_WALLET && scope != PrivateSeedScope::ORCHARD_ONLY)) {
        error = Untranslated("Invalid canonical Orchard seed or recovery scope.");
        return false;
    }
    if (IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) || IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        error = _("Nito.network private addresses require a wallet with private keys.");
        return false;
    }
    if (IsLocked()) {
        error = Untranslated("Unlock the wallet before adding its Orchard recovery root.");
        return false;
    }
    if (HasCanonicalPrivateHDSeed() || !m_orchard_keyman.GetChain().hd_seed_id.IsNull()) {
        error = Untranslated("This wallet already has an Orchard recovery root.");
        return false;
    }

    auto normalized_passphrase{NormalizeBIP39Passphrase(bip39_passphrase)};
    if (!normalized_passphrase) {
        error = util::ErrorString(normalized_passphrase);
        return false;
    }
    const bool passphrase_enabled{!normalized_passphrase->empty()};
    auto derived_seed{DeriveBIP39SeedFromEntropyKey(hd_seed, *normalized_passphrase)};
    ClearBIP39Passphrase(*normalized_passphrase);
    if (!derived_seed) {
        error = util::ErrorString(derived_seed);
        return false;
    }
    BIP39SeedGuard derived_seed_guard{*derived_seed};
    auto fail = [&](bilingual_str failure) {
        error = std::move(failure);
        ClearBIP39Seed(*derived_seed);
        return false;
    };

    CPrivateWalletChain private_chain{};
    private_chain.hd_seed_id = hd_seed.GetPubKey().GetID();
    private_chain.seed_scope = scope;
    std::string viewing_key_error;
    if (!PopulatePrivateViewingKeys(private_chain, *derived_seed, viewing_key_error)) {
        return fail(Untranslated(viewing_key_error.empty() ? "Private viewing key preparation failed" : viewing_key_error));
    }

    // Persist the key before activating the chain metadata. If the second phase
    // fails, an unreferenced key is safe and a retry can reuse it. The reverse
    // order could leave a durable Orchard chain pointing at a missing key.
    WalletBatch key_batch(GetDatabase());
    const CPubKey seed_pub_key{hd_seed.GetPubKey()};
    bool stored{false};
    try {
        if (IsLegacy()) {
            LegacyScriptPubKeyMan* spk_man{GetLegacyScriptPubKeyMan()};
            if (spk_man) {
                LOCK(spk_man->cs_KeyStore);
                CKey existing;
                stored = spk_man->GetKey(private_chain.hd_seed_id, existing) ||
                         spk_man->AddKeyPubKeyWithDB(key_batch, hd_seed, seed_pub_key);
            }
        } else {
            for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
                auto* desc_spk_man{dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)};
                if (!desc_spk_man) continue;
                CKey existing;
                if (desc_spk_man->GetPrivateKey(private_chain.hd_seed_id, existing)) {
                    stored = true;
                    break;
                }
                LOCK(desc_spk_man->cs_desc_man);
                if (desc_spk_man->AddDescriptorKeyWithDB(key_batch, hd_seed, seed_pub_key)) {
                    stored = true;
                    break;
                }
            }
        }
    } catch (const std::exception&) {
        // A key write can persist the key before a later bookkeeping write
        // fails. It remains harmless and unreferenced; report a retryable
        // activation failure instead of leaking a database exception.
        stored = false;
    }

    if (!stored) {
        return fail(Untranslated("Unable to persist the Orchard recovery key."));
    }

    WalletBatch chain_batch(GetDatabase());
    if (!chain_batch.TxnBegin()) {
        return fail(Untranslated("The Orchard recovery key was stored, but its activation transaction could not start. Retry the operation."));
    }
    CBIP39DerivedSeedRecord stored_record;
    bilingual_str record_error;
    const uint64_t new_flags{m_wallet_flags.load() | WALLET_FLAG_BIP39_DERIVED_SEED};
    if (!WriteBIP39DerivedSeedRecord(chain_batch, hd_seed, *derived_seed, passphrase_enabled, scope, stored_record, record_error) ||
        !PersistPrivateChain(chain_batch, private_chain) ||
        !chain_batch.WriteWalletFlags(new_flags) ||
        !chain_batch.TxnCommit()) {
        chain_batch.TxnAbort();
        if (!stored_record.payload.empty()) memory_cleanse(stored_record.payload.data(), stored_record.payload.size());
        return fail(record_error.original.empty()
            ? Untranslated("The Orchard recovery key was stored, but its activation metadata could not be committed. Retry the operation.")
            : record_error);
    }

    m_wallet_flags = new_flags;
    m_bip39_derived_seed_record = std::move(stored_record);
    ClearBIP39DerivedSeedCache();
    m_bip39_derived_seed_cache.assign(
        reinterpret_cast<const unsigned char*>(derived_seed->data()),
        reinterpret_cast<const unsigned char*>(derived_seed->data()) + derived_seed->size());
    LoadPrivateChain(private_chain);
    ClearBIP39Seed(*derived_seed);
    return true;
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    return RunWithinTxn(GetDatabase(), /*process_desc=*/"address book entry removal", [&](WalletBatch& batch){
        return DelAddressBookWithDB(batch, address);
    });
}

bool CWallet::DelAddressBookWithDB(WalletBatch& batch, const CTxDestination& address)
{
    const std::string& dest = EncodeDestination(address);
    {
        LOCK(cs_wallet);
        // If we want to delete receiving addresses, we should avoid calling EraseAddressData because it will delete the previously_spent value. Could instead just erase the label so it becomes a change address, and keep the data.
        // NOTE: This isn't a problem for sending addresses because they don't have any data that needs to be kept.
        // When adding new address data, it should be considered here whether to retain or delete it.
        if (IsMine(address)) {
            WalletLogPrintf("%s called with IsMine address, NOT SUPPORTED. Please report this bug! %s\n", __func__, PACKAGE_BUGREPORT);
            return false;
        }
        // Delete data rows associated with this address
        if (!batch.EraseAddressData(address)) {
            WalletLogPrintf("Error: cannot erase address book entry data\n");
            return false;
        }

        // Delete purpose entry
        if (!batch.ErasePurpose(dest)) {
            WalletLogPrintf("Error: cannot erase address book entry purpose\n");
            return false;
        }

        // Delete name entry
        if (!batch.EraseName(dest)) {
            WalletLogPrintf("Error: cannot erase address book entry name\n");
            return false;
        }

        // finally, remove it from the map
        m_address_book.erase(address);
    }

    // All good, signal changes
    NotifyAddressBookChanged(address, "", /*is_mine=*/false, AddressPurpose::SEND, CT_DELETED);
    return true;
}

size_t CWallet::KeypoolCountExternalKeys() const
{
    AssertLockHeld(cs_wallet);

    auto legacy_spk_man = GetLegacyScriptPubKeyMan();
    if (legacy_spk_man) {
        return legacy_spk_man->KeypoolCountExternalKeys();
    }

    unsigned int count = 0;
    for (auto spk_man : m_external_spk_managers) {
        count += spk_man.second->GetKeyPoolSize();
    }

    return count;
}

unsigned int CWallet::GetKeyPoolSize() const
{
    AssertLockHeld(cs_wallet);

    unsigned int count = 0;
    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        count += spk_man->GetKeyPoolSize();
    }
    return count;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    LOCK(cs_wallet);
    bool res = true;
    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        res &= spk_man->TopUp(kpSize);
    }
    return res;
}

bool CWallet::TopUpSeedRestoreKeyPool()
{
    return TopUpKeyPool(SEED_RESTORE_KEYPOOL_SIZE);
}

util::Result<CTxDestination> CWallet::GetNewDestination(const OutputType type, const std::string label)
{
    LOCK(cs_wallet);
    auto spk_man = GetScriptPubKeyMan(type, /*internal=*/false);
    if (!spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    auto op_dest = spk_man->GetNewDestination(type);
    if (op_dest) {
        SetAddressBook(*op_dest, label, AddressPurpose::RECEIVE);
    }

    return op_dest;
}

util::Result<CTxDestination> CWallet::GetNewChangeDestination(const OutputType type)
{
    LOCK(cs_wallet);

    ReserveDestination reservedest(this, type);
    auto op_dest = reservedest.GetReservedDestination(true);
    if (op_dest) reservedest.KeepDestination();

    return op_dest;
}

std::optional<int64_t> CWallet::GetOldestKeyPoolTime() const
{
    LOCK(cs_wallet);
    if (m_spk_managers.empty()) {
        return std::nullopt;
    }

    std::optional<int64_t> oldest_key{std::numeric_limits<int64_t>::max()};
    for (const auto& spk_man_pair : m_spk_managers) {
        oldest_key = std::min(oldest_key, spk_man_pair.second->GetOldestKeyPoolTime());
    }
    return oldest_key;
}

void CWallet::MarkDestinationsDirty(const std::set<CTxDestination>& destinations) {
    for (auto& entry : mapWallet) {
        CWalletTx& wtx = entry.second;
        if (wtx.m_is_cache_empty) continue;
        for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
            CTxDestination dst;
            if (ExtractDestination(wtx.tx->vout[i].scriptPubKey, dst) && destinations.count(dst)) {
                wtx.MarkDirty();
                break;
            }
        }
    }
}

void CWallet::ForEachAddrBookEntry(const ListAddrBookFunc& func) const
{
    AssertLockHeld(cs_wallet);
    for (const std::pair<const CTxDestination, CAddressBookData>& item : m_address_book) {
        const auto& entry = item.second;
        func(item.first, entry.GetLabel(), entry.IsChange(), entry.purpose);
    }
}

std::vector<CTxDestination> CWallet::ListAddrBookAddresses(const std::optional<AddrBookFilter>& _filter) const
{
    AssertLockHeld(cs_wallet);
    std::vector<CTxDestination> result;
    AddrBookFilter filter = _filter ? *_filter : AddrBookFilter();
    ForEachAddrBookEntry([&result, &filter](const CTxDestination& dest, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) {
        // Filter by change
        if (filter.ignore_change && is_change) return;
        // Filter by label
        if (filter.m_op_label && *filter.m_op_label != label) return;
        // All good
        result.emplace_back(dest);
    });
    return result;
}

std::set<std::string> CWallet::ListAddrBookLabels(const std::optional<AddressPurpose> purpose) const
{
    AssertLockHeld(cs_wallet);
    std::set<std::string> label_set;
    ForEachAddrBookEntry([&](const CTxDestination& _dest, const std::string& _label,
                             bool _is_change, const std::optional<AddressPurpose>& _purpose) {
        if (_is_change) return;
        if (!purpose || purpose == _purpose) {
            label_set.insert(_label);
        }
    });
    return label_set;
}

util::Result<CTxDestination> ReserveDestination::GetReservedDestination(bool internal)
{
    m_spk_man = pwallet->GetScriptPubKeyMan(type, internal);
    if (!m_spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    if (nIndex == -1) {
        CKeyPool keypool;
        int64_t index;
        auto op_address = m_spk_man->GetReservedDestination(type, internal, index, keypool);
        if (!op_address) return op_address;
        nIndex = index;
        address = *op_address;
        fInternal = keypool.fInternal;
    }
    return address;
}

void ReserveDestination::KeepDestination()
{
    if (nIndex != -1) {
        m_spk_man->KeepDestination(nIndex, type);
    }
    nIndex = -1;
    address = CNoDestination();
}

void ReserveDestination::ReturnDestination()
{
    if (nIndex != -1) {
        m_spk_man->ReturnDestination(nIndex, fInternal, address);
    }
    nIndex = -1;
    address = CNoDestination();
}

bool CWallet::DisplayAddress(const CTxDestination& dest)
{
    CScript scriptPubKey = GetScriptForDestination(dest);
    for (const auto& spk_man : GetScriptPubKeyMans(scriptPubKey)) {
        auto signer_spk_man = dynamic_cast<ExternalSignerScriptPubKeyMan *>(spk_man);
        if (signer_spk_man == nullptr) {
            continue;
        }
        ExternalSigner signer = ExternalSignerScriptPubKeyMan::GetExternalSigner();
        return signer_spk_man->DisplayAddress(scriptPubKey, signer);
    }
    return false;
}

bool CWallet::LockCoin(const COutPoint& output, WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    setLockedCoins.insert(output);
    if (batch) {
        return batch->WriteLockedUTXO(output);
    }
    return true;
}

bool CWallet::UnlockCoin(const COutPoint& output, WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    bool was_locked = setLockedCoins.erase(output);
    if (batch && was_locked) {
        return batch->EraseLockedUTXO(output);
    }
    return true;
}

bool CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet);
    bool success = true;
    WalletBatch batch(GetDatabase());
    for (auto it = setLockedCoins.begin(); it != setLockedCoins.end(); ++it) {
        success &= batch.EraseLockedUTXO(*it);
    }
    setLockedCoins.clear();
    return success;
}

bool CWallet::IsLockedCoin(const COutPoint& output) const
{
    AssertLockHeld(cs_wallet);
    return setLockedCoins.count(output) > 0;
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts) const
{
    AssertLockHeld(cs_wallet);
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t>& mapKeyBirth) const {
    AssertLockHeld(cs_wallet);
    mapKeyBirth.clear();

    // map in which we'll infer heights of other keys
    std::map<CKeyID, const TxStateConfirmed*> mapKeyFirstBlock;
    TxStateConfirmed max_confirm{uint256{}, /*height=*/-1, /*index=*/-1};
    max_confirm.confirmed_block_height = GetLastBlockHeight() > 144 ? GetLastBlockHeight() - 144 : 0; // the tip can be reorganized; use a 144-block safety margin
    CHECK_NONFATAL(chain().findAncestorByHeight(GetLastBlockHash(), max_confirm.confirmed_block_height, FoundBlock().hash(max_confirm.confirmed_block_hash)));

    {
        LegacyScriptPubKeyMan* spk_man = GetLegacyScriptPubKeyMan();
        assert(spk_man != nullptr);
        LOCK(spk_man->cs_KeyStore);

        // get birth times for keys with metadata
        for (const auto& entry : spk_man->mapKeyMetadata) {
            if (entry.second.nCreateTime) {
                mapKeyBirth[entry.first] = entry.second.nCreateTime;
            }
        }

        // Prepare to infer birth heights for keys without metadata
        for (const CKeyID &keyid : spk_man->GetKeys()) {
            if (mapKeyBirth.count(keyid) == 0)
                mapKeyFirstBlock[keyid] = &max_confirm;
        }

        // if there are no such keys, we're done
        if (mapKeyFirstBlock.empty())
            return;

        // find first block that affects those keys, if there are any left
        for (const auto& entry : mapWallet) {
            // iterate over all wallet transactions...
            const CWalletTx &wtx = entry.second;
            if (auto* conf = wtx.state<TxStateConfirmed>()) {
                // ... which are already in a block
                for (const CTxOut &txout : wtx.tx->vout) {
                    // iterate over all their outputs
                    for (const auto &keyid : GetAffectedKeys(txout.scriptPubKey, *spk_man)) {
                        // ... and all their affected keys
                        auto rit = mapKeyFirstBlock.find(keyid);
                        if (rit != mapKeyFirstBlock.end() && conf->confirmed_block_height < rit->second->confirmed_block_height) {
                            rit->second = conf;
                        }
                    }
                }
            }
        }
    }

    // Extract block timestamps for those keys
    for (const auto& entry : mapKeyFirstBlock) {
        int64_t block_time;
        CHECK_NONFATAL(chain().findBlock(entry.second->confirmed_block_hash, FoundBlock().time(block_time)));
        mapKeyBirth[entry.first] = block_time - TIMESTAMP_WINDOW; // block times can be 2h off
    }
}

/**
 * Compute smart timestamp for a transaction being added to the wallet.
 *
 * Logic:
 * - If sending a transaction, assign its timestamp to the current time.
 * - If receiving a transaction outside a block, assign its timestamp to the
 *   current time.
 * - If receiving a transaction during a rescanning process, assign all its
 *   (not already known) transactions' timestamps to the block time.
 * - If receiving a block with a future timestamp, assign all its (not already
 *   known) transactions' timestamps to the current time.
 * - If receiving a block with a past timestamp, before the most recent known
 *   transaction (that we care about), assign all its (not already known)
 *   transactions' timestamps to the same timestamp as that most-recent-known
 *   transaction.
 * - If receiving a block with a past timestamp, but after the most recent known
 *   transaction, assign all its (not already known) transactions' timestamps to
 *   the block time.
 *
 * For more information see CWalletTx::nTimeSmart,
 * https://nitotalk.org/?topic=54527, or
 * https://github.com/bitcoin/bitcoin/pull/1393.
 */
unsigned int CWallet::ComputeTimeSmart(const CWalletTx& wtx, bool rescanning_old_block) const
{
    std::optional<uint256> block_hash;
    if (auto* conf = wtx.state<TxStateConfirmed>()) {
        block_hash = conf->confirmed_block_hash;
    } else if (auto* conf = wtx.state<TxStateConflicted>()) {
        block_hash = conf->conflicting_block_hash;
    }

    unsigned int nTimeSmart = wtx.nTimeReceived;
    if (block_hash) {
        int64_t blocktime;
        int64_t block_max_time;
        if (chain().findBlock(*block_hash, FoundBlock().time(blocktime).maxTime(block_max_time))) {
            if (rescanning_old_block) {
                nTimeSmart = block_max_time;
            } else {
                int64_t latestNow = wtx.nTimeReceived;
                int64_t latestEntry = 0;

                // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                int64_t latestTolerated = latestNow + 300;
                const TxItems& txOrdered = wtxOrdered;
                for (auto it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
                    CWalletTx* const pwtx = it->second;
                    if (pwtx == &wtx) {
                        continue;
                    }
                    int64_t nSmartTime;
                    nSmartTime = pwtx->nTimeSmart;
                    if (!nSmartTime) {
                        nSmartTime = pwtx->nTimeReceived;
                    }
                    if (nSmartTime <= latestTolerated) {
                        latestEntry = nSmartTime;
                        if (nSmartTime > latestNow) {
                            latestNow = nSmartTime;
                        }
                        break;
                    }
                }

                nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
            }
        } else if (wtx.tx && wtx.tx->HasPrivateBundle()) {
            WalletLogPrintf("%s: found private transaction not in index (transaction and block identifiers redacted)\n", __func__);
        } else {
            WalletLogPrintf("%s: found %s in block %s not in index\n", __func__, wtx.GetHash().ToString(), block_hash->ToString());
        }
    }
    return nTimeSmart;
}

bool CWallet::SetAddressPreviouslySpent(WalletBatch& batch, const CTxDestination& dest, bool used)
{
    if (std::get_if<CNoDestination>(&dest))
        return false;

    if (!used) {
        if (auto* data{common::FindKey(m_address_book, dest)}) data->previously_spent = false;
        return batch.WriteAddressPreviouslySpent(dest, false);
    }

    LoadAddressPreviouslySpent(dest);
    return batch.WriteAddressPreviouslySpent(dest, true);
}

void CWallet::LoadAddressPreviouslySpent(const CTxDestination& dest)
{
    m_address_book[dest].previously_spent = true;
}

void CWallet::LoadAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& request)
{
    if (!IsValidDestination(dest)) {
        m_non_destination_receive_requests[id] = request;
        return;
    }
    m_address_book[dest].receive_requests[id] = request;
}

bool CWallet::IsAddressPreviouslySpent(const CTxDestination& dest) const
{
    if (auto* data{common::FindKey(m_address_book, dest)}) return data->previously_spent;
    return false;
}

std::vector<std::string> CWallet::GetAddressReceiveRequests() const
{
    std::vector<std::string> values;
    for (const auto& [id, request] : m_non_destination_receive_requests) {
        values.emplace_back(request);
    }
    for (const auto& [dest, entry] : m_address_book) {
        for (const auto& [id, request] : entry.receive_requests) {
            values.emplace_back(request);
        }
    }
    return values;
}

bool CWallet::SetAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id, const std::string& value)
{
    if (!batch.WriteAddressReceiveRequest(dest, id, value)) return false;
    if (!IsValidDestination(dest)) {
        m_non_destination_receive_requests[id] = value;
        return true;
    }
    m_address_book[dest].receive_requests[id] = value;
    return true;
}

bool CWallet::EraseAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id)
{
    if (!batch.EraseAddressReceiveRequest(dest, id)) return false;
    if (!IsValidDestination(dest)) {
        m_non_destination_receive_requests.erase(id);
        return true;
    }
    m_address_book[dest].receive_requests.erase(id);
    return true;
}

std::unique_ptr<WalletDatabase> MakeWalletDatabase(const std::string& name, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error_string)
{
    // Do some checking on wallet path. It should be either a:
    //
    // 1. Path where a directory can be created.
    // 2. Path to an existing directory.
    // 3. Path to a symlink to a directory.
    // 4. For backwards compatibility, the name of a data file in -walletdir.
    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(name));
    fs::file_type path_type = fs::symlink_status(wallet_path).type();
    if (!(path_type == fs::file_type::not_found || path_type == fs::file_type::directory ||
          (path_type == fs::file_type::symlink && fs::is_directory(wallet_path)) ||
          (path_type == fs::file_type::regular && fs::PathFromString(name).filename() == fs::PathFromString(name)))) {
        error_string = Untranslated(strprintf(
              "Invalid -wallet path '%s'. -wallet path should point to a directory where wallet.dat and "
              "database/log.* files can be stored, a location where such a directory could be created, "
              "or (for backwards compatibility) the name of an existing data file in -walletdir (%s)",
              name, fs::quoted(fs::PathToString(GetWalletDir()))));
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }
    return MakeDatabase(wallet_path, options, status, error_string);
}

std::shared_ptr<CWallet> CWallet::Create(WalletContext& context,
                                         const std::string& name,
                                         std::unique_ptr<WalletDatabase> database,
                                         uint64_t wallet_creation_flags,
                                         const SecureString& bip39_passphrase,
                                         bilingual_str& error,
                                         std::vector<bilingual_str>& warnings)
{
    interfaces::Chain* chain = context.chain;
    ArgsManager& args = *Assert(context.args);
    const std::string& walletFile = database->Filename();

    const auto start{SteadyClock::now()};
    // TODO: Can't use std::make_shared because we need a custom deleter but
    // should be possible to use std::allocate_shared.
    std::shared_ptr<CWallet> walletInstance(new CWallet(chain, name, std::move(database)), ReleaseWallet);
    walletInstance->m_keypool_size = std::max(args.GetIntArg("-keypool", DEFAULT_KEYPOOL_SIZE), int64_t{1});
    walletInstance->m_notify_tx_changed_script = args.GetArg("-walletnotify", "");

    // Load wallet
    bool rescan_required = false;
    DBErrors nLoadWalletRet = walletInstance->LoadWallet();
    if (nLoadWalletRet != DBErrors::LOAD_OK) {
        if (nLoadWalletRet == DBErrors::CORRUPT) {
            error = strprintf(_("Error loading %s: Wallet corrupted"), walletFile);
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::NONCRITICAL_ERROR)
        {
            warnings.push_back(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                           " or address metadata may be missing or incorrect."),
                walletFile));
        }
        else if (nLoadWalletRet == DBErrors::TOO_NEW) {
            error = strprintf(_("Error loading %s: Wallet requires newer version of %s"), walletFile, PACKAGE_NAME);
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::EXTERNAL_SIGNER_SUPPORT_REQUIRED) {
            error = strprintf(_("Error loading %s: External signer wallet being loaded without external signer support compiled"), walletFile);
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::NEED_REWRITE)
        {
            error = strprintf(_("Wallet needed to be rewritten: restart %s to complete"), PACKAGE_NAME);
            return nullptr;
        } else if (nLoadWalletRet == DBErrors::NEED_RESCAN) {
            warnings.push_back(strprintf(_("Error reading %s! Transaction data may be missing or incorrect."
                                           " Rescanning wallet."), walletFile));
            rescan_required = true;
        } else if (nLoadWalletRet == DBErrors::UNKNOWN_DESCRIPTOR) {
            error = strprintf(_("Unrecognized descriptor found. Loading wallet %s\n\n"
                                "The wallet might had been created on a newer version.\n"
                                "Please try running the latest software version.\n"), walletFile);
            return nullptr;
        } else if (nLoadWalletRet == DBErrors::UNEXPECTED_LEGACY_ENTRY) {
            error = strprintf(_("Unexpected legacy entry in descriptor wallet found. Loading wallet %s\n\n"
                                "The wallet might have been tampered with or created with malicious intent.\n"), walletFile);
            return nullptr;
        } else {
            error = strprintf(_("Error loading %s"), walletFile);
            return nullptr;
        }
    }

    // This wallet is in its first run if there are no ScriptPubKeyMans and it isn't blank or no privkeys
    const bool fFirstRun = walletInstance->m_spk_managers.empty() &&
                     !walletInstance->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) &&
                     !walletInstance->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET);
    if (fFirstRun)
    {
        // ensure this wallet.dat can only be opened by clients supporting HD with chain split and expects no default key
        walletInstance->SetMinVersion(FEATURE_LATEST);

        walletInstance->InitWalletFlags(wallet_creation_flags);

        // Only create LegacyScriptPubKeyMan when not descriptor wallet
        if (!walletInstance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            walletInstance->SetupLegacyScriptPubKeyMan();
        }

        if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) || !(wallet_creation_flags & (WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET))) {
            LOCK(walletInstance->cs_wallet);
            if (walletInstance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
                if (walletInstance->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
                    walletInstance->SetupDescriptorScriptPubKeyMans();
                } else {
                    CKey mnemonic_entropy{GenerateRandomKey()};
                    walletInstance->SetupDescriptorScriptPubKeyMans(mnemonic_entropy, bip39_passphrase);
                }
                // SetupDescriptorScriptPubKeyMans already calls SetupGeneration for us so we don't need to call SetupGeneration separately
            } else {
                // Legacy wallets need SetupGeneration here.
                for (auto spk_man : walletInstance->GetActiveScriptPubKeyMans()) {
                    if (!spk_man->SetupGeneration()) {
                        error = _("Unable to generate initial keys");
                        return nullptr;
                    }
                }
                LegacyScriptPubKeyMan* legacy_spk_man{walletInstance->GetLegacyScriptPubKeyMan()};
                if (!legacy_spk_man) {
                    error = Untranslated("Unable to access the newly-created legacy wallet key manager.");
                    return nullptr;
                }
                const CHDChain& hd_chain{legacy_spk_man->GetHDChain()};
                CKey legacy_seed;
                if (hd_chain.seed_id.IsNull() || !legacy_spk_man->GetKey(hd_chain.seed_id, legacy_seed)) {
                    error = Untranslated("Unable to retrieve the newly-created legacy wallet seed.");
                    return nullptr;
                }
                bilingual_str private_seed_error;
                const SecureString empty_bip39_passphrase;
                if (!walletInstance->InitializePrivateHDSeed(legacy_seed, empty_bip39_passphrase, PrivateSeedScope::FULL_WALLET, private_seed_error)) {
                    error = private_seed_error;
                    return nullptr;
                }
            }
        }

        if (chain) {
            walletInstance->chainStateFlushed(ChainstateRole::NORMAL, chain->getTipLocator());
        }
    } else if (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS) {
        // Make it impossible to disable private keys after creation
        error = strprintf(_("Error loading %s: Private keys can only be disabled during creation"), walletFile);
        return nullptr;
    } else if (walletInstance->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        for (auto spk_man : walletInstance->GetActiveScriptPubKeyMans()) {
            if (spk_man->HavePrivateKeys()) {
                warnings.push_back(strprintf(_("Warning: Private keys detected in wallet {%s} with disabled private keys"), walletFile));
                break;
            }
        }
    }

    if (!args.GetArg("-addresstype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-addresstype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown address type '%s'"), args.GetArg("-addresstype", ""));
            return nullptr;
        }
        walletInstance->m_default_address_type = parsed.value();
    }

    if (!args.GetArg("-changetype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-changetype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown change type '%s'"), args.GetArg("-changetype", ""));
            return nullptr;
        }
        walletInstance->m_default_change_type = parsed.value();
    }

    if (args.IsArgSet("-mintxfee")) {
        std::optional<CAmount> min_tx_fee = ParseMoney(args.GetArg("-mintxfee", ""));
        if (!min_tx_fee) {
            error = AmountErrMsg("mintxfee", args.GetArg("-mintxfee", ""));
            return nullptr;
        } else if (min_tx_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-mintxfee") + Untranslated(" ") +
                               _("This is the minimum transaction fee you pay on every transaction."));
        }

        walletInstance->m_min_fee = CFeeRate{min_tx_fee.value()};
    }

    if (args.IsArgSet("-maxapsfee")) {
        const std::string max_aps_fee{args.GetArg("-maxapsfee", "")};
        if (max_aps_fee == "-1") {
            walletInstance->m_max_aps_fee = -1;
        } else if (std::optional<CAmount> max_fee = ParseMoney(max_aps_fee)) {
            if (max_fee.value() > HIGH_APS_FEE) {
                warnings.push_back(AmountHighWarn("-maxapsfee") + Untranslated(" ") +
                                  _("This is the maximum transaction fee you pay (in addition to the normal fee) to prioritize partial spend avoidance over regular coin selection."));
            }
            walletInstance->m_max_aps_fee = max_fee.value();
        } else {
            error = AmountErrMsg("maxapsfee", max_aps_fee);
            return nullptr;
        }
    }

    if (args.IsArgSet("-fallbackfee")) {
        std::optional<CAmount> fallback_fee = ParseMoney(args.GetArg("-fallbackfee", ""));
        if (!fallback_fee) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s'"), "-fallbackfee", args.GetArg("-fallbackfee", ""));
            return nullptr;
        } else if (fallback_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-fallbackfee") + Untranslated(" ") +
                               _("This is the transaction fee you may pay when fee estimates are not available."));
        }
        walletInstance->m_fallback_fee = CFeeRate{fallback_fee.value()};
    }

    // Disable fallback fee in case value was set to 0, enable if non-null value
    walletInstance->m_allow_fallback_fee = walletInstance->m_fallback_fee.GetFeePerK() != 0;

    if (args.IsArgSet("-discardfee")) {
        std::optional<CAmount> discard_fee = ParseMoney(args.GetArg("-discardfee", ""));
        if (!discard_fee) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s'"), "-discardfee", args.GetArg("-discardfee", ""));
            return nullptr;
        } else if (discard_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-discardfee") + Untranslated(" ") +
                               _("This is the transaction fee you may discard if change is smaller than dust at this level"));
        }
        walletInstance->m_discard_rate = CFeeRate{discard_fee.value()};
    }

    if (args.IsArgSet("-paytxfee")) {
        std::optional<CAmount> pay_tx_fee = ParseMoney(args.GetArg("-paytxfee", ""));
        if (!pay_tx_fee) {
            error = AmountErrMsg("paytxfee", args.GetArg("-paytxfee", ""));
            return nullptr;
        } else if (pay_tx_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-paytxfee") + Untranslated(" ") +
                               _("This is the transaction fee you will pay if you send a transaction."));
        }

        walletInstance->m_pay_tx_fee = CFeeRate{pay_tx_fee.value(), 1000};

        if (chain && walletInstance->m_pay_tx_fee < chain->relayMinFee()) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s' (must be at least %s)"),
                "-paytxfee", args.GetArg("-paytxfee", ""), chain->relayMinFee().ToString());
            return nullptr;
        }
    }

    if (args.IsArgSet("-maxtxfee")) {
        std::optional<CAmount> max_fee = ParseMoney(args.GetArg("-maxtxfee", ""));
        if (!max_fee) {
            error = AmountErrMsg("maxtxfee", args.GetArg("-maxtxfee", ""));
            return nullptr;
        } else if (max_fee.value() > HIGH_MAX_TX_FEE) {
            warnings.push_back(strprintf(_("%s is set very high! Fees this large could be paid on a single transaction."), "-maxtxfee"));
        }

        if (chain && CFeeRate{max_fee.value(), 1000} < chain->relayMinFee()) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                "-maxtxfee", args.GetArg("-maxtxfee", ""), chain->relayMinFee().ToString());
            return nullptr;
        }

        walletInstance->m_default_max_tx_fee = max_fee.value();
    }

    if (args.IsArgSet("-consolidatefeerate")) {
        if (std::optional<CAmount> consolidate_feerate = ParseMoney(args.GetArg("-consolidatefeerate", ""))) {
            walletInstance->m_consolidate_feerate = CFeeRate(*consolidate_feerate);
        } else {
            error = AmountErrMsg("consolidatefeerate", args.GetArg("-consolidatefeerate", ""));
            return nullptr;
        }
    }

    if (chain && chain->relayMinFee().GetFeePerK() > HIGH_TX_FEE_PER_KB) {
        warnings.push_back(AmountHighWarn("-minrelaytxfee") + Untranslated(" ") +
                           _("The wallet will avoid paying less than the minimum relay fee."));
    }

    walletInstance->m_confirm_target = args.GetIntArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    walletInstance->m_spend_zero_conf_change = args.GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    walletInstance->m_signal_rbf = args.GetBoolArg("-walletrbf", DEFAULT_WALLET_RBF);

    walletInstance->WalletLogPrintf("Wallet completed loading in %15dms\n", Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));

    // Try to top up keypool. No-op if the wallet is locked.
    walletInstance->TopUpKeyPool();

    {
        LOCK(walletInstance->cs_wallet);
        bilingual_str private_metadata_error;
        if (!walletInstance->PreparePrivateViewingKeyMetadata(/*batch=*/nullptr, private_metadata_error, /*require_seed=*/false)) {
            walletInstance->WalletLogPrintf("Nito.network private viewing metadata preparation skipped: %s\n", private_metadata_error.original);
        }
    }

    // Cache the first key time
    std::optional<int64_t> time_first_key;
    for (auto spk_man : walletInstance->GetAllScriptPubKeyMans()) {
        int64_t time = spk_man->GetTimeFirstKey();
        if (!time_first_key || time < *time_first_key) time_first_key = time;
    }
    if (time_first_key) walletInstance->MaybeUpdateBirthTime(*time_first_key);

    if (chain && !AttachChain(walletInstance, *chain, rescan_required, error, warnings)) {
        walletInstance->m_chain_notifications_handler.reset(); // Reset this pointer so that the wallet will actually be unloaded
        return nullptr;
    }

    {
        LOCK(walletInstance->cs_wallet);
        walletInstance->SetBroadcastTransactions(args.GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));
        walletInstance->WalletLogPrintf("setKeyPool.size() = %u\n",      walletInstance->GetKeyPoolSize());
        walletInstance->WalletLogPrintf("mapWallet.size() = %u\n",       walletInstance->mapWallet.size());
        walletInstance->WalletLogPrintf("m_address_book.size() = %u\n",  walletInstance->m_address_book.size());
    }

    return walletInstance;
}

bool CWallet::AttachChain(const std::shared_ptr<CWallet>& walletInstance, interfaces::Chain& chain, const bool rescan_required, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    LOCK(walletInstance->cs_wallet);
    // allow setting the chain if it hasn't been set already but prevent changing it
    assert(!walletInstance->m_chain || walletInstance->m_chain == &chain);
    walletInstance->m_chain = &chain;

    // Unless allowed, ensure wallet files are not reused across chains:
    if (!gArgs.GetBoolArg("-walletcrosschain", DEFAULT_WALLETCROSSCHAIN)) {
        WalletBatch batch(walletInstance->GetDatabase());
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator) && locator.vHave.size() > 0 && chain.getHeight()) {
            // Wallet is assumed to be from another chain, if genesis block in the active
            // chain differs from the genesis block known to the wallet.
            if (chain.getBlockHash(0) != locator.vHave.back()) {
                error = Untranslated("Wallet files should not be reused across chains. Restart nitod with -walletcrosschain to override.");
                return false;
            }
        }
    }

    // Register wallet with validationinterface. It's done before rescan to avoid
    // missing block connections between end of rescan and validation subscribing.
    // Because of wallet lock being hold, block connection notifications are going to
    // be pending on the validation-side until lock release. It's likely to have
    // block processing duplicata (if rescan block range overlaps with notification one)
    // but we guarantee at least than wallet state is correct after notifications delivery.
    // However, chainStateFlushed notifications are ignored until the rescan is finished
    // so that in case of a shutdown event, the rescan will be repeated at the next start.
    // This is temporary until rescan and notifications delivery are unified under same
    // interface.
    walletInstance->m_attaching_chain = true; //ignores chainStateFlushed notifications
    walletInstance->m_chain_notifications_handler = walletInstance->chain().handleNotifications(walletInstance);

    // If rescan_required = true, rescan_height remains equal to 0
    int rescan_height = 0;
    if (!rescan_required)
    {
        WalletBatch batch(walletInstance->GetDatabase());
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator)) {
            if (const std::optional<int> fork_height = chain.findLocatorFork(locator)) {
                rescan_height = *fork_height;
            }
        }
    }

    const std::optional<int> tip_height = chain.getHeight();
    if (tip_height) {
        walletInstance->m_last_block_processed = chain.getBlockHash(*tip_height);
        walletInstance->m_last_block_processed_height = *tip_height;
    } else {
        walletInstance->m_last_block_processed.SetNull();
        walletInstance->m_last_block_processed_height = -1;
    }

    if (tip_height && *tip_height != rescan_height)
    {
        // No need to read and scan block if block was created before
        // our wallet birthday (as adjusted for block time variability)
        std::optional<int64_t> time_first_key = walletInstance->m_birth_time.load();
        if (time_first_key) {
            FoundBlock found = FoundBlock().height(rescan_height);
            chain.findFirstBlockWithTimeAndHeight(*time_first_key - TIMESTAMP_WINDOW, rescan_height, found);
            if (!found.found) {
                // We were unable to find a block that had a time more recent than our earliest timestamp
                // or a height higher than the wallet was synced to, indicating that the wallet is newer than the
                // current chain tip. Skip rescanning in this case.
                rescan_height = *tip_height;
            }
        }

        // Technically we could execute the code below in any case, but performing the
        // `while` loop below can make startup very slow, so only check blocks on disk
        // if necessary.
        if (chain.havePruned() || chain.hasAssumedValidChain()) {
            int block_height = *tip_height;
            while (block_height > 0 && chain.haveBlockOnDisk(block_height - 1) && rescan_height != block_height) {
                --block_height;
            }

            if (rescan_height != block_height) {
                // We can't rescan beyond blocks we don't have data for, stop and throw an error.
                // This might happen if a user uses an old wallet within a pruned node
                // or if they ran -disablewallet for a longer time, then decided to re-enable
                // Exit early and print an error.
                // It also may happen if an assumed-valid chain is in use and therefore not
                // all block data is available.
                // If a block is pruned after this check, we will load the wallet,
                // but fail the rescan with a generic error.

                error = chain.havePruned() ?
                     PrunedWalletRecoveryError() :
                     strprintf(_(
                        "Error loading wallet. Wallet requires blocks to be downloaded, "
                        "and software does not currently support loading wallets while "
                        "blocks are being downloaded out of order when using assumeutxo "
                        "snapshots. Wallet should be able to load successfully after "
                        "node sync reaches height %s"), block_height);
                return false;
            }
        }

        chain.initMessage(_("Rescanning…").translated);
        walletInstance->WalletLogPrintf("Rescanning last %i blocks (from block %i)...\n", *tip_height - rescan_height, rescan_height);

        {
            WalletRescanReserver reserver(*walletInstance);
            if (!reserver.reserve()) {
                error = _("Failed to rescan the wallet during initialization");
                return false;
            }
            const ScanResult scan_result{walletInstance->ScanForWalletTransactions(
                chain.getBlockHash(rescan_height), rescan_height, /*max_height=*/{}, reserver,
                /*fUpdate=*/true, /*save_progress=*/true, /*require_filter_index=*/false,
                /*require_private_index=*/false, /*show_progress=*/true, /*progress_fn=*/{},
                PrivateRescanMode::DEFER_WHILE_LOCKED)};
            if (scan_result.status != ScanResult::SUCCESS) {
                error = _("Failed to rescan the wallet during initialization");
                return false;
            }
        }
        walletInstance->m_attaching_chain = false;
        walletInstance->chainStateFlushed(ChainstateRole::NORMAL, chain.getTipLocator());
        walletInstance->GetDatabase().IncrementUpdateCounter();
    }
    walletInstance->m_attaching_chain = false;

    return true;
}

const CAddressBookData* CWallet::FindAddressBookEntry(const CTxDestination& dest, bool allow_change) const
{
    const auto& address_book_it = m_address_book.find(dest);
    if (address_book_it == m_address_book.end()) return nullptr;
    if ((!allow_change) && address_book_it->second.IsChange()) {
        return nullptr;
    }
    return &address_book_it->second;
}

bool CWallet::UpgradeWallet(int version, bilingual_str& error)
{
    int prev_version = GetVersion();
    if (version == 0) {
        WalletLogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
        version = FEATURE_LATEST;
    } else {
        WalletLogPrintf("Allowing wallet upgrade up to %i\n", version);
    }
    if (version < prev_version) {
        error = strprintf(_("Cannot downgrade wallet from version %i to version %i. Wallet version unchanged."), prev_version, version);
        return false;
    }

    LOCK(cs_wallet);

    // Do not upgrade versions to any version between HD_SPLIT and FEATURE_PRE_SPLIT_KEYPOOL unless already supporting HD_SPLIT
    if (!CanSupportFeature(FEATURE_HD_SPLIT) && version >= FEATURE_HD_SPLIT && version < FEATURE_PRE_SPLIT_KEYPOOL) {
        error = strprintf(_("Cannot upgrade a non HD split wallet from version %i to version %i without upgrading to support pre-split keypool. Please use version %i or no version specified."), prev_version, version, FEATURE_PRE_SPLIT_KEYPOOL);
        return false;
    }

    // Permanently upgrade to the version
    SetMinVersion(GetClosestWalletFeature(version));

    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        if (!spk_man->Upgrade(prev_version, version, error)) {
            return false;
        }
    }
    return true;
}

std::map<uint32_t, std::string> CWallet::ResolveInputAddresses(const CWalletTx& wtx, bool read_block) const
{
    if (!wtx.tx || wtx.IsCoinBase() || wtx.tx->HasPrivateBundle()) return {};
    auto result = wtx.m_input_addresses;
    if (result.size() == wtx.tx->vin.size()) return result;

    auto record = [&](uint32_t index, const CTxOut& output) {
        CTxDestination destination;
        result[index] = ExtractDestination(output.scriptPubKey, destination) ? EncodeDestination(destination) : std::string{};
    };
    std::map<COutPoint, Coin> coins;
    {
        LOCK(cs_wallet);
        for (uint32_t index = 0; index < wtx.tx->vin.size(); ++index) {
            if (result.count(index)) continue;
            const auto& prevout = wtx.tx->vin[index].prevout;
            const auto previous = mapWallet.find(prevout.hash);
            if (previous != mapWallet.end() && prevout.n < previous->second.tx->vout.size()) {
                record(index, previous->second.tx->vout[prevout.n]);
            } else {
                coins.emplace(prevout, Coin{});
            }
        }
    }
    if (!HaveChain() || coins.empty()) return result;

    chain().findCoins(coins);
    for (uint32_t index = 0; index < wtx.tx->vin.size(); ++index) {
        if (result.count(index)) continue;
        const auto coin = coins.find(wtx.tx->vin[index].prevout);
        if (coin != coins.end() && !coin->second.IsSpent()) record(index, coin->second.out);
    }
    if (read_block && result.size() != wtx.tx->vin.size()) {
        if (const auto* confirmed = wtx.state<TxStateConfirmed>()) {
            std::vector<CTxOut> inputs;
            if (chain().findConfirmedTransactionInputs(*wtx.tx, confirmed->confirmed_block_hash,
                                                      confirmed->position_in_block, inputs)) {
                for (uint32_t index = 0; index < inputs.size(); ++index) record(index, inputs[index]);
            }
        }
    }
    return result;
}

void CWallet::RefreshInputAddresses(const std::vector<uint256>& transaction_ids)
{
    // Group old wallet records by block to reuse the node's bounded undo cache.
    // Run during wallet initialization, never while rendering a Qt table/detail.
    std::vector<std::pair<uint256, uint256>> pending;
    {
        LOCK(cs_wallet);
        auto add_pending = [&](const uint256& txid, const CWalletTx& wtx) {
            if (!wtx.IsCoinBase() && !wtx.tx->HasPrivateBundle() &&
                wtx.m_input_addresses.size() < wtx.tx->vin.size()) {
                const auto* confirmed = wtx.state<TxStateConfirmed>();
                pending.emplace_back(confirmed ? confirmed->confirmed_block_hash : uint256{}, txid);
            }
        };
        if (transaction_ids.empty()) {
            for (const auto& [txid, wtx] : mapWallet) add_pending(txid, wtx);
        } else {
            for (const auto& txid : transaction_ids) {
                if (const auto it = mapWallet.find(txid); it != mapWallet.end()) add_pending(txid, it->second);
            }
        }
    }
    std::sort(pending.begin(), pending.end());
    for (const auto& [block_hash, txid] : pending) {
        if (HaveChain() && chain().shutdownRequested()) return;
        std::optional<CWalletTx> snapshot;
        {
            LOCK(cs_wallet);
            if (const auto it = mapWallet.find(txid); it != mapWallet.end()) {
                snapshot.emplace(it->second.tx, it->second.m_state);
                snapshot->m_input_addresses = it->second.m_input_addresses;
            }
        }
        if (!snapshot) continue;
        const auto resolved = ResolveInputAddresses(*snapshot);
        LOCK(cs_wallet);
        const auto it = mapWallet.find(txid);
        if (it == mapWallet.end()) continue;
        CWalletTx& wtx = it->second;
        const auto previous = wtx.m_input_addresses;
        wtx.m_input_addresses.insert(resolved.begin(), resolved.end());
        if (wtx.m_input_addresses == previous) continue;
        if (!WalletBatch(GetDatabase(), /*flush_on_close=*/false).WriteTx(wtx)) {
            wtx.m_input_addresses = previous;
            throw std::runtime_error("DB error writing transparent input address metadata");
        }
        NotifyTransactionChanged(txid, CT_UPDATED);
    }
}

void CWallet::postInitProcess()
{
    // Add wallet transactions that aren't already in a block to mempool
    // Do this here as mempool requires genesis block to be loaded
    ResubmitWalletTransactions(/*relay=*/false, /*force=*/true);

    // Update wallet transactions with current mempool transactions.
    WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));
    RefreshInputAddresses();
}

bool CWallet::BackupWallet(const std::string& strDest) const
{
    return GetDatabase().Backup(strDest);
}

CKeyPool::CKeyPool()
{
    nTime = GetTime();
    fInternal = false;
    m_pre_split = false;
}

CKeyPool::CKeyPool(const CPubKey& vchPubKeyIn, bool internalIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
    fInternal = internalIn;
    m_pre_split = false;
}

int CWallet::GetTxDepthInMainChain(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);
    if (auto* conf = wtx.state<TxStateConfirmed>()) {
        assert(conf->confirmed_block_height >= 0);
        return GetLastBlockHeight() - conf->confirmed_block_height + 1;
    } else if (auto* conf = wtx.state<TxStateConflicted>()) {
        assert(conf->conflicting_block_height >= 0);
        return -1 * (GetLastBlockHeight() - conf->conflicting_block_height + 1);
    } else {
        return 0;
    }
}

int CWallet::GetTxBlocksToMaturity(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    if (!wtx.IsCoinBase()) {
        return 0;
    }
    int chain_depth = GetTxDepthInMainChain(wtx);
    assert(chain_depth >= 0); // coinbase tx should not be conflicted
    return std::max(0, (COINBASE_MATURITY+1) - chain_depth);
}

bool CWallet::IsTxImmatureCoinBase(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    // note GetBlocksToMaturity is 0 for non-coinbase tx
    return GetTxBlocksToMaturity(wtx) > 0;
}

bool CWallet::IsCrypted() const
{
    return HasEncryptionKeys();
}

bool CWallet::IsLocked() const
{
    if (!IsCrypted()) {
        return false;
    }
    LOCK(cs_wallet);
    return vMasterKey.empty();
}

bool CWallet::CanViewPrivateData() const
{
    AssertLockHeld(cs_wallet);
    return !IsCrypted() || !vMasterKey.empty() || m_private_viewing_only;
}

static void ClearWalletMasterKey(CKeyingMaterial& master_key)
{
    if (!master_key.empty()) {
        memory_cleanse(master_key.data(), master_key.size() * sizeof(CKeyingMaterial::value_type));
        master_key.clear();
    }
}

void CWallet::ClearBIP39DerivedSeedCache()
{
    AssertLockHeld(cs_wallet);
    if (!m_bip39_derived_seed_cache.empty()) {
        memory_cleanse(m_bip39_derived_seed_cache.data(), m_bip39_derived_seed_cache.size());
        m_bip39_derived_seed_cache.clear();
    }
}

bool CWallet::LoadBIP39DerivedSeedRecord(const CBIP39DerivedSeedRecord& record)
{
    AssertLockHeld(cs_wallet);
    if (m_bip39_derived_seed_record.has_value()) return false;

    auto valid{ValidateBIP39DerivedSeedRecord(record)};
    if (!valid) {
        WalletLogPrintf("Refusing BIP39 derived-seed record: %s\n", util::ErrorString(valid).original);
        return false;
    }
    m_bip39_derived_seed_record = record;
    return true;
}

bool CWallet::ValidateBIP39DerivedSeedState(bilingual_str& error)
{
    AssertLockHeld(cs_wallet);
    const bool declared{IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED)};
    if (declared != m_bip39_derived_seed_record.has_value()) {
        error = Untranslated(declared
            ? "The wallet declares a BIP39 derived seed, but its record is missing."
            : "The wallet contains a BIP39 derived-seed record without its required wallet flag.");
        return false;
    }
    if (!declared) {
        ClearBIP39DerivedSeedCache();
        return true;
    }

    const CBIP39DerivedSeedRecord& record{*m_bip39_derived_seed_record};
    auto valid{ValidateBIP39DerivedSeedRecord(record)};
    if (!valid) {
        error = util::ErrorString(valid);
        return false;
    }

    const CPrivateWalletChain& chain{m_orchard_keyman.GetChain()};
    if (chain.hd_seed_id.IsNull() || chain.seed_scope == PrivateSeedScope::UNKNOWN ||
        record.hd_seed_id != chain.hd_seed_id || record.SeedScope() != chain.seed_scope) {
        error = Untranslated("The BIP39 derived-seed record does not match the active mnemonic root and recovery scope.");
        return false;
    }

    const bool encrypted_wallet{HasEncryptionKeys()};
    if (encrypted_wallet != (record.protection == BIP39_DERIVED_SEED_ENCRYPTED)) {
        error = Untranslated(encrypted_wallet
            ? "An encrypted wallet contains an unencrypted BIP39 derived-seed record."
            : "An unencrypted wallet contains an encrypted BIP39 derived-seed record.");
        return false;
    }

    ClearBIP39DerivedSeedCache();
    if (!encrypted_wallet) {
        CKey mnemonic_entropy;
        bilingual_str entropy_error;
        if (!GetPrivateHDSeed(mnemonic_entropy, entropy_error) ||
            mnemonic_entropy.GetPubKey().GetID() != record.hd_seed_id) {
            error = entropy_error.original.empty()
                ? Untranslated("The BIP39 derived-seed record references a missing mnemonic entropy key.")
                : entropy_error;
            return false;
        }
        auto extracted{ExtractBIP39DerivedSeed(record)};
        if (!extracted || extracted->size() != BIP39Seed{}.size()) {
            error = extracted ? Untranslated("The BIP39 derived-seed record has an invalid seed length.") : util::ErrorString(extracted);
            return false;
        }
        m_bip39_derived_seed_cache = std::move(*extracted);
    }
    return true;
}

bool CWallet::UnlockBIP39DerivedSeed(const CKeyingMaterial& master_key, bilingual_str& error)
{
    AssertLockHeld(cs_wallet);
    ClearBIP39DerivedSeedCache();

    if (!m_bip39_derived_seed_record) {
        if (IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED)) {
            error = Untranslated("The wallet declares a BIP39 derived seed, but its record is missing.");
            return false;
        }
        return true;
    }

    const CBIP39DerivedSeedRecord& record{*m_bip39_derived_seed_record};
    auto extracted{ExtractBIP39DerivedSeed(record, &master_key)};
    if (!extracted || extracted->size() != BIP39Seed{}.size()) {
        error = extracted ? Untranslated("The BIP39 derived-seed record has an invalid seed length.") : util::ErrorString(extracted);
        return false;
    }

    CKey mnemonic_entropy;
    bilingual_str entropy_error;
    if (!GetPrivateHDSeed(mnemonic_entropy, entropy_error) ||
        mnemonic_entropy.GetPubKey().GetID() != record.hd_seed_id) {
        error = entropy_error.original.empty()
            ? Untranslated("The BIP39 derived-seed record references a missing mnemonic entropy key.")
            : entropy_error;
        return false;
    }

    m_bip39_derived_seed_cache = std::move(*extracted);
    return true;
}

bool CWallet::LockForDisplay()
{
    if (!IsCrypted())
        return false;

    {
        LOCK2(m_relock_mutex, cs_wallet);
        ClearWalletMasterKey(vMasterKey);
        ClearBIP39DerivedSeedCache();
        m_private_viewing_only = true;
    }

    NotifyStatusChanged(this);
    return true;
}

bool CWallet::Lock()
{
    if (!IsCrypted())
        return false;

    {
        LOCK2(m_relock_mutex, cs_wallet);
        ClearWalletMasterKey(vMasterKey);
        ClearBIP39DerivedSeedCache();
        m_private_viewing_only = false;
        ClearPrivateRescanViewingKeys();
        CPrivateWalletChain private_chain{m_orchard_keyman.GetChain()};
        private_chain.has_external_full_viewing_key = false;
        private_chain.has_internal_full_viewing_key = false;
        memory_cleanse(private_chain.external_full_viewing_key.data(), private_chain.external_full_viewing_key.size());
        memory_cleanse(private_chain.internal_full_viewing_key.data(), private_chain.internal_full_viewing_key.size());
        LoadPrivateChain(private_chain);
        ClearDecryptedPrivateNotes();
    }

    NotifyStatusChanged(this);
    return true;
}

bool CWallet::Unlock(const CKeyingMaterial& vMasterKeyIn, bilingual_str* error)
{
    {
        LOCK(cs_wallet);
        for (const auto& spk_man_pair : m_spk_managers) {
            if (!spk_man_pair.second->CheckDecryptionKey(vMasterKeyIn)) {
                return false;
            }
        }
        vMasterKey = vMasterKeyIn;
        m_private_viewing_only = false;
        bilingual_str derived_seed_error;
        if (!UnlockBIP39DerivedSeed(vMasterKey, derived_seed_error)) {
            WalletLogPrintf("Wallet key accepted, but the BIP39 derived-seed record is unusable: %s\n", derived_seed_error.original);
            if (error) *error = derived_seed_error;
            ClearBIP39DerivedSeedCache();
            ClearWalletMasterKey(vMasterKey);
            return false;
        }
        if (!MigratePrivateNoteEncryption()) {
            WalletLogPrintf("Wallet key accepted, but private note encryption migration failed; wallet remains unlocked\n");
        }
        if (!DecryptPrivateNotes()) {
            WalletLogPrintf("Wallet key accepted, but one or more encrypted private notes are unreadable; wallet remains unlocked\n");
        }
    }
    NotifyStatusChanged(this);
    return true;
}

std::set<ScriptPubKeyMan*> CWallet::GetActiveScriptPubKeyMans() const
{
    std::set<ScriptPubKeyMan*> spk_mans;
    for (bool internal : {false, true}) {
        for (OutputType t : OUTPUT_TYPES) {
            auto spk_man = GetScriptPubKeyMan(t, internal);
            if (spk_man) {
                spk_mans.insert(spk_man);
            }
        }
    }
    return spk_mans;
}

bool CWallet::GetPrivateHDSeed(CKey& hd_seed, bilingual_str& error, bool require_exportable_seed) const
{
    AssertLockHeld(cs_wallet);

    if (IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = _("Nito.network private addresses require a wallet with private keys.");
        return false;
    }

    const CPrivateWalletChain& private_chain{m_orchard_keyman.GetChain()};
    if (private_chain.hd_seed_id.IsNull() || private_chain.seed_scope == PrivateSeedScope::UNKNOWN) {
        error = require_exportable_seed
            ? Untranslated("This wallet has no exportable canonical Orchard recovery root. Keep its wallet.dat backup for transparent V3 keys.")
            : Untranslated("This wallet has no canonical Orchard root. Its transparent keys remain unchanged; initialize Orchard explicitly before using Bech32x.");
        return false;
    }

    if (IsLegacy()) {
        LegacyScriptPubKeyMan* spk_man{GetLegacyScriptPubKeyMan()};
        if (spk_man && spk_man->GetKey(private_chain.hd_seed_id, hd_seed)) {
            return true;
        }
    } else {
        for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
            DescriptorScriptPubKeyMan* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
            if (!desc_spk_man) continue;

            if (desc_spk_man->GetPrivateKey(private_chain.hd_seed_id, hd_seed)) {
                return true;
            }
        }
    }

    error = _("Unable to access the Nito.network wallet seed. Unlock the wallet or restore from the recovery phrase.");
    return false;
}

bool CWallet::GetBIP39DerivedSeed(BIP39Seed& seed, bilingual_str& error) const
{
    AssertLockHeld(cs_wallet);
    ClearBIP39Seed(seed);

    if (IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED) != m_bip39_derived_seed_record.has_value()) {
        error = Untranslated("The wallet's BIP39 derived-seed state is incomplete or inconsistent.");
        return false;
    }

    if (m_bip39_derived_seed_record) {
        const CBIP39DerivedSeedRecord& record{*m_bip39_derived_seed_record};
        const CKeyingMaterial* source{nullptr};
        CKeyingMaterial extracted;
        if (!m_bip39_derived_seed_cache.empty()) {
            source = &m_bip39_derived_seed_cache;
        } else if (record.protection == BIP39_DERIVED_SEED_CLEAR) {
            auto result{ExtractBIP39DerivedSeed(record)};
            if (!result) {
                error = util::ErrorString(result);
                return false;
            }
            extracted = std::move(*result);
            source = &extracted;
        } else {
            error = _("Unlock the wallet to access its BIP39-derived spending root.");
            return false;
        }

        if (source->size() != seed.size()) {
            if (!extracted.empty()) memory_cleanse(extracted.data(), extracted.size());
            error = Untranslated("The BIP39 derived-seed record has an invalid seed length.");
            return false;
        }
        std::memcpy(seed.data(), source->data(), seed.size());
        if (!extracted.empty()) {
            memory_cleanse(extracted.data(), extracted.size());
            extracted.clear();
        }
        return true;
    }

    // Legacy V4 wallets did not persist the final seed. Their exact historical
    // behavior is the standard BIP39 derivation with an empty passphrase.
    CKey mnemonic_entropy;
    if (!GetPrivateHDSeed(mnemonic_entropy, error)) return false;
    auto derived{DeriveBIP39SeedFromEntropyKey(mnemonic_entropy)};
    if (!derived) {
        error = util::ErrorString(derived);
        return false;
    }
    seed = *derived;
    ClearBIP39Seed(*derived);
    return true;
}

bool CWallet::IsBIP39PassphraseEnabled() const
{
    AssertLockHeld(cs_wallet);
    return m_bip39_derived_seed_record && m_bip39_derived_seed_record->PassphraseEnabled();
}

util::Result<std::string> CWallet::GetNewPrivateAddress(bool internal)
{
    AssertLockHeld(cs_wallet);

    if (!HaveChain() || !chain().hasOrchardIndex()) {
        return util::Error{_("The private wallet index is not available. Restart Nito Core with private wallet indexing enabled (-orchardindex=1) before using Bech32x wallet features.")};
    }

    OrchardKeyMan keyman{m_orchard_keyman.GetChain()};
    if (IsLocked()) {
        return util::Error{_("Private receiving address metadata is not available yet for this encrypted wallet. Unlock the wallet once or restore it from the recovery phrase to prepare private receiving addresses.")};
    }
    if (!keyman.GetChain().HasFullViewingKey(internal)) {
        bilingual_str private_metadata_error;
        if (!PreparePrivateViewingKeyMetadata(/*batch=*/nullptr, private_metadata_error)) {
            return util::Error{private_metadata_error};
        }
        keyman.SetChain(m_orchard_keyman.GetChain());
        if (!keyman.GetChain().HasFullViewingKey(internal)) {
            return util::Error{_("Private receiving address metadata is not available yet for this encrypted wallet. Unlock the wallet once or restore it from the recovery phrase to prepare private receiving addresses.")};
        }
    }

    PrivateOrchardKeyPath path = keyman.NextPath(internal);

    std::string address;
    std::string error;
    const auto result = keyman.DeriveAddress(path, Params(), address, error);
    if (result != PrivateOrchardBuildResult::OK) {
        return util::Error{Untranslated(error.empty() ? "Private address derivation failed" : error)};
    }

    keyman.MarkPathUsed(path);
    WalletBatch batch(GetDatabase());
    if (!PersistPrivateChain(batch, keyman.GetChain())) {
        return util::Error{_("Failed to persist Nito.network private address chain state.")};
    }
    LoadPrivateChain(keyman.GetChain());
    return address;
}

const OrchardKeyMan& CWallet::GetOrchardKeyMan() const
{
    AssertLockHeld(cs_wallet);
    return m_orchard_keyman;
}

const CPrivateWalletChain& CWallet::GetPrivateChain() const
{
    AssertLockHeld(cs_wallet);
    return m_orchard_keyman.GetChain();
}

std::set<ScriptPubKeyMan*> CWallet::GetAllScriptPubKeyMans() const
{
    std::set<ScriptPubKeyMan*> spk_mans;
    for (const auto& spk_man_pair : m_spk_managers) {
        spk_mans.insert(spk_man_pair.second.get());
    }
    return spk_mans;
}

ScriptPubKeyMan* CWallet::GetScriptPubKeyMan(const OutputType& type, bool internal) const
{
    const std::map<OutputType, ScriptPubKeyMan*>& spk_managers = internal ? m_internal_spk_managers : m_external_spk_managers;
    std::map<OutputType, ScriptPubKeyMan*>::const_iterator it = spk_managers.find(type);
    if (it == spk_managers.end()) {
        return nullptr;
    }
    return it->second;
}

std::set<ScriptPubKeyMan*> CWallet::GetScriptPubKeyMans(const CScript& script) const
{
    std::set<ScriptPubKeyMan*> spk_mans;

    // Search the cache for relevant SPKMs instead of iterating m_spk_managers
    const auto& it = m_cached_spks.find(script);
    if (it != m_cached_spks.end()) {
        spk_mans.insert(it->second.begin(), it->second.end());
    }
    SignatureData sigdata;
    Assume(std::all_of(spk_mans.begin(), spk_mans.end(), [&script, &sigdata](ScriptPubKeyMan* spkm) { return spkm->CanProvide(script, sigdata); }));

    // Legacy wallet
    if (IsLegacy() && GetLegacyScriptPubKeyMan()->CanProvide(script, sigdata)) spk_mans.insert(GetLegacyScriptPubKeyMan());

    return spk_mans;
}

ScriptPubKeyMan* CWallet::GetScriptPubKeyMan(const uint256& id) const
{
    if (m_spk_managers.count(id) > 0) {
        return m_spk_managers.at(id).get();
    }
    return nullptr;
}

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script) const
{
    SignatureData sigdata;
    return GetSolvingProvider(script, sigdata);
}

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script, SignatureData& sigdata) const
{
    // Search the cache for relevant SPKMs instead of iterating m_spk_managers
    const auto& it = m_cached_spks.find(script);
    if (it != m_cached_spks.end()) {
        // All spkms for a given script must already be able to make a SigningProvider for the script, so just return the first one.
        Assume(it->second.at(0)->CanProvide(script, sigdata));
        return it->second.at(0)->GetSolvingProvider(script);
    }

    // Legacy wallet
    if (IsLegacy() && GetLegacyScriptPubKeyMan()->CanProvide(script, sigdata)) return GetLegacyScriptPubKeyMan()->GetSolvingProvider(script);

    return nullptr;
}

std::vector<WalletDescriptor> CWallet::GetWalletDescriptors(const CScript& script) const
{
    std::vector<WalletDescriptor> descs;
    for (const auto spk_man: GetScriptPubKeyMans(script)) {
        if (const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)) {
            LOCK(desc_spk_man->cs_desc_man);
            descs.push_back(desc_spk_man->GetWalletDescriptor());
        }
    }
    return descs;
}

LegacyScriptPubKeyMan* CWallet::GetLegacyScriptPubKeyMan() const
{
    if (IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return nullptr;
    }
    // Legacy wallets only have one ScriptPubKeyMan which is a LegacyScriptPubKeyMan.
    // Everything in m_internal_spk_managers and m_external_spk_managers point to the same legacyScriptPubKeyMan.
    auto it = m_internal_spk_managers.find(OutputType::LEGACY);
    if (it == m_internal_spk_managers.end()) return nullptr;
    return dynamic_cast<LegacyScriptPubKeyMan*>(it->second);
}

LegacyScriptPubKeyMan* CWallet::GetOrCreateLegacyScriptPubKeyMan()
{
    SetupLegacyScriptPubKeyMan();
    return GetLegacyScriptPubKeyMan();
}

void CWallet::AddScriptPubKeyMan(const uint256& id, std::unique_ptr<ScriptPubKeyMan> spkm_man)
{
    // Add spkm_man to m_spk_managers before calling any method
    // that might access it.
    const auto& spkm = m_spk_managers[id] = std::move(spkm_man);

    // Update birth time if needed
    MaybeUpdateBirthTime(spkm->GetTimeFirstKey());
}

void CWallet::SetupLegacyScriptPubKeyMan()
{
    if (!m_internal_spk_managers.empty() || !m_external_spk_managers.empty() || !m_spk_managers.empty() || IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return;
    }

    auto spk_manager = std::unique_ptr<ScriptPubKeyMan>(new LegacyScriptPubKeyMan(*this, m_keypool_size));
    for (const auto& type : LEGACY_OUTPUT_TYPES) {
        m_internal_spk_managers[type] = spk_manager.get();
        m_external_spk_managers[type] = spk_manager.get();
    }
    uint256 id = spk_manager->GetID();
    AddScriptPubKeyMan(id, std::move(spk_manager));
}

bool CWallet::WithEncryptionKey(std::function<bool (const CKeyingMaterial&)> cb) const
{
    LOCK(cs_wallet);
    return cb(vMasterKey);
}

bool CWallet::HasEncryptionKeys() const
{
    return !mapMasterKeys.empty();
}

void CWallet::ConnectScriptPubKeyManNotifiers()
{
    for (const auto& spk_man : GetActiveScriptPubKeyMans()) {
        spk_man->NotifyWatchonlyChanged.connect(NotifyWatchonlyChanged);
        spk_man->NotifyCanGetAddressesChanged.connect(NotifyCanGetAddressesChanged);
        spk_man->NotifyFirstKeyTimeChanged.connect(std::bind(&CWallet::MaybeUpdateBirthTime, this, std::placeholders::_2));
    }
}

DescriptorScriptPubKeyMan& CWallet::LoadDescriptorScriptPubKeyMan(uint256 id, WalletDescriptor& desc)
{
    DescriptorScriptPubKeyMan* spk_manager;
    if (IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        spk_manager = new ExternalSignerScriptPubKeyMan(*this, desc, m_keypool_size);
    } else {
        spk_manager = new DescriptorScriptPubKeyMan(*this, desc, m_keypool_size);
    }
    AddScriptPubKeyMan(id, std::unique_ptr<ScriptPubKeyMan>(spk_manager));
    return *spk_manager;
}

void CWallet::SetupDescriptorScriptPubKeyMansWithBIP39(const CExtKey& master_key,
                                                        const std::optional<CKey>& mnemonic_entropy,
                                                        const BIP39Seed* seed,
                                                        bool passphrase_enabled,
                                                        std::optional<int64_t> creation_time)
{
    AssertLockHeld(cs_wallet);
    if (mnemonic_entropy.has_value() != (seed != nullptr)) {
        throw std::runtime_error(std::string(__func__) + ": mnemonic entropy and derived seed must be supplied together");
    }

    WalletBatch batch(GetDatabase());
    if (!batch.TxnBegin()) throw std::runtime_error("Error: cannot create db transaction for descriptors setup");

    struct PreparedDescriptor {
        uint256 id;
        OutputType type;
        bool internal;
        std::unique_ptr<DescriptorScriptPubKeyMan> manager;
    };
    std::vector<PreparedDescriptor> prepared;
    const uint64_t original_flags{m_wallet_flags.load()};
    uint64_t committed_flags{original_flags};
    CBIP39DerivedSeedRecord stored_record;
    CPrivateWalletChain private_chain;

    try {
        for (bool internal : {false, true}) {
            for (OutputType type : OUTPUT_TYPES) {
                auto spk_manager{std::make_unique<DescriptorScriptPubKeyMan>(*this, m_keypool_size)};
                if (IsCrypted()) {
                    if (IsLocked()) {
                        throw std::runtime_error(std::string(__func__) + ": Wallet is locked, cannot setup new descriptors");
                    }
                    if (!spk_manager->CheckDecryptionKey(vMasterKey) && !spk_manager->Encrypt(vMasterKey, &batch)) {
                        throw std::runtime_error(std::string(__func__) + ": Could not encrypt new descriptors");
                    }
                }
                spk_manager->SetupDescriptorGeneration(batch, master_key, type, internal, creation_time);
                if (mnemonic_entropy) {
                    const CPubKey entropy_pub_key{mnemonic_entropy->GetPubKey()};
                    LOCK(spk_manager->cs_desc_man);
                    if (!spk_manager->AddDescriptorKeyWithDB(batch, *mnemonic_entropy, entropy_pub_key)) {
                        throw std::runtime_error(std::string(__func__) + ": writing Nito.network mnemonic entropy key failed");
                    }
                }
                const uint256 id{spk_manager->GetID()};
                if (!batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(type), id, internal)) {
                    throw std::runtime_error(std::string(__func__) + ": writing active ScriptPubKeyMan id failed");
                }
                prepared.push_back({id, type, internal, std::move(spk_manager)});
            }
        }

        if (mnemonic_entropy) {
            private_chain.hd_seed_id = mnemonic_entropy->GetPubKey().GetID();
            private_chain.seed_scope = PrivateSeedScope::FULL_WALLET;
            std::string viewing_key_error;
            if (!PopulatePrivateViewingKeys(private_chain, *seed, viewing_key_error)) {
                throw std::runtime_error(strprintf("%s: preparing Nito.network private viewing keys failed: %s", __func__, viewing_key_error));
            }
            bilingual_str record_error;
            if (!WriteBIP39DerivedSeedRecord(batch, *mnemonic_entropy, *seed, passphrase_enabled,
                                             PrivateSeedScope::FULL_WALLET, stored_record, record_error)) {
                throw std::runtime_error(record_error.original);
            }
            if (!PersistPrivateChain(batch, private_chain)) {
                throw std::runtime_error(std::string(__func__) + ": writing Nito.network private seed metadata failed");
            }
            committed_flags = m_wallet_flags.load() | WALLET_FLAG_BIP39_DERIVED_SEED;
            if (!batch.WriteWalletFlags(committed_flags)) {
                throw std::runtime_error(std::string(__func__) + ": writing BIP39 wallet flag failed");
            }
        } else {
            committed_flags = m_wallet_flags.load();
        }

        if (!batch.TxnCommit()) {
            throw std::runtime_error("Error: cannot commit db transaction for descriptors setup");
        }
    } catch (...) {
        batch.TxnAbort();
        m_wallet_flags = original_flags;
        if (!stored_record.payload.empty()) {
            memory_cleanse(stored_record.payload.data(), stored_record.payload.size());
            stored_record.payload.clear();
        }
        throw;
    }

    m_wallet_flags = committed_flags;
    for (auto& item : prepared) {
        AddScriptPubKeyMan(item.id, std::move(item.manager));
        LoadActiveScriptPubKeyMan(item.id, item.type, item.internal);
    }

    if (mnemonic_entropy) {
        m_bip39_derived_seed_record = std::move(stored_record);
        ClearBIP39DerivedSeedCache();
        m_bip39_derived_seed_cache.assign(
            reinterpret_cast<const unsigned char*>(seed->data()),
            reinterpret_cast<const unsigned char*>(seed->data()) + seed->size());
        LoadPrivateChain(private_chain);
    }
}

void CWallet::SetupDescriptorScriptPubKeyMans(const CExtKey& master_key,
                                               const std::optional<CKey>& seed_key,
                                               std::optional<int64_t> creation_time)
{
    AssertLockHeld(cs_wallet);
    if (!seed_key) {
        SetupDescriptorScriptPubKeyMansWithBIP39(
            master_key, std::nullopt, /*seed=*/nullptr, /*passphrase_enabled=*/false, creation_time);
        return;
    }

    auto derived_seed{DeriveBIP39SeedFromEntropyKey(*seed_key)};
    if (!derived_seed) {
        throw std::runtime_error(std::string(__func__) + ": failed to derive BIP39 seed: " + util::ErrorString(derived_seed).original);
    }
    BIP39SeedGuard derived_seed_guard{*derived_seed};
    const CExtKey expected_master{MakeBIP39MasterKey(*derived_seed)};
    if (master_key.Neuter() != expected_master.Neuter()) {
        throw std::runtime_error(std::string(__func__) + ": descriptor master key does not match the BIP39 mnemonic entropy");
    }
    SetupDescriptorScriptPubKeyMansWithBIP39(
        master_key, seed_key, &*derived_seed, /*passphrase_enabled=*/false, creation_time);
}

void CWallet::SetupDescriptorScriptPubKeyMans(const CKey& mnemonic_entropy,
                                               const SecureString& bip39_passphrase,
                                               std::optional<int64_t> creation_time)
{
    AssertLockHeld(cs_wallet);
    auto normalized_passphrase{NormalizeBIP39Passphrase(bip39_passphrase)};
    if (!normalized_passphrase) {
        throw std::runtime_error(util::ErrorString(normalized_passphrase).original);
    }
    const bool passphrase_enabled{!normalized_passphrase->empty()};
    auto derived_seed{DeriveBIP39SeedFromEntropyKey(mnemonic_entropy, *normalized_passphrase)};
    ClearBIP39Passphrase(*normalized_passphrase);
    if (!derived_seed) {
        throw std::runtime_error(util::ErrorString(derived_seed).original);
    }
    BIP39SeedGuard derived_seed_guard{*derived_seed};
    const CExtKey master_key{MakeBIP39MasterKey(*derived_seed)};
    SetupDescriptorScriptPubKeyMansWithBIP39(
        master_key, mnemonic_entropy, &*derived_seed, passphrase_enabled, creation_time);
}

void CWallet::SetupDescriptorScriptPubKeyMans()
{
    AssertLockHeld(cs_wallet);

    if (!IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        // Make a seed
        CKey seed_key = GenerateRandomKey();
        CPubKey seed = seed_key.GetPubKey();
        assert(seed_key.VerifyPubKey(seed));

        const SecureString empty_bip39_passphrase;
        SetupDescriptorScriptPubKeyMans(seed_key, empty_bip39_passphrase);
    } else {
        ExternalSigner signer = ExternalSignerScriptPubKeyMan::GetExternalSigner();

        // TODO: add account parameter
        int account = 0;
        UniValue signer_res = signer.GetDescriptors(account);

        if (!signer_res.isObject()) throw std::runtime_error(std::string(__func__) + ": Unexpected result");

        WalletBatch batch(GetDatabase());
        if (!batch.TxnBegin()) throw std::runtime_error("Error: cannot create db transaction for descriptors import");

        for (bool internal : {false, true}) {
            const UniValue& descriptor_vals = signer_res.find_value(internal ? "internal" : "receive");
            if (!descriptor_vals.isArray()) throw std::runtime_error(std::string(__func__) + ": Unexpected result");
            for (const UniValue& desc_val : descriptor_vals.get_array().getValues()) {
                const std::string& desc_str = desc_val.getValStr();
                FlatSigningProvider keys;
                std::string desc_error;
                std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, desc_error, false);
                if (desc == nullptr) {
                    throw std::runtime_error(std::string(__func__) + ": Invalid descriptor \"" + desc_str + "\" (" + desc_error + ")");
                }
                if (!desc->GetOutputType()) {
                    continue;
                }
                OutputType t =  *desc->GetOutputType();
                auto spk_manager = std::unique_ptr<ExternalSignerScriptPubKeyMan>(new ExternalSignerScriptPubKeyMan(*this, m_keypool_size));
                spk_manager->SetupDescriptor(batch, std::move(desc));
                uint256 id = spk_manager->GetID();
                AddScriptPubKeyMan(id, std::move(spk_manager));
                AddActiveScriptPubKeyManWithDb(batch, id, t, internal);
            }
        }

        // Ensure imported descriptors are committed to disk
        if (!batch.TxnCommit()) throw std::runtime_error("Error: cannot commit db transaction for descriptors import");
    }
}

void CWallet::AddActiveScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    WalletBatch batch(GetDatabase());
    return AddActiveScriptPubKeyManWithDb(batch, id, type, internal);
}

void CWallet::AddActiveScriptPubKeyManWithDb(WalletBatch& batch, uint256 id, OutputType type, bool internal)
{
    if (!batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(type), id, internal)) {
        throw std::runtime_error(std::string(__func__) + ": writing active ScriptPubKeyMan id failed");
    }
    LoadActiveScriptPubKeyMan(id, type, internal);
}

void CWallet::LoadActiveScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    // Activating ScriptPubKeyManager for a given output and change type is incompatible with legacy wallets.
    // Legacy wallets have only one ScriptPubKeyManager and it's active for all output and change types.
    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    WalletLogPrintf("Setting spkMan to active: id = %s, type = %s, internal = %s\n", id.ToString(), FormatOutputType(type), internal ? "true" : "false");
    auto& spk_mans = internal ? m_internal_spk_managers : m_external_spk_managers;
    auto& spk_mans_other = internal ? m_external_spk_managers : m_internal_spk_managers;
    auto spk_man = m_spk_managers.at(id).get();
    spk_mans[type] = spk_man;

    const auto it = spk_mans_other.find(type);
    if (it != spk_mans_other.end() && it->second == spk_man) {
        spk_mans_other.erase(type);
    }

    NotifyCanGetAddressesChanged();
}

void CWallet::DeactivateScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    auto spk_man = GetScriptPubKeyMan(type, internal);
    if (spk_man != nullptr && spk_man->GetID() == id) {
        WalletLogPrintf("Deactivate spkMan: id = %s, type = %s, internal = %s\n", id.ToString(), FormatOutputType(type), internal ? "true" : "false");
        WalletBatch batch(GetDatabase());
        if (!batch.EraseActiveScriptPubKeyMan(static_cast<uint8_t>(type), internal)) {
            throw std::runtime_error(std::string(__func__) + ": erasing active ScriptPubKeyMan id failed");
        }

        auto& spk_mans = internal ? m_internal_spk_managers : m_external_spk_managers;
        spk_mans.erase(type);
    }

    NotifyCanGetAddressesChanged();
}

bool CWallet::IsLegacy() const
{
    if (m_internal_spk_managers.count(OutputType::LEGACY) == 0) {
        return false;
    }
    auto spk_man = dynamic_cast<LegacyScriptPubKeyMan*>(m_internal_spk_managers.at(OutputType::LEGACY));
    return spk_man != nullptr;
}

DescriptorScriptPubKeyMan* CWallet::GetDescriptorScriptPubKeyMan(const WalletDescriptor& desc) const
{
    for (auto& spk_man_pair : m_spk_managers) {
        // Try to downcast to DescriptorScriptPubKeyMan then check if the descriptors match
        DescriptorScriptPubKeyMan* spk_manager = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man_pair.second.get());
        if (spk_manager != nullptr && spk_manager->HasWalletDescriptor(desc)) {
            return spk_manager;
        }
    }

    return nullptr;
}

std::optional<bool> CWallet::IsInternalScriptPubKeyMan(ScriptPubKeyMan* spk_man) const
{
    // Legacy script pubkey man can't be either external or internal
    if (IsLegacy()) {
        return std::nullopt;
    }

    // only active ScriptPubKeyMan can be internal
    if (!GetActiveScriptPubKeyMans().count(spk_man)) {
        return std::nullopt;
    }

    const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
    if (!desc_spk_man) {
        throw std::runtime_error(std::string(__func__) + ": unexpected ScriptPubKeyMan type.");
    }

    LOCK(desc_spk_man->cs_desc_man);
    const auto& type = desc_spk_man->GetWalletDescriptor().descriptor->GetOutputType();
    assert(type.has_value());

    return GetScriptPubKeyMan(*type, /* internal= */ true) == desc_spk_man;
}

ScriptPubKeyMan* CWallet::AddWalletDescriptor(WalletDescriptor& desc, const FlatSigningProvider& signing_provider, const std::string& label, bool internal)
{
    AssertLockHeld(cs_wallet);

    if (!IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        WalletLogPrintf("Cannot add WalletDescriptor to a non-descriptor wallet\n");
        return nullptr;
    }

    auto spk_man = GetDescriptorScriptPubKeyMan(desc);
    if (spk_man) {
        WalletLogPrintf("Update existing descriptor: %s\n", desc.descriptor->ToString());
        spk_man->UpdateWalletDescriptor(desc);
    } else {
        auto new_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(*this, desc, m_keypool_size));
        spk_man = new_spk_man.get();

        // Save the descriptor to memory
        uint256 id = new_spk_man->GetID();
        AddScriptPubKeyMan(id, std::move(new_spk_man));
    }

    // Add the private keys to the descriptor
    for (const auto& entry : signing_provider.keys) {
        const CKey& key = entry.second;
        spk_man->AddDescriptorKey(key, key.GetPubKey());
    }

    // Top up key pool, the manager will generate new scriptPubKeys internally
    if (!spk_man->TopUp()) {
        WalletLogPrintf("Could not top up scriptPubKeys\n");
        return nullptr;
    }

    // Apply the label if necessary
    // Note: we disable labels for ranged descriptors
    if (!desc.descriptor->IsRange()) {
        auto script_pub_keys = spk_man->GetScriptPubKeys();
        if (script_pub_keys.empty()) {
            WalletLogPrintf("Could not generate scriptPubKeys (cache is empty)\n");
            return nullptr;
        }

        if (!internal) {
            for (const auto& script : script_pub_keys) {
                CTxDestination dest;
                if (ExtractDestination(script, dest)) {
                    SetAddressBook(dest, label, AddressPurpose::RECEIVE);
                }
            }
        }
    }

    // Save the descriptor to DB
    spk_man->WriteDescriptor();

    return spk_man;
}

bool CWallet::MigrateToSQLite(bilingual_str& error)
{
    AssertLockHeld(cs_wallet);

    WalletLogPrintf("Migrating wallet storage database from BerkeleyDB to SQLite.\n");

    if (m_database->Format() == "sqlite") {
        error = _("Error: This wallet already uses SQLite");
        return false;
    }

    // Get all of the records for DB type migration
    std::unique_ptr<DatabaseBatch> batch = m_database->MakeBatch();
    std::unique_ptr<DatabaseCursor> cursor = batch->GetNewCursor();
    std::vector<std::pair<SerializeData, SerializeData>> records;
    if (!cursor) {
        error = _("Error: Unable to begin reading all records in the database");
        return false;
    }
    DatabaseCursor::Status status = DatabaseCursor::Status::FAIL;
    while (true) {
        DataStream ss_key{};
        DataStream ss_value{};
        status = cursor->Next(ss_key, ss_value);
        if (status != DatabaseCursor::Status::MORE) {
            break;
        }
        SerializeData key(ss_key.begin(), ss_key.end());
        SerializeData value(ss_value.begin(), ss_value.end());
        records.emplace_back(key, value);
    }
    cursor.reset();
    batch.reset();
    if (status != DatabaseCursor::Status::DONE) {
        error = _("Error: Unable to read all records in the database");
        return false;
    }

    // Close this database and delete the file
    fs::path db_path = fs::PathFromString(m_database->Filename());
    m_database->Close();
    fs::remove(db_path);

    // Generate the path for the location of the migrated wallet
    // Wallets that are plain files rather than wallet directories will be migrated to be wallet directories.
    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(m_name));

    // Make new DB
    DatabaseOptions opts;
    opts.require_create = true;
    opts.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus db_status;
    std::unique_ptr<WalletDatabase> new_db = MakeDatabase(wallet_path, opts, db_status, error);
    assert(new_db); // This is to prevent doing anything further with this wallet. The original file was deleted, but a backup exists.
    m_database.reset();
    m_database = std::move(new_db);

    // Write existing records into the new DB
    batch = m_database->MakeBatch();
    bool began = batch->TxnBegin();
    assert(began); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
    for (const auto& [key, value] : records) {
        if (!batch->Write(Span{key}, Span{value})) {
            batch->TxnAbort();
            m_database->Close();
            fs::remove(m_database->Filename());
            assert(false); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
        }
    }
    bool committed = batch->TxnCommit();
    assert(committed); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
    return true;
}

std::optional<MigrationData> CWallet::GetDescriptorsForLegacy(bilingual_str& error) const
{
    AssertLockHeld(cs_wallet);

    LegacyScriptPubKeyMan* legacy_spkm = GetLegacyScriptPubKeyMan();
    if (!Assume(legacy_spkm)) {
        // This shouldn't happen
        error = Untranslated(STR_INTERNAL_BUG("Error: Legacy wallet data missing"));
        return std::nullopt;
    }

    std::optional<MigrationData> res = legacy_spkm->MigrateToDescriptor();
    if (res == std::nullopt) {
        error = _("Error: Unable to produce descriptors for this legacy wallet. Make sure to provide the wallet's passphrase if it is encrypted.");
        return std::nullopt;
    }
    return res;
}

bool CWallet::ApplyMigrationData(MigrationData& data, bilingual_str& error)
{
    AssertLockHeld(cs_wallet);

    LegacyScriptPubKeyMan* legacy_spkm = GetLegacyScriptPubKeyMan();
    if (!Assume(legacy_spkm)) {
        // This shouldn't happen
        error = Untranslated(STR_INTERNAL_BUG("Error: Legacy wallet data missing"));
        return false;
    }

    // Get all invalid or non-watched scripts that will not be migrated
    std::set<CTxDestination> not_migrated_dests;
    for (const auto& script : legacy_spkm->GetNotMineScriptPubKeys()) {
        CTxDestination dest;
        if (ExtractDestination(script, dest)) not_migrated_dests.emplace(dest);
    }

    Assume(!m_cached_spks.empty());

    for (auto& desc_spkm : data.desc_spkms) {
        if (m_spk_managers.count(desc_spkm->GetID()) > 0) {
            error = _("Error: Duplicate descriptors created during migration. Your wallet may be corrupted.");
            return false;
        }
        uint256 id = desc_spkm->GetID();
        AddScriptPubKeyMan(id, std::move(desc_spkm));
    }

    // Remove the LegacyScriptPubKeyMan from disk
    if (!legacy_spkm->DeleteRecords()) {
        return false;
    }

    // Remove the LegacyScriptPubKeyMan from memory
    m_spk_managers.erase(legacy_spkm->GetID());
    m_external_spk_managers.clear();
    m_internal_spk_managers.clear();

    // Setup new descriptors
    SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    if (!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        // Use the existing master key if we have it
        if (data.master_key.key.IsValid()) {
            SetupDescriptorScriptPubKeyMans(data.master_key);
        } else {
            // Setup with a new seed if we don't.
            SetupDescriptorScriptPubKeyMans();
        }
    }

    // Get best block locator so that we can copy it to the watchonly and solvables
    CBlockLocator best_block_locator;
    if (!WalletBatch(GetDatabase()).ReadBestBlock(best_block_locator)) {
        error = _("Error: Unable to read wallet's best block locator record");
        return false;
    }

    // Check if the transactions in the wallet are still ours. Either they belong here, or they belong in the watchonly wallet.
    // We need to go through these in the tx insertion order so that lookups to spends works.
    std::vector<uint256> txids_to_delete;
    std::unique_ptr<WalletBatch> watchonly_batch;
    if (data.watchonly_wallet) {
        watchonly_batch = std::make_unique<WalletBatch>(data.watchonly_wallet->GetDatabase());
        // Copy the next tx order pos to the watchonly wallet
        LOCK(data.watchonly_wallet->cs_wallet);
        data.watchonly_wallet->nOrderPosNext = nOrderPosNext;
        watchonly_batch->WriteOrderPosNext(data.watchonly_wallet->nOrderPosNext);
        // Write the best block locator to avoid rescanning on reload
        if (!watchonly_batch->WriteBestBlock(best_block_locator)) {
            error = _("Error: Unable to write watchonly wallet best block locator record");
            return false;
        }
    }
    if (data.solvable_wallet) {
        // Write the best block locator to avoid rescanning on reload
        if (!WalletBatch(data.solvable_wallet->GetDatabase()).WriteBestBlock(best_block_locator)) {
            error = _("Error: Unable to write solvable wallet best block locator record");
            return false;
        }
    }
    for (const auto& [_pos, wtx] : wtxOrdered) {
        // Check it is the watchonly wallet's
        // solvable_wallet doesn't need to be checked because transactions for those scripts weren't being watched for
        bool is_mine = IsMine(*wtx->tx) || IsFromMe(*wtx->tx);
        if (data.watchonly_wallet) {
            LOCK(data.watchonly_wallet->cs_wallet);
            if (data.watchonly_wallet->IsMine(*wtx->tx) || data.watchonly_wallet->IsFromMe(*wtx->tx)) {
                // Add to watchonly wallet
                const uint256& hash = wtx->GetHash();
                const CWalletTx& to_copy_wtx = *wtx;
                if (!data.watchonly_wallet->LoadToWallet(hash, [&](CWalletTx& ins_wtx, bool new_tx) EXCLUSIVE_LOCKS_REQUIRED(data.watchonly_wallet->cs_wallet) {
                    if (!new_tx) return false;
                    ins_wtx.SetTx(to_copy_wtx.tx);
                    ins_wtx.CopyFrom(to_copy_wtx);
                    return true;
                })) {
                    error = strprintf(_("Error: Could not add watchonly tx %s to watchonly wallet"), wtx->GetHash().GetHex());
                    return false;
                }
                watchonly_batch->WriteTx(data.watchonly_wallet->mapWallet.at(hash));
                // Mark as to remove from the migrated wallet only if it does not also belong to it
                if (!is_mine) {
                    txids_to_delete.push_back(hash);
                }
                continue;
            }
        }
        if (!is_mine) {
            // Both not ours and not in the watchonly wallet
            error = strprintf(_("Error: Transaction %s in wallet cannot be identified to belong to migrated wallets"), wtx->GetHash().GetHex());
            return false;
        }
    }
    watchonly_batch.reset(); // Flush
    // Do the removes
    if (txids_to_delete.size() > 0) {
        if (auto res = RemoveTxs(txids_to_delete); !res) {
            error = _("Error: Could not delete watchonly transactions. ") + util::ErrorString(res);
            return false;
        }
    }

    // Pair external wallets with their corresponding db handler
    std::vector<std::pair<std::shared_ptr<CWallet>, std::unique_ptr<WalletBatch>>> wallets_vec;
    for (const auto& ext_wallet : {data.watchonly_wallet, data.solvable_wallet}) {
        if (!ext_wallet) continue;

        std::unique_ptr<WalletBatch> batch = std::make_unique<WalletBatch>(ext_wallet->GetDatabase());
        if (!batch->TxnBegin()) {
            error = strprintf(_("Error: database transaction cannot be executed for wallet %s"), ext_wallet->GetName());
            return false;
        }
        wallets_vec.emplace_back(ext_wallet, std::move(batch));
    }

    // Write address book entry to disk
    auto func_store_addr = [](WalletBatch& batch, const CTxDestination& dest, const CAddressBookData& entry) {
        auto address{EncodeDestination(dest)};
        if (entry.purpose) batch.WritePurpose(address, PurposeToString(*entry.purpose));
        if (entry.label) batch.WriteName(address, *entry.label);
        for (const auto& [id, request] : entry.receive_requests) {
            batch.WriteAddressReceiveRequest(dest, id, request);
        }
        if (entry.previously_spent) batch.WriteAddressPreviouslySpent(dest, true);
    };

    // Check the address book data in the same way we did for transactions
    std::vector<CTxDestination> dests_to_delete;
    for (const auto& [dest, record] : m_address_book) {
        // Ensure "receive" entries that are no longer part of the original wallet are transferred to another wallet
        // Entries for everything else ("send") will be cloned to all wallets.
        bool require_transfer = record.purpose == AddressPurpose::RECEIVE && !IsMine(dest);
        bool copied = false;
        for (auto& [wallet, batch] : wallets_vec) {
            LOCK(wallet->cs_wallet);
            if (require_transfer && !wallet->IsMine(dest)) continue;

            // Copy the entire address book entry
            wallet->m_address_book[dest] = record;
            func_store_addr(*batch, dest, record);

            copied = true;
            // Only delete 'receive' records that are no longer part of the original wallet
            if (require_transfer) {
                dests_to_delete.push_back(dest);
                break;
            }
        }

        // Fail immediately if we ever found an entry that was ours and cannot be transferred
        // to any of the created wallets (watch-only, solvable).
        // Means that no inferred descriptor maps to the stored entry. Which mustn't happen.
        if (require_transfer && !copied) {

            // Skip invalid/non-watched scripts that will not be migrated
            if (not_migrated_dests.count(dest) > 0) {
                dests_to_delete.push_back(dest);
                continue;
            }

            error = _("Error: Address book data in wallet cannot be identified to belong to migrated wallets");
            return false;
        }
    }

    // Persist external wallets address book entries
    for (auto& [wallet, batch] : wallets_vec) {
        if (!batch->TxnCommit()) {
            error = strprintf(_("Error: address book copy failed for wallet %s"), wallet->GetName());
            return false;
        }
    }

    // Remove the things to delete in this wallet
    WalletBatch local_wallet_batch(GetDatabase());
    local_wallet_batch.TxnBegin();
    if (dests_to_delete.size() > 0) {
        for (const auto& dest : dests_to_delete) {
            if (!DelAddressBookWithDB(local_wallet_batch, dest)) {
                error = _("Error: Unable to remove watchonly address book data");
                return false;
            }
        }
    }
    local_wallet_batch.TxnCommit();

    // Connect the SPKM signals
    ConnectScriptPubKeyManNotifiers();
    NotifyCanGetAddressesChanged();

    WalletLogPrintf("Wallet migration complete.\n");

    return true;
}

bool CWallet::CanGrindR() const
{
    return !IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER);
}

bool DoMigration(CWallet& wallet, WalletContext& context, bilingual_str& error, MigrationResult& res) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    // Get all of the descriptors from the legacy wallet
    std::optional<MigrationData> data = wallet.GetDescriptorsForLegacy(error);
    if (data == std::nullopt) return false;

    // Create the watchonly and solvable wallets if necessary
    if (data->watch_descs.size() > 0 || data->solvable_descs.size() > 0) {
        DatabaseOptions options;
        options.require_existing = false;
        options.require_create = true;
        options.require_format = DatabaseFormat::SQLITE;

        WalletContext empty_context;
        empty_context.args = context.args;
        const SecureString empty_bip39_passphrase;

        // Make the wallets
        options.create_flags = WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET | WALLET_FLAG_DESCRIPTORS;
        if (wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            options.create_flags |= WALLET_FLAG_AVOID_REUSE;
        }
        if (wallet.IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
            options.create_flags |= WALLET_FLAG_KEY_ORIGIN_METADATA;
        }
        if (data->watch_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the watched scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = wallet.GetName() + "_watchonly";
            std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
            if (!database) {
                error = strprintf(_("Wallet file creation failed: %s"), error);
                return false;
            }

            data->watchonly_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, empty_bip39_passphrase, error, warnings);
            if (!data->watchonly_wallet) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.watchonly_wallet = data->watchonly_wallet;
            LOCK(data->watchonly_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->watch_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, parse_err, /* require_checksum */ true);
                assert(desc); // It shouldn't be possible to have the LegacyScriptPubKeyMan make an invalid descriptor
                assert(!desc->IsRange()); // It shouldn't be possible to have LegacyScriptPubKeyMan make a ranged watchonly descriptor

                // Add to the wallet
                WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
                data->watchonly_wallet->AddWalletDescriptor(w_desc, keys, "", false);
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, /*load_on_startup=*/true, warnings);
        }
        if (data->solvable_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the unwatched solvable scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = wallet.GetName() + "_solvables";
            std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
            if (!database) {
                error = strprintf(_("Wallet file creation failed: %s"), error);
                return false;
            }

            data->solvable_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, empty_bip39_passphrase, error, warnings);
            if (!data->solvable_wallet) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.solvables_wallet = data->solvable_wallet;
            LOCK(data->solvable_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->solvable_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, parse_err, /* require_checksum */ true);
                assert(desc); // It shouldn't be possible to have the LegacyScriptPubKeyMan make an invalid descriptor
                assert(!desc->IsRange()); // It shouldn't be possible to have LegacyScriptPubKeyMan make a ranged watchonly descriptor

                // Add to the wallet
                WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
                data->solvable_wallet->AddWalletDescriptor(w_desc, keys, "", false);
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, /*load_on_startup=*/true, warnings);
        }
    }

    // Add the descriptors to wallet, remove LegacyScriptPubKeyMan, and cleanup txs and address book data
    if (!wallet.ApplyMigrationData(*data, error)) {
        return false;
    }
    return true;
}

util::Result<MigrationResult> MigrateLegacyToDescriptor(const std::string& wallet_name, const SecureString& passphrase, WalletContext& context)
{
    MigrationResult res;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    // If the wallet is still loaded, unload it so that nothing else tries to use it while we're changing it
    bool was_loaded = false;
    if (auto wallet = GetWallet(context, wallet_name)) {
        if (!RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt, warnings)) {
            return util::Error{_("Unable to unload the wallet before migrating")};
        }
        UnloadWallet(std::move(wallet));
        was_loaded = true;
    }

    // Load the wallet but only in the context of this function.
    // No signals should be connected nor should anything else be aware of this wallet
    WalletContext empty_context;
    empty_context.args = context.args;
    DatabaseOptions options;
    options.require_existing = true;
    const SecureString empty_bip39_passphrase;
    DatabaseStatus status;
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
    if (!database) {
        return util::Error{Untranslated("Wallet file verification failed.") + Untranslated(" ") + error};
    }

    // Make the local wallet
    std::shared_ptr<CWallet> local_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, empty_bip39_passphrase, error, warnings);
    if (!local_wallet) {
        return util::Error{_("Wallet loading failed.") + Untranslated(" ") + error};
    }

    // Helper to reload as normal for some of our exit scenarios
    const auto& reload_wallet = [&](std::shared_ptr<CWallet>& to_reload) {
        assert(to_reload.use_count() == 1);
        std::string name = to_reload->GetName();
        to_reload.reset();
        to_reload = LoadWallet(context, name, /*load_on_start=*/std::nullopt, options, status, error, warnings);
        return to_reload != nullptr;
    };

    // Before anything else, check if there is something to migrate.
    if (local_wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        if (was_loaded) {
            reload_wallet(local_wallet);
        }
        return util::Error{_("Error: This wallet is already a descriptor wallet")};
    }

    const bool has_private_root{WITH_LOCK(local_wallet->cs_wallet, return local_wallet->HasCanonicalPrivateHDSeed())};
    if (has_private_root) {
        if (was_loaded) {
            reload_wallet(local_wallet);
        }
        return util::Error{Untranslated("Error: migratewallet is disabled after an Orchard root has been added. Keep using the legacy wallet directly so its transparent and Orchard keys remain intact.")};
    }

    // Make a backup of the DB
    fs::path this_wallet_dir = fs::absolute(fs::PathFromString(local_wallet->GetDatabase().Filename())).parent_path();
    fs::path backup_filename = fs::PathFromString(strprintf("%s-%d.legacy.bak", wallet_name, GetTime()));
    fs::path backup_path = this_wallet_dir / backup_filename;
    if (!local_wallet->BackupWallet(fs::PathToString(backup_path))) {
        if (was_loaded) {
            reload_wallet(local_wallet);
        }
        return util::Error{_("Error: Unable to make a backup of your wallet")};
    }
    res.backup_path = backup_path;

    bool success = false;

    // Unlock the wallet if needed
    if (local_wallet->IsLocked() && !local_wallet->Unlock(passphrase)) {
        if (was_loaded) {
            reload_wallet(local_wallet);
        }
        if (passphrase.find('\0') == std::string::npos) {
            return util::Error{Untranslated("Error: Wallet decryption failed, the wallet passphrase was not provided or was incorrect.")};
        } else {
            return util::Error{Untranslated("Error: Wallet decryption failed, the wallet passphrase entered was incorrect. "
                                            "The passphrase contains a null character (ie - a zero byte). "
                                            "If this passphrase was set with a version of this software prior to 25.0, "
                                            "please try again with only the characters up to — but not including — "
                                            "the first null character.")};
        }
    }

    {
        LOCK(local_wallet->cs_wallet);
        // First change to using SQLite
        if (!local_wallet->MigrateToSQLite(error)) return util::Error{error};

        // Do the migration of keys and scripts for non-blank wallets, and cleanup if it fails
        success = local_wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET);
        if (!success) {
            success = DoMigration(*local_wallet, context, error, res);
        } else {
            // Make sure that descriptors flag is actually set
            local_wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        }
    }

    // In case of reloading failure, we need to remember the wallet dirs to remove
    // Set is used as it may be populated with the same wallet directory paths multiple times,
    // both before and after reloading. This ensures the set is complete even if one of the wallets
    // fails to reload.
    std::set<fs::path> wallet_dirs;
    if (success) {
        // Migration successful, unload all wallets locally, then reload them.
        // Reload the main wallet
        wallet_dirs.insert(fs::PathFromString(local_wallet->GetDatabase().Filename()).parent_path());
        success = reload_wallet(local_wallet);
        res.wallet = local_wallet;
        res.wallet_name = wallet_name;
        if (success && res.watchonly_wallet) {
            // Reload watchonly
            wallet_dirs.insert(fs::PathFromString(res.watchonly_wallet->GetDatabase().Filename()).parent_path());
            success = reload_wallet(res.watchonly_wallet);
        }
        if (success && res.solvables_wallet) {
            // Reload solvables
            wallet_dirs.insert(fs::PathFromString(res.solvables_wallet->GetDatabase().Filename()).parent_path());
            success = reload_wallet(res.solvables_wallet);
        }
    }
    if (!success) {
        // Migration failed, cleanup
        // Copy the backup to the actual wallet dir
        fs::path temp_backup_location = fsbridge::AbsPathJoin(GetWalletDir(), backup_filename);
        fs::copy_file(backup_path, temp_backup_location, fs::copy_options::none);

        // Make list of wallets to cleanup
        std::vector<std::shared_ptr<CWallet>> created_wallets;
        if (local_wallet) created_wallets.push_back(std::move(local_wallet));
        if (res.watchonly_wallet) created_wallets.push_back(std::move(res.watchonly_wallet));
        if (res.solvables_wallet) created_wallets.push_back(std::move(res.solvables_wallet));

        // Get the directories to remove after unloading
        for (std::shared_ptr<CWallet>& w : created_wallets) {
            wallet_dirs.emplace(fs::PathFromString(w->GetDatabase().Filename()).parent_path());
        }

        // Unload the wallets
        for (std::shared_ptr<CWallet>& w : created_wallets) {
            if (w->HaveChain()) {
                // Unloading for wallets that were loaded for normal use
                if (!RemoveWallet(context, w, /*load_on_start=*/false)) {
                    error += _("\nUnable to cleanup failed migration");
                    return util::Error{error};
                }
                UnloadWallet(std::move(w));
            } else {
                // Unloading for wallets in local context
                assert(w.use_count() == 1);
                w.reset();
            }
        }

        // Delete the wallet directories
        for (const fs::path& dir : wallet_dirs) {
            fs::remove_all(dir);
        }

        // Restore the backup
        DatabaseStatus status;
        std::vector<bilingual_str> warnings;
        if (!RestoreWallet(context, temp_backup_location, wallet_name, /*load_on_start=*/std::nullopt, status, error, warnings)) {
            error += _("\nUnable to restore backup of wallet.");
            return util::Error{error};
        }

        // Move the backup to the wallet dir
        fs::copy_file(temp_backup_location, backup_path, fs::copy_options::none);
        fs::remove(temp_backup_location);

        return util::Error{error};
    }
    return res;
}

void CWallet::CacheNewScriptPubKeys(const std::set<CScript>& spks, ScriptPubKeyMan* spkm)
{
    for (const auto& script : spks) {
        m_cached_spks[script].push_back(spkm);
    }
}

void CWallet::TopUpCallback(const std::set<CScript>& spks, ScriptPubKeyMan* spkm)
{
    // Update scriptPubKey cache
    CacheNewScriptPubKeys(spks, spkm);
}
} // namespace wallet
