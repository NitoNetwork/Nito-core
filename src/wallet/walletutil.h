// Copyright (c) 2017-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETUTIL_H
#define BITCOIN_WALLET_WALLETUTIL_H

#include <script/descriptor.h>
#include <util/fs.h>
#include <util/translation.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
/** Shared recovery guidance: localized for Qt, original English for RPC. */
bilingual_str PrunedWalletRecoveryError();

/** (client) version numbers for particular wallet features */
enum WalletFeature
{
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getwalletinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys

    FEATURE_HD = 130000, // Hierarchical key derivation after BIP32 (HD Wallet)

    FEATURE_HD_SPLIT = 139900, // Wallet with HD chain split (change outputs will use m/0'/1'/k)

    FEATURE_NO_DEFAULT_KEY = 159900, // Wallet without a default key written

    FEATURE_PRE_SPLIT_KEYPOOL = 169900, // Upgraded to HD SPLIT and can have a pre-split keypool

    FEATURE_LATEST = FEATURE_PRE_SPLIT_KEYPOOL
};

bool IsFeatureSupported(int wallet_version, int feature_version);
WalletFeature GetClosestWalletFeature(int version);

enum class SeedHistoryMode : uint8_t {
    UNKNOWN = 0,
    AVAILABLE_BALANCE = 1,
    FULL_HISTORY = 2,
};

enum class SeedRecoveryStatus : uint8_t {
    UNKNOWN = 0,
    NOT_APPLICABLE = 1,
    NOT_REQUESTED = 2,
    PENDING = 3,
    COMPLETE = 4,
    FAILED = 5,
};

/** Persistent status and exact chain target for one recovery obligation. */
class SeedRecoveryProgress
{
public:
    SeedRecoveryStatus m_status{SeedRecoveryStatus::NOT_APPLICABLE};
    int m_height{-1};
    uint256 m_block{};

    bool HasTarget() const { return m_height >= 0 && !m_block.IsNull(); }

    bool IsValid() const
    {
        switch (m_status) {
        case SeedRecoveryStatus::UNKNOWN:
        case SeedRecoveryStatus::NOT_APPLICABLE:
        case SeedRecoveryStatus::NOT_REQUESTED:
            return m_height == -1 && m_block.IsNull();
        case SeedRecoveryStatus::PENDING:
        case SeedRecoveryStatus::COMPLETE:
        case SeedRecoveryStatus::FAILED:
            return HasTarget();
        }
        return false;
    }

    std::string StatusString() const
    {
        switch (m_status) {
        case SeedRecoveryStatus::NOT_APPLICABLE: return "not_applicable";
        case SeedRecoveryStatus::NOT_REQUESTED: return "not_requested";
        case SeedRecoveryStatus::PENDING: return "pending";
        case SeedRecoveryStatus::COMPLETE: return "complete";
        case SeedRecoveryStatus::FAILED: return "failed";
        case SeedRecoveryStatus::UNKNOWN:
            break;
        }
        return "unknown";
    }

    static SeedRecoveryProgress WithoutTarget(SeedRecoveryStatus status)
    {
        SeedRecoveryProgress progress;
        progress.m_status = status;
        return progress;
    }

    static SeedRecoveryProgress At(SeedRecoveryStatus status, int height, const uint256& block_hash)
    {
        SeedRecoveryProgress progress;
        progress.m_status = status;
        progress.m_height = height;
        progress.m_block = block_hash;
        return progress;
    }

    SERIALIZE_METHODS(SeedRecoveryProgress, obj)
    {
        uint8_t status{static_cast<uint8_t>(obj.m_status)};
        READWRITE(status, obj.m_height, obj.m_block);
        SER_READ(obj, obj.m_status = static_cast<SeedRecoveryStatus>(status));
    }
};

class SeedRecoveryDomainState
{
public:
    SeedRecoveryProgress m_restore_funds;
    SeedRecoveryProgress m_explicit_history;

    bool IsValid() const { return m_restore_funds.IsValid() && m_explicit_history.IsValid(); }

    SERIALIZE_METHODS(SeedRecoveryDomainState, obj)
    {
        READWRITE(obj.m_restore_funds, obj.m_explicit_history);
    }
};

/** Persisted recovery-phrase history state for Nito descriptor wallets. */
class SeedHistoryState
{
public:
    static constexpr uint8_t CURRENT_VERSION{2};

    uint8_t m_version{CURRENT_VERSION};
    SeedHistoryMode m_mode{SeedHistoryMode::UNKNOWN};
    int m_full_history_height{-1};
    uint256 m_full_history_block{};
    SeedRecoveryDomainState m_transparent;
    SeedRecoveryDomainState m_orchard;

    bool IsValid() const
    {
        if (m_version != CURRENT_VERSION) return false;
        if (m_mode != SeedHistoryMode::UNKNOWN &&
            m_mode != SeedHistoryMode::AVAILABLE_BALANCE &&
            m_mode != SeedHistoryMode::FULL_HISTORY) {
            return false;
        }
        if (m_mode == SeedHistoryMode::FULL_HISTORY) {
            if (m_full_history_height < 0 || m_full_history_block.IsNull()) return false;
        } else if (m_full_history_height != -1 || !m_full_history_block.IsNull()) {
            return false;
        }
        return m_transparent.IsValid() && m_orchard.IsValid();
    }

    std::string ModeString() const
    {
        switch (m_mode) {
        case SeedHistoryMode::AVAILABLE_BALANCE: return "available_balance";
        case SeedHistoryMode::FULL_HISTORY: return "full_history";
        case SeedHistoryMode::UNKNOWN:
            break;
        }
        return "unknown";
    }

    bool FundsRecoveryComplete() const
    {
        const auto complete_or_inapplicable = [](const SeedRecoveryProgress& progress) {
            return progress.m_status == SeedRecoveryStatus::COMPLETE ||
                   progress.m_status == SeedRecoveryStatus::NOT_APPLICABLE;
        };
        return complete_or_inapplicable(m_transparent.m_restore_funds) &&
               complete_or_inapplicable(m_orchard.m_restore_funds);
    }

    bool FundsRecoveryPending() const
    {
        return m_transparent.m_restore_funds.m_status == SeedRecoveryStatus::PENDING ||
               m_orchard.m_restore_funds.m_status == SeedRecoveryStatus::PENDING;
    }

    static SeedHistoryState AvailableBalance(int height, const uint256& block_hash, bool orchard_applicable)
    {
        SeedHistoryState state;
        state.m_mode = SeedHistoryMode::AVAILABLE_BALANCE;
        state.m_transparent.m_restore_funds = SeedRecoveryProgress::At(SeedRecoveryStatus::PENDING, height, block_hash);
        state.m_transparent.m_explicit_history = SeedRecoveryProgress::WithoutTarget(SeedRecoveryStatus::NOT_REQUESTED);
        state.m_orchard.m_restore_funds = orchard_applicable ?
            SeedRecoveryProgress::At(SeedRecoveryStatus::PENDING, height, block_hash) :
            SeedRecoveryProgress::WithoutTarget(SeedRecoveryStatus::NOT_APPLICABLE);
        state.m_orchard.m_explicit_history = orchard_applicable ?
            SeedRecoveryProgress::WithoutTarget(SeedRecoveryStatus::NOT_REQUESTED) :
            SeedRecoveryProgress::WithoutTarget(SeedRecoveryStatus::NOT_APPLICABLE);
        return state;
    }

    static SeedHistoryState FullHistory(int height, const uint256& block_hash, bool orchard_applicable = true)
    {
        SeedHistoryState state;
        state.m_mode = SeedHistoryMode::FULL_HISTORY;
        state.m_full_history_height = height;
        state.m_full_history_block = block_hash;
        state.m_transparent.m_restore_funds = SeedRecoveryProgress::At(SeedRecoveryStatus::COMPLETE, height, block_hash);
        state.m_transparent.m_explicit_history = SeedRecoveryProgress::At(SeedRecoveryStatus::COMPLETE, height, block_hash);
        state.m_orchard.m_restore_funds = orchard_applicable ?
            SeedRecoveryProgress::At(SeedRecoveryStatus::COMPLETE, height, block_hash) :
            SeedRecoveryProgress::WithoutTarget(SeedRecoveryStatus::NOT_APPLICABLE);
        state.m_orchard.m_explicit_history = orchard_applicable ?
            SeedRecoveryProgress::At(SeedRecoveryStatus::COMPLETE, height, block_hash) :
            SeedRecoveryProgress::WithoutTarget(SeedRecoveryStatus::NOT_APPLICABLE);
        return state;
    }

    void MarkFunds(bool orchard, SeedRecoveryStatus status, int height, const uint256& block_hash)
    {
        SeedRecoveryDomainState& domain{orchard ? m_orchard : m_transparent};
        domain.m_restore_funds = SeedRecoveryProgress::At(status, height, block_hash);
    }

    void MarkHistory(bool orchard, SeedRecoveryStatus status, int height, const uint256& block_hash)
    {
        SeedRecoveryDomainState& domain{orchard ? m_orchard : m_transparent};
        domain.m_explicit_history = SeedRecoveryProgress::At(status, height, block_hash);
    }

    SERIALIZE_METHODS(SeedHistoryState, obj)
    {
        SER_WRITE(obj, {
            const uint8_t version{CURRENT_VERSION};
            const uint8_t mode{static_cast<uint8_t>(obj.m_mode)};
            s << version << mode << obj.m_full_history_height << obj.m_full_history_block;
            s << obj.m_transparent << obj.m_orchard;
        });
        SER_READ(obj, {
            uint8_t mode{0};
            s >> obj.m_version;
            if (obj.m_version != CURRENT_VERSION) {
                throw std::ios_base::failure("Unsupported seed history state version");
            }
            s >> mode >> obj.m_full_history_height >> obj.m_full_history_block;
            obj.m_mode = static_cast<SeedHistoryMode>(mode);
            s >> obj.m_transparent >> obj.m_orchard;
        });
    }
};

enum WalletFlags : uint64_t {
    // wallet flags in the upper section (> 1 << 31) will lead to not opening the wallet if flag is unknown
    // unknown wallet flags in the lower section <= (1 << 31) will be tolerated

    // will categorize coins as clean (not reused) and dirty (reused), and handle
    // them with privacy considerations in mind
    WALLET_FLAG_AVOID_REUSE = (1ULL << 0),

    // Indicates that the metadata has already been upgraded to contain key origins
    WALLET_FLAG_KEY_ORIGIN_METADATA = (1ULL << 1),

    // Indicates that the descriptor cache has been upgraded to cache last hardened xpubs
    WALLET_FLAG_LAST_HARDENED_XPUB_CACHED = (1ULL << 2),

    // will enforce the rule that the wallet can't contain any private keys (only watch-only/pubkeys)
    WALLET_FLAG_DISABLE_PRIVATE_KEYS = (1ULL << 32),

    //! Flag set when a wallet contains no HD seed and no private keys, scripts,
    //! addresses, and other watch only things, and is therefore "blank."
    //!
    //! The main function this flag serves is to distinguish a blank wallet from
    //! a newly created wallet when the wallet database is loaded, to avoid
    //! initialization that should only happen on first run.
    //!
    //! A secondary function of this flag, which applies to descriptor wallets
    //! only, is to serve as an ongoing indication that descriptors in the
    //! wallet should be created manually, and that the wallet should not
    //! generate automatically generate new descriptors if it is later
    //! encrypted. To support this behavior, descriptor wallets unlike legacy
    //! wallets do not automatically unset the BLANK flag when things are
    //! imported.
    //!
    //! This flag is also a mandatory flag to prevent previous versions of
    //! nito from opening the wallet, thinking it was newly created, and
    //! then improperly reinitializing it.
    WALLET_FLAG_BLANK_WALLET = (1ULL << 33),

    //! Indicate that this wallet supports DescriptorScriptPubKeyMan
    WALLET_FLAG_DESCRIPTORS = (1ULL << 34),

    //! Indicates that the wallet needs an external signer
    WALLET_FLAG_EXTERNAL_SIGNER = (1ULL << 35),

    //! Indicates that the final 64-byte BIP39 seed is persisted in the
    //! versioned derived-seed record. Older clients must refuse this flag
    //! rather than silently deriving with an empty BIP39 passphrase.
    WALLET_FLAG_BIP39_DERIVED_SEED = (1ULL << 36),
};

//! Get the path of the wallet directory.
fs::path GetWalletDir();

/** Descriptor with some wallet metadata */
class WalletDescriptor
{
public:
    std::shared_ptr<Descriptor> descriptor;
    uint256 id; // Descriptor ID (calculated once at descriptor initialization/deserialization)
    uint64_t creation_time = 0;
    int32_t range_start = 0; // First item in range; start of range, inclusive, i.e. [range_start, range_end). This never changes.
    int32_t range_end = 0; // Item after the last; end of range, exclusive, i.e. [range_start, range_end). This will increment with each TopUp()
    int32_t next_index = 0; // Position of the next item to generate
    DescriptorCache cache;

    void DeserializeDescriptor(const std::string& str)
    {
        std::string error;
        FlatSigningProvider keys;
        descriptor = Parse(str, keys, error, true);
        if (!descriptor) {
            throw std::ios_base::failure("Invalid descriptor: " + error);
        }
        id = DescriptorID(*descriptor);
    }

    SERIALIZE_METHODS(WalletDescriptor, obj)
    {
        std::string descriptor_str;
        SER_WRITE(obj, descriptor_str = obj.descriptor->ToString());
        READWRITE(descriptor_str, obj.creation_time, obj.next_index, obj.range_start, obj.range_end);
        SER_READ(obj, obj.DeserializeDescriptor(descriptor_str));
    }

    WalletDescriptor() {}
    WalletDescriptor(std::shared_ptr<Descriptor> descriptor, uint64_t creation_time, int32_t range_start, int32_t range_end, int32_t next_index) : descriptor(descriptor), id(DescriptorID(*descriptor)), creation_time(creation_time), range_start(range_start), range_end(range_end), next_index(next_index) { }
};
} // namespace wallet

#endif // BITCOIN_WALLET_WALLETUTIL_H
