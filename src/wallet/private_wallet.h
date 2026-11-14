// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRIVATE_WALLET_H
#define BITCOIN_WALLET_PRIVATE_WALLET_H

#include <key.h>
#include <private/private_address.h>
#include <private/orchard_verifier.h>
#include <serialize.h>
#include <wallet/bip39.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

class CKey;
class CChainParams;

namespace wallet {

static constexpr size_t NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE = 32;
static constexpr uint32_t NITO_PRIVATE_ORCHARD_PURPOSE = 96U;
static constexpr uint32_t NITO_PRIVATE_ORCHARD_COIN_TYPE = 0U;
static constexpr uint32_t NITO_PRIVATE_ORCHARD_EXTERNAL_BRANCH = 0U;
static constexpr uint32_t NITO_PRIVATE_ORCHARD_INTERNAL_BRANCH = 1U;
static constexpr uint32_t NITO_PRIVATE_ORCHARD_LIVE_LOOKAHEAD = 32U;
static constexpr uint32_t NITO_PRIVATE_ORCHARD_RECOVERY_GAP_LIMIT = 64U;
static constexpr uint32_t NITO_PRIVATE_ORCHARD_LOOKAHEAD = NITO_PRIVATE_ORCHARD_RECOVERY_GAP_LIMIT;
static constexpr uint32_t NITO_PRIVATE_ORCHARD_DERIVATION_VERSION = 1U;
static constexpr const char* NITO_PRIVATE_ORCHARD_DERIVATION_ID = "nito_orchard_derivation";
static constexpr const char* NITO_PRIVATE_ORCHARD_DERIVATION_SPEC = "Nito.network-Orchard96-branch-diversifier";

struct PrivateOrchardKeyPath {
    uint32_t account{0};
    bool internal{false};
    uint32_t diversifier_index{0};
    uint32_t derivation_version{NITO_PRIVATE_ORCHARD_DERIVATION_VERSION};

    std::string ToString() const;
};

enum class PrivateSeedScope : uint8_t {
    UNKNOWN = 0,
    FULL_WALLET = 1,
    ORCHARD_ONLY = 2,
};

/** Exact, generation-aware work item for a deferred Orchard scan. */
class CPrivateScanObligation
{
public:
    int32_t start_height{-1};
    uint256 start_block{};
    int32_t target_height{-1};
    uint256 target_block{};
    uint64_t generation{0};

    bool IsPending() const { return start_height >= 0; }
    bool HasExactTarget() const
    {
        return IsPending() && !start_block.IsNull() && target_height >= start_height && !target_block.IsNull();
    }
    void Mark(int32_t first_height, const uint256& first_block, int32_t stop_height, const uint256& stop_block)
    {
        if (!IsPending() || first_height < start_height || start_block.IsNull()) {
            start_height = first_height;
            start_block = first_block;
        }
        target_height = stop_height;
        target_block = stop_block;
        ++generation;
        if (generation == 0) generation = 1;
    }
    void Clear()
    {
        start_height = -1;
        start_block.SetNull();
        target_height = -1;
        target_block.SetNull();
    }

    SERIALIZE_METHODS(CPrivateScanObligation, obj)
    {
        READWRITE(obj.start_height, obj.start_block, obj.target_height, obj.target_block, obj.generation);
    }
};

class CPrivateWalletChain
{
public:
    static constexpr int VERSION_BASE = 1;
    static constexpr int VERSION_DERIVATION = 2;
    static constexpr int VERSION_HD_SEED = 3;
    static constexpr int VERSION_VIEWING_KEYS = 4;
    static constexpr int VERSION_SEED_SCOPE = 5;
    static constexpr int VERSION_PRIVATE_SCAN_PENDING = 6;
    static constexpr int VERSION_PRIVATE_SCAN_OBLIGATIONS = 7;
    static constexpr int CURRENT_VERSION = VERSION_PRIVATE_SCAN_OBLIGATIONS;

    int nVersion{CURRENT_VERSION};
    uint32_t derivation_version{NITO_PRIVATE_ORCHARD_DERIVATION_VERSION};
    CKeyID hd_seed_id;
    PrivateSeedScope seed_scope{PrivateSeedScope::UNKNOWN};
    uint32_t account{0};
    uint32_t next_external_index{0};
    uint32_t next_internal_index{0};
    bool has_external_full_viewing_key{false};
    bool has_internal_full_viewing_key{false};
    std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE> external_full_viewing_key{};
    std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE> internal_full_viewing_key{};
    /** Compatibility mirror of the earliest obligation height. */
    int32_t private_scan_pending_height{-1};
    CPrivateScanObligation private_restore_scan;
    CPrivateScanObligation private_locked_live_scan;

    bool IsSupported() const;
    void Normalize();
    uint32_t NextIndex(bool internal) const;
    void MarkUsed(bool internal, uint32_t index);
    bool HasFullViewingKey(bool internal) const;
    const std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& FullViewingKey(bool internal) const;
    void SetFullViewingKey(bool internal, const std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& full_viewing_key);

    SERIALIZE_METHODS(CPrivateWalletChain, obj)
    {
        SER_WRITE(obj, {
            const int nVersion{CURRENT_VERSION};
            const uint32_t derivation_version{
                obj.derivation_version == 0 ? NITO_PRIVATE_ORCHARD_DERIVATION_VERSION : obj.derivation_version};
            s << nVersion << obj.account << obj.next_external_index << obj.next_internal_index << derivation_version << obj.hd_seed_id;
            s << static_cast<uint8_t>(obj.seed_scope);
            s << obj.has_external_full_viewing_key << obj.has_internal_full_viewing_key;
            if (obj.has_external_full_viewing_key) {
                s << obj.external_full_viewing_key;
            }
            if (obj.has_internal_full_viewing_key) {
                s << obj.internal_full_viewing_key;
            }
            s << obj.private_scan_pending_height;
            s << obj.private_restore_scan << obj.private_locked_live_scan;
        });
        SER_READ(obj, {
            s >> obj.nVersion;
            if (obj.nVersion != CURRENT_VERSION) {
                throw std::ios_base::failure("Unsupported private wallet chain version");
            }
            s >> obj.account >> obj.next_external_index >> obj.next_internal_index >> obj.derivation_version >> obj.hd_seed_id;
            if (obj.derivation_version != NITO_PRIVATE_ORCHARD_DERIVATION_VERSION) {
                throw std::ios_base::failure("Unsupported private wallet derivation version");
            }
            uint8_t seed_scope{0};
            s >> seed_scope;
            if (seed_scope > static_cast<uint8_t>(PrivateSeedScope::ORCHARD_ONLY)) {
                throw std::ios_base::failure("Invalid private wallet seed scope");
            }
            obj.seed_scope = static_cast<PrivateSeedScope>(seed_scope);
            s >> obj.has_external_full_viewing_key >> obj.has_internal_full_viewing_key;
            obj.external_full_viewing_key.fill(0);
            obj.internal_full_viewing_key.fill(0);
            if (obj.has_external_full_viewing_key) {
                s >> obj.external_full_viewing_key;
            }
            if (obj.has_internal_full_viewing_key) {
                s >> obj.internal_full_viewing_key;
            }
            s >> obj.private_scan_pending_height >> obj.private_restore_scan >> obj.private_locked_live_scan;
            obj.Normalize();
        });
    }
};

class OrchardKeyMan
{
private:
    CPrivateWalletChain m_chain;

public:
    OrchardKeyMan() = default;
    explicit OrchardKeyMan(const CPrivateWalletChain& chain);

    const CPrivateWalletChain& GetChain() const;
    void SetChain(const CPrivateWalletChain& chain);

    uint32_t NextIndex(bool internal) const;
    PrivateOrchardKeyPath NextPath(bool internal) const;
    void MarkUsed(bool internal, uint32_t index);
    void MarkPathUsed(const PrivateOrchardKeyPath& path);

    PrivateOrchardBuildResult DeriveSpendingKey(
        const BIP39Seed& seed,
        const PrivateOrchardKeyPath& path,
        std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE>& spending_key,
        std::string& error) const;

    PrivateOrchardBuildResult DeriveRawAddress(
        const BIP39Seed& seed,
        const PrivateOrchardKeyPath& path,
        std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
        std::string& error) const;

    PrivateOrchardBuildResult DeriveAddress(
        const BIP39Seed& seed,
        const PrivateOrchardKeyPath& path,
        const CChainParams& params,
        std::string& encoded_address,
        std::string& error) const;

    PrivateOrchardBuildResult DeriveAddress(
        const PrivateOrchardKeyPath& path,
        const CChainParams& params,
        std::string& encoded_address,
        std::string& error) const;

    bool FindAddressPath(
        const BIP39Seed& seed,
        const std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
        PrivateOrchardKeyPath& path_out,
        std::string& error,
        uint32_t extra_lookahead = 0) const;

    bool GetDescriptor(
        const BIP39Seed& seed,
        bool internal,
        bool ranged,
        std::string& descriptor,
        std::string& error) const;

    bool GetDescriptorForPath(
        const BIP39Seed& seed,
        const PrivateOrchardKeyPath& path,
        std::string& descriptor,
        std::string& error) const;
};

PrivateOrchardBuildResult DeriveNitoPrivateOrchardSpendingKey(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE>& spending_key,
    std::string& error);

PrivateOrchardBuildResult DeriveNitoPrivateOrchardRawAddress(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
    std::string& error);

PrivateOrchardBuildResult DeriveNitoPrivateOrchardFullViewingKey(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& full_viewing_key,
    std::string& error);

PrivateOrchardBuildResult DeriveNitoPrivateAddress(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    const CChainParams& params,
    std::string& encoded_address,
    std::string& error);

PrivateOrchardBuildResult DeriveNitoPrivateAddress(
    const std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& full_viewing_key,
    const PrivateOrchardKeyPath& path,
    const CChainParams& params,
    std::string& encoded_address,
    std::string& error);

} // namespace wallet

#endif // BITCOIN_WALLET_PRIVATE_WALLET_H
