// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/private_wallet.h>

#include <chainparams.h>
#include <crypto/hkdf_sha256_32.h>
#include <key.h>
#include <key_io.h>
#include <private/orchard_verifier.h>
#include <script/descriptor.h>
#include <support/cleanse.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <wallet/bip39.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace wallet {
namespace {
static constexpr uint32_t HARDENED = 0x80000000U;
static constexpr size_t MAX_ORCHARD_KEY_DERIVATION_ATTEMPTS = 16;

bool DeriveExtKeyChecked(const CExtKey& parent, uint32_t child, CExtKey& out, std::string& error)
{
    if (!parent.Derive(out, child)) {
        error = "BIP32 private Orchard derivation failed";
        return false;
    }
    return true;
}

CExtKey MakeOrchardMasterKey(const BIP39Seed& seed)
{
    return MakeBIP39MasterKey(seed);
}

std::string FormatPrivateOrchardPath(const PrivateOrchardKeyPath& path)
{
    return std::string{"m/96'/0'/"} + std::to_string(path.account) + "'/" +
        (path.internal ? std::to_string(NITO_PRIVATE_ORCHARD_INTERNAL_BRANCH) : std::to_string(NITO_PRIVATE_ORCHARD_EXTERNAL_BRANCH)) +
        "/" + std::to_string(path.diversifier_index);
}

std::string FormatPrivateOrchardBranchPath(const PrivateOrchardKeyPath& path)
{
    return std::string{"m/96'/0'/"} + std::to_string(path.account) + "'/" +
        (path.internal ? std::to_string(NITO_PRIVATE_ORCHARD_INTERNAL_BRANCH) : std::to_string(NITO_PRIVATE_ORCHARD_EXTERNAL_BRANCH));
}

bool DerivePrivateOrchardAccount(
    const BIP39Seed& seed,
    uint32_t account_index,
    CExtKey& account,
    std::array<unsigned char, 4>& master_fingerprint,
    std::string& error)
{
    if (account_index >= HARDENED) {
        error = "private Orchard derivation index out of range";
        return false;
    }

    CExtKey master{MakeOrchardMasterKey(seed)};
    CExtKey purpose;
    CExtKey coin_type;

    const CKeyID master_id = master.key.GetPubKey().GetID();
    std::copy(master_id.begin(), master_id.begin() + master_fingerprint.size(), master_fingerprint.begin());
    if (!DeriveExtKeyChecked(master, NITO_PRIVATE_ORCHARD_PURPOSE | HARDENED, purpose, error)) return false;
    if (!DeriveExtKeyChecked(purpose, NITO_PRIVATE_ORCHARD_COIN_TYPE | HARDENED, coin_type, error)) return false;
    if (!DeriveExtKeyChecked(coin_type, account_index | HARDENED, account, error)) return false;
    return true;
}

bool DerivePrivateOrchardBranch(const BIP39Seed& seed, const PrivateOrchardKeyPath& path, CExtKey& branch, std::string& error)
{
    if (path.derivation_version != NITO_PRIVATE_ORCHARD_DERIVATION_VERSION) {
        error = "unsupported Nito.network Orchard derivation version";
        return false;
    }
    if (path.diversifier_index >= std::numeric_limits<uint32_t>::max()) {
        error = "private Orchard derivation index out of range";
        return false;
    }

    CExtKey account;
    std::array<unsigned char, 4> unused_fingerprint{};
    if (!DerivePrivateOrchardAccount(seed, path.account, account, unused_fingerprint, error)) return false;
    const uint32_t branch_id = path.internal ? NITO_PRIVATE_ORCHARD_INTERNAL_BRANCH : NITO_PRIVATE_ORCHARD_EXTERNAL_BRANCH;
    if (!DeriveExtKeyChecked(account, branch_id, branch, error)) return false;
    return true;
}

void DeriveAttemptKey(const CExtKey& branch, const PrivateOrchardKeyPath& path, size_t attempt, std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE>& spending_key)
{
    std::array<unsigned char, 32> branch_secret{};
    std::memcpy(branch_secret.data(), branch.key.begin(), branch_secret.size());

    CHKDF_HMAC_SHA256_L32 hkdf{
        branch_secret.data(),
        branch_secret.size(),
        "Nito.network Orchard spending key"};
    const std::string info = FormatPrivateOrchardBranchPath(path) + "/attempt/" + std::to_string(attempt);
    hkdf.Expand32(info, spending_key.data());
    memory_cleanse(branch_secret.data(), branch_secret.size());
}
} // namespace

std::string PrivateOrchardKeyPath::ToString() const
{
    return FormatPrivateOrchardPath(*this);
}

bool CPrivateWalletChain::IsSupported() const
{
    return derivation_version == NITO_PRIVATE_ORCHARD_DERIVATION_VERSION;
}

void CPrivateWalletChain::Normalize()
{
    if (nVersion < VERSION_BASE) {
        nVersion = VERSION_BASE;
    }
    if (nVersion < VERSION_DERIVATION) {
        derivation_version = NITO_PRIVATE_ORCHARD_DERIVATION_VERSION;
    }
    if (nVersion < VERSION_HD_SEED) {
        hd_seed_id.SetNull();
    }
    if (nVersion < VERSION_SEED_SCOPE ||
        (seed_scope != PrivateSeedScope::FULL_WALLET && seed_scope != PrivateSeedScope::ORCHARD_ONLY)) {
        seed_scope = PrivateSeedScope::UNKNOWN;
    }
    if (nVersion < VERSION_VIEWING_KEYS) {
        has_external_full_viewing_key = false;
        has_internal_full_viewing_key = false;
        external_full_viewing_key.fill(0);
        internal_full_viewing_key.fill(0);
    }
    auto normalize_obligation = [](CPrivateScanObligation& obligation) {
        if (obligation.start_height < 0) {
            obligation.Clear();
            return;
        }
        if (obligation.generation == 0) obligation.generation = 1;
        if (obligation.target_height < obligation.start_height) {
            obligation.target_height = -1;
            obligation.target_block.SetNull();
        }
    };
    normalize_obligation(private_restore_scan);
    normalize_obligation(private_locked_live_scan);
    private_scan_pending_height = -1;
    for (const CPrivateScanObligation* obligation : {&private_restore_scan, &private_locked_live_scan}) {
        if (!obligation->IsPending()) continue;
        if (private_scan_pending_height < 0 || obligation->start_height < private_scan_pending_height) {
            private_scan_pending_height = obligation->start_height;
        }
    }
    if (derivation_version == 0) {
        derivation_version = NITO_PRIVATE_ORCHARD_DERIVATION_VERSION;
    }
    if (IsSupported()) {
        nVersion = CURRENT_VERSION;
    }
}

uint32_t CPrivateWalletChain::NextIndex(bool internal) const
{
    return internal ? next_internal_index : next_external_index;
}

void CPrivateWalletChain::MarkUsed(bool internal, uint32_t index)
{
    uint32_t& next_index = internal ? next_internal_index : next_external_index;
    if (index >= next_index) {
        next_index = index + 1;
    }
}

bool CPrivateWalletChain::HasFullViewingKey(bool internal) const
{
    return internal ? has_internal_full_viewing_key : has_external_full_viewing_key;
}

const std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& CPrivateWalletChain::FullViewingKey(bool internal) const
{
    return internal ? internal_full_viewing_key : external_full_viewing_key;
}

void CPrivateWalletChain::SetFullViewingKey(bool internal, const std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& full_viewing_key)
{
    if (internal) {
        internal_full_viewing_key = full_viewing_key;
        has_internal_full_viewing_key = true;
    } else {
        external_full_viewing_key = full_viewing_key;
        has_external_full_viewing_key = true;
    }
    nVersion = CURRENT_VERSION;
}

OrchardKeyMan::OrchardKeyMan(const CPrivateWalletChain& chain) : m_chain(chain)
{
    m_chain.Normalize();
}

const CPrivateWalletChain& OrchardKeyMan::GetChain() const
{
    return m_chain;
}

void OrchardKeyMan::SetChain(const CPrivateWalletChain& chain)
{
    m_chain = chain;
    m_chain.Normalize();
}

uint32_t OrchardKeyMan::NextIndex(bool internal) const
{
    return m_chain.NextIndex(internal);
}

PrivateOrchardKeyPath OrchardKeyMan::NextPath(bool internal) const
{
    return PrivateOrchardKeyPath{m_chain.account, internal, m_chain.NextIndex(internal), m_chain.derivation_version};
}

void OrchardKeyMan::MarkUsed(bool internal, uint32_t index)
{
    m_chain.MarkUsed(internal, index);
}

void OrchardKeyMan::MarkPathUsed(const PrivateOrchardKeyPath& path)
{
    if (path.account == m_chain.account) {
        m_chain.MarkUsed(path.internal, path.diversifier_index);
    }
}

PrivateOrchardBuildResult OrchardKeyMan::DeriveSpendingKey(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE>& spending_key,
    std::string& error) const
{
    return DeriveNitoPrivateOrchardSpendingKey(seed, path, spending_key, error);
}

PrivateOrchardBuildResult OrchardKeyMan::DeriveRawAddress(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
    std::string& error) const
{
    return DeriveNitoPrivateOrchardRawAddress(seed, path, raw_address, error);
}

PrivateOrchardBuildResult OrchardKeyMan::DeriveAddress(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    const CChainParams& params,
    std::string& encoded_address,
    std::string& error) const
{
    return DeriveNitoPrivateAddress(seed, path, params, encoded_address, error);
}

PrivateOrchardBuildResult OrchardKeyMan::DeriveAddress(
    const PrivateOrchardKeyPath& path,
    const CChainParams& params,
    std::string& encoded_address,
    std::string& error) const
{
    if (!m_chain.HasFullViewingKey(path.internal)) {
        error = "private viewing key is not available";
        return PrivateOrchardBuildResult::BuildError;
    }
    return DeriveNitoPrivateAddress(m_chain.FullViewingKey(path.internal), path, params, encoded_address, error);
}

bool OrchardKeyMan::FindAddressPath(
    const BIP39Seed& seed,
    const std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
    PrivateOrchardKeyPath& path_out,
    std::string& error,
    uint32_t extra_lookahead) const
{
    (void)extra_lookahead;
    for (const bool internal : {false, true}) {
        PrivateOrchardKeyPath branch_path{m_chain.account, internal, 0, m_chain.derivation_version};
        std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE> spending_key{};
        auto key_result = DeriveSpendingKey(seed, branch_path, spending_key, error);
        if (key_result != PrivateOrchardBuildResult::OK) {
            memory_cleanse(spending_key.data(), spending_key.size());
            return false;
        }

        std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE> fvk{};
        auto fvk_result = DerivePrivateOrchardFullViewingKey(
            Span<const unsigned char>{spending_key.data(), spending_key.size()},
            fvk,
            error);
        memory_cleanse(spending_key.data(), spending_key.size());
        if (fvk_result != PrivateOrchardBuildResult::OK) {
            memory_cleanse(fvk.data(), fvk.size());
            return false;
        }

        bool matched{false};
        uint32_t diversifier_index{0};
        auto index_result = GetPrivateOrchardDiversifierIndex(
            Span<const unsigned char>{fvk.data(), fvk.size()},
            internal,
            Span<const unsigned char>{raw_address.data(), raw_address.size()},
            matched,
            diversifier_index,
            error);
        memory_cleanse(fvk.data(), fvk.size());
        if (index_result != PrivateOrchardBuildResult::OK) {
            return false;
        }
        if (matched) {
            path_out = PrivateOrchardKeyPath{m_chain.account, internal, diversifier_index, m_chain.derivation_version};
            return true;
        }
    }

    error = "Private address is not in this wallet's derived private address range";
    return false;
}

bool OrchardKeyMan::GetDescriptor(
    const BIP39Seed& seed,
    bool internal,
    bool ranged,
    std::string& descriptor,
    std::string& error) const
{
    descriptor.clear();
    error.clear();
    (void)ranged;
    if (!m_chain.IsSupported()) {
        error = "unsupported Nito.network Orchard derivation version";
        return false;
    }

    const CExtKey master{MakeOrchardMasterKey(seed)};

    std::vector<uint32_t> descriptor_path{
        NITO_PRIVATE_ORCHARD_PURPOSE | HARDENED,
        NITO_PRIVATE_ORCHARD_COIN_TYPE | HARDENED,
        m_chain.account | HARDENED,
        internal ? NITO_PRIVATE_ORCHARD_INTERNAL_BRANCH : NITO_PRIVATE_ORCHARD_EXTERNAL_BRANCH,
    };
    descriptor = "or(" +
        EncodeExtKey(master) +
        FormatHDKeypath(descriptor_path) +
        ")";

    const std::string checksum = GetDescriptorChecksum(descriptor);
    if (!checksum.empty()) {
        descriptor += "#" + checksum;
    }
    return true;
}

bool OrchardKeyMan::GetDescriptorForPath(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    std::string& descriptor,
    std::string& error) const
{
    descriptor.clear();
    error.clear();
    if (path.derivation_version != NITO_PRIVATE_ORCHARD_DERIVATION_VERSION) {
        error = "unsupported Nito.network Orchard derivation version";
        return false;
    }

    const CExtKey master{MakeOrchardMasterKey(seed)};

    const std::vector<uint32_t> descriptor_path{
        NITO_PRIVATE_ORCHARD_PURPOSE | HARDENED,
        NITO_PRIVATE_ORCHARD_COIN_TYPE | HARDENED,
        path.account | HARDENED,
        path.internal ? NITO_PRIVATE_ORCHARD_INTERNAL_BRANCH : NITO_PRIVATE_ORCHARD_EXTERNAL_BRANCH,
    };

    descriptor = "or(" + EncodeExtKey(master) + FormatHDKeypath(descriptor_path) + ")";

    const std::string checksum = GetDescriptorChecksum(descriptor);
    if (!checksum.empty()) {
        descriptor += "#" + checksum;
    }
    return true;
}

PrivateOrchardBuildResult DeriveNitoPrivateOrchardSpendingKey(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE>& spending_key,
    std::string& error)
{
    error.clear();

    CExtKey branch;
    if (!DerivePrivateOrchardBranch(seed, path, branch, error)) {
        return PrivateOrchardBuildResult::BadEncoding;
    }

    for (size_t attempt = 0; attempt < MAX_ORCHARD_KEY_DERIVATION_ATTEMPTS; ++attempt) {
        DeriveAttemptKey(branch, path, attempt, spending_key);

        std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> unused_raw_address{};
        std::string validation_error;
        const auto validation_result = ::DerivePrivateOrchardRawAddressScoped(
            Span<const unsigned char>{spending_key.data(), spending_key.size()},
            path.diversifier_index,
            path.internal,
            unused_raw_address,
            validation_error);
        if (validation_result == PrivateOrchardBuildResult::OK) {
            return PrivateOrchardBuildResult::OK;
        }
    }

    memory_cleanse(spending_key.data(), spending_key.size());
    error = "unable to derive a valid Orchard spending key";
    return PrivateOrchardBuildResult::BuildError;
}

PrivateOrchardBuildResult DeriveNitoPrivateOrchardRawAddress(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
    std::string& error)
{
    error.clear();

    std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE> spending_key{};
    const auto key_result = DeriveNitoPrivateOrchardSpendingKey(seed, path, spending_key, error);
    if (key_result != PrivateOrchardBuildResult::OK) {
        memory_cleanse(spending_key.data(), spending_key.size());
        return key_result;
    }

    const auto address_result = ::DerivePrivateOrchardRawAddressScoped(
        Span<const unsigned char>{spending_key.data(), spending_key.size()},
        path.diversifier_index,
        path.internal,
        raw_address,
        error);
    memory_cleanse(spending_key.data(), spending_key.size());
    return address_result;
}

PrivateOrchardBuildResult DeriveNitoPrivateOrchardFullViewingKey(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& full_viewing_key,
    std::string& error)
{
    error.clear();

    std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE> spending_key{};
    const auto key_result = DeriveNitoPrivateOrchardSpendingKey(seed, path, spending_key, error);
    if (key_result != PrivateOrchardBuildResult::OK) {
        return key_result;
    }

    const auto fvk_result = ::DerivePrivateOrchardFullViewingKey(
        Span<const unsigned char>{spending_key.data(), spending_key.size()},
        full_viewing_key,
        error);
    memory_cleanse(spending_key.data(), spending_key.size());
    return fvk_result;
}

PrivateOrchardBuildResult DeriveNitoPrivateAddress(
    const BIP39Seed& seed,
    const PrivateOrchardKeyPath& path,
    const CChainParams& params,
    std::string& encoded_address,
    std::string& error)
{
    error.clear();
    encoded_address.clear();

    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> raw_address{};
    const auto result = DeriveNitoPrivateOrchardRawAddress(seed, path, raw_address, error);
    if (result != PrivateOrchardBuildResult::OK) {
        return result;
    }
    encoded_address = EncodeNitoPrivateAddress(raw_address, params);
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult DeriveNitoPrivateAddress(
    const std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& full_viewing_key,
    const PrivateOrchardKeyPath& path,
    const CChainParams& params,
    std::string& encoded_address,
    std::string& error)
{
    error.clear();
    encoded_address.clear();

    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> raw_address{};
    const auto result = ::DerivePrivateOrchardRawAddressFromFullViewingKeyScoped(
        Span<const unsigned char>{full_viewing_key.data(), full_viewing_key.size()},
        path.diversifier_index,
        path.internal,
        raw_address,
        error);
    if (result != PrivateOrchardBuildResult::OK) {
        return result;
    }
    encoded_address = EncodeNitoPrivateAddress(raw_address, params);
    return PrivateOrchardBuildResult::OK;
}

} // namespace wallet
