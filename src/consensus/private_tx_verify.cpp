// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/private_tx_verify.h>

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <private/orchard_verifier.h>
#include <primitives/private_transaction.h>
#include <primitives/transaction.h>

#include <atomic>
#include <cstring>
#include <limits>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <string>

namespace {
std::atomic<uint64_t> g_private_orchard_proof_verification_count{0};

class PrivateProofCacheHasher
{
public:
    template <uint8_t hash_select>
    uint32_t operator()(const uint256& key) const
    {
        static_assert(hash_select < 8);
        uint32_t value;
        std::memcpy(&value, key.begin() + 4 * hash_select, sizeof(value));
        return value;
    }
};

class PrivateProofCache
{
private:
    using Cache = CuckooCache::cache<uint256, PrivateProofCacheHasher>;
    Cache m_valid;
    std::shared_mutex m_mutex;
    bool m_initialized{false};

public:
    bool Init(size_t max_size_bytes)
    {
        std::unique_lock lock{m_mutex};
        const auto result{m_valid.setup_bytes(max_size_bytes)};
        m_initialized = result.has_value();
        return m_initialized;
    }

    bool Get(const uint256& entry, bool erase)
    {
        if (erase) {
            std::unique_lock lock{m_mutex};
            return m_initialized && m_valid.contains(entry, /*erase=*/true);
        }
        std::shared_lock lock{m_mutex};
        return m_initialized && m_valid.contains(entry, /*erase=*/false);
    }

    void Set(const uint256& entry)
    {
        std::unique_lock lock{m_mutex};
        if (m_initialized) m_valid.insert(entry);
    }
};

PrivateProofCache g_private_proof_cache;

bool CheckVectorSizeExact(const std::vector<unsigned char>& v, size_t expected_size)
{
    return v.size() == expected_size;
}
} // namespace

bool CheckPrivateBundleSanity(const CPrivateBundle& bundle, TxValidationState& state)
{
    if (bundle.effects.version != 1) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-version");
    }
    if ((bundle.effects.flags & ~PRIVATE_ORCHARD_FLAGS_MASK) != 0) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-flags");
    }
    if (!MoneyRangeSigned(bundle.effects.value_balance)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-valuebalance-outofrange");
    }
    if (bundle.effects.actions.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-empty");
    }
    if (bundle.effects.actions.size() > MAX_PRIVATE_ORCHARD_ACTIONS) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-too-many-actions");
    }
    if (bundle.auth && bundle.auth->actions_auth.size() != bundle.effects.actions.size()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-auth-count");
    }

    std::set<uint256> nullifiers;
    for (const auto& action : bundle.effects.actions) {
        if (action.version != PRIVATE_ACTION_V1) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-action-version");
        }
        if (action.nullifier.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-nullifier-null");
        }
        if (!nullifiers.insert(action.nullifier).second) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-nullifier-duplicate");
        }
        if (action.cmx.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-commitment-null");
        }
        if (action.cv.IsNull() || action.rk.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-action-point-null");
        }
        if (!CheckVectorSizeExact(action.ephemeral_key, PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE) ||
            !CheckVectorSizeExact(action.enc_ciphertext, PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE) ||
            !CheckVectorSizeExact(action.out_ciphertext, PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-encoding-size");
        }
    }

    if (bundle.auth) {
        if (!CheckVectorSizeExact(bundle.auth->binding_sig, PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-binding-sig");
        }
        if (bundle.auth->proof.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-proof-empty");
        }
        if (bundle.auth->proof.size() != PrivateOrchardExpectedProofSize(bundle.effects.actions.size())) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-proof-size");
        }
        for (const auto& auth : bundle.auth->actions_auth) {
            if (!CheckVectorSizeExact(auth.spend_auth_sig, PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-auth-size");
            }
        }
    }

    return true;
}

bool SetPrivateBundleProofValidationState(PrivateOrchardVerifyResult result, const std::string& error, TxValidationState& state)
{
    switch (result) {
    case PrivateOrchardVerifyResult::OK:
        return true;
    case PrivateOrchardVerifyResult::BadEncoding:
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-orchard-encoding", error);
    case PrivateOrchardVerifyResult::BadProof:
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-orchard-proof", error);
    case PrivateOrchardVerifyResult::BadSpendAuth:
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-orchard-spendauth", error);
    case PrivateOrchardVerifyResult::BadBindingSig:
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-orchard-bindingsig", error);
    case PrivateOrchardVerifyResult::EngineError:
        return state.Error(error.empty() ? "private-orchard-engine" : "private-orchard-engine: " + error);
    }

    return state.Error("private-orchard-engine: unknown private verifier result");
}

bool CheckPrivateBundleProofs(const CTransaction& tx, TxValidationState& state, PrivateProofCacheMode cache_mode)
{
    if (!tx.HasPrivateBundle()) {
        return true;
    }
    if (!CheckPrivateBundleSanity(*tx.m_private_bundle, state)) {
        return false;
    }
    if (!tx.HasPrivateAuth()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-private-auth-missing");
    }

    const uint256 cache_entry{tx.GetWitnessHash().ToUint256()};
    if (cache_mode != PrivateProofCacheMode::BYPASS &&
        g_private_proof_cache.Get(cache_entry, cache_mode == PrivateProofCacheMode::ERASE)) {
        return true;
    }

    std::string error;
    g_private_orchard_proof_verification_count.fetch_add(1, std::memory_order_relaxed);
    const PrivateOrchardVerifyResult result{VerifyPrivateOrchardBundle(tx, error)};
    if (result == PrivateOrchardVerifyResult::OK && cache_mode == PrivateProofCacheMode::STORE) {
        g_private_proof_cache.Set(cache_entry);
    }
    return SetPrivateBundleProofValidationState(result, error, state);
}

bool InitPrivateOrchardProofCache(size_t max_size_bytes)
{
    return g_private_proof_cache.Init(max_size_bytes);
}

int64_t GetPrivateOrchardVerificationCost(size_t action_count)
{
    if (action_count == 0) return 0;
    constexpr uint64_t MAX_COST_ACTIONS{
        (static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) - PRIVATE_ORCHARD_VERIFY_BASE_COST) /
        PRIVATE_ORCHARD_VERIFY_PER_ACTION_COST};
    if (action_count > MAX_COST_ACTIONS) return std::numeric_limits<int64_t>::max();
    return PRIVATE_ORCHARD_VERIFY_BASE_COST +
        PRIVATE_ORCHARD_VERIFY_PER_ACTION_COST * static_cast<int64_t>(action_count);
}

uint64_t GetPrivateOrchardProofVerificationCount()
{
    return g_private_orchard_proof_verification_count.load(std::memory_order_relaxed);
}

void ResetPrivateOrchardProofVerificationCount()
{
    g_private_orchard_proof_verification_count.store(0, std::memory_order_relaxed);
}
