// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PRIVATE_TX_VERIFY_H
#define BITCOIN_CONSENSUS_PRIVATE_TX_VERIFY_H

#include <cstddef>
#include <cstdint>
#include <string>

class CPrivateBundle;
class CTransaction;
class TxValidationState;
enum class PrivateOrchardVerifyResult;

static constexpr size_t MAX_PRIVATE_ORCHARD_ACTIONS{50};

// Policy cost in virtual bytes, calibrated from the measured warm-verification
// curve (about 5 ms fixed work plus about 1 ms per Orchard action). The
// serialized transaction size remains the floor whenever it is larger.
static constexpr int64_t PRIVATE_ORCHARD_VERIFY_BASE_COST{5000};
static constexpr int64_t PRIVATE_ORCHARD_VERIFY_PER_ACTION_COST{1000};

// Current serialization makes a one-action bundle the worst cost/weight case:
// 6,000 cost units for at least 8,662 weight units. MAX_BLOCK_WEIGHT therefore
// limits a valid block to fewer than 555,000 Orchard verification cost units.
// This is a demonstrated consequence of the existing block-weight consensus
// rule, not an additional consensus limit.
static constexpr int64_t MAX_BLOCK_PRIVATE_ORCHARD_VERIFY_COST{555000};

// Dedicated, bounded success cache. It is intentionally independent from the
// script/signature cache allocation so existing cache semantics do not change.
static constexpr size_t DEFAULT_MAX_PRIVATE_ORCHARD_PROOF_CACHE_BYTES{8U << 20};

enum class PrivateProofCacheMode {
    BYPASS,
    STORE,
    ERASE,
};

[[nodiscard]] bool CheckPrivateBundleSanity(const CPrivateBundle& bundle, TxValidationState& state);
[[nodiscard]] bool SetPrivateBundleProofValidationState(PrivateOrchardVerifyResult result, const std::string& error, TxValidationState& state);
[[nodiscard]] bool CheckPrivateBundleProofs(const CTransaction& tx, TxValidationState& state, PrivateProofCacheMode cache_mode = PrivateProofCacheMode::BYPASS);
[[nodiscard]] bool InitPrivateOrchardProofCache(size_t max_size_bytes);
int64_t GetPrivateOrchardVerificationCost(size_t action_count);
uint64_t GetPrivateOrchardProofVerificationCount();
void ResetPrivateOrchardProofVerificationCount();

#endif // BITCOIN_CONSENSUS_PRIVATE_TX_VERIFY_H
