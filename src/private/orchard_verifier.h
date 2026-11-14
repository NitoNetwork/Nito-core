// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIVATE_ORCHARD_VERIFIER_H
#define BITCOIN_PRIVATE_ORCHARD_VERIFIER_H

#include <consensus/amount.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

class CPrivateBundle;
class CPrivateCompactEffects;
struct CMutableTransaction;
class CTransaction;
class uint256;

enum class PrivateOrchardVerifyResult {
    OK,
    BadEncoding,
    BadProof,
    BadSpendAuth,
    BadBindingSig,
    EngineError,
};

enum class PrivateOrchardBuildResult {
    OK,
    BadEncoding,
    BufferTooSmall,
    BuildError,
    EngineError,
};

static constexpr size_t NITO_ORCHARD_RAW_ADDRESS_SIZE = 43;
static constexpr size_t NITO_ORCHARD_DIVERSIFIER_SIZE = 11;
static constexpr size_t NITO_ORCHARD_RHO_SIZE = 32;
static constexpr size_t NITO_ORCHARD_RSEED_SIZE = 32;
static constexpr size_t NITO_ORCHARD_MEMO_SIZE = 512;
static constexpr size_t NITO_ORCHARD_MERKLE_PATH_SIZE = 32 * 32;
static constexpr size_t NITO_ORCHARD_FULL_VIEWING_KEY_SIZE = 96;

struct PrivateOrchardDecryptedNote {
    bool matched{false};
    CAmount value{0};
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> recipient_raw{};
    uint256 cmx;
    uint256 nullifier;
    std::array<unsigned char, NITO_ORCHARD_RHO_SIZE> rho{};
    std::array<unsigned char, NITO_ORCHARD_RSEED_SIZE> rseed{};
    std::array<unsigned char, NITO_ORCHARD_MEMO_SIZE> memo{};
};

struct PrivateOrchardViewingKey {
    bool internal{false};
    Span<const unsigned char> full_viewing_key;
    Span<const unsigned char> diversifier;
    bool has_diversifier{true};
};

struct PrivateOrchardCompactDecryptionResult {
    bool matched{false};
    uint32_t viewing_key_index{0};
    PrivateOrchardDecryptedNote note;
};

struct PrivateOrchardSpendInfo {
    Span<const unsigned char> spending_key;
    Span<const unsigned char> note_recipient_raw;
    CAmount note_value{0};
    Span<const unsigned char> note_rho;
    Span<const unsigned char> note_rseed;
    uint32_t note_position{0};
    Span<const unsigned char> merkle_path;
};

struct PrivateOrchardOutputInfo {
    Span<const unsigned char> recipient_raw;
    CAmount value{0};
    bool ovk_internal{false};
};

PrivateOrchardBuildResult BuildPrivateOrchardOutputBundle(
    Span<const unsigned char> recipient_raw,
    CAmount value,
    const uint256& anchor,
    const uint256& sighash,
    CPrivateBundle& out,
    std::string& error);

PrivateOrchardBuildResult DerivePrivateOrchardRawAddress(
    Span<const unsigned char> spending_key,
    uint32_t diversifier_index,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& recipient_raw,
    std::string& error);

PrivateOrchardBuildResult DerivePrivateOrchardRawAddressScoped(
    Span<const unsigned char> spending_key,
    uint32_t diversifier_index,
    bool internal_scope,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& recipient_raw,
    std::string& error);

PrivateOrchardBuildResult DerivePrivateOrchardFullViewingKey(
    Span<const unsigned char> spending_key,
    std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& full_viewing_key,
    std::string& error);

PrivateOrchardBuildResult DerivePrivateOrchardRawAddressFromFullViewingKeyScoped(
    Span<const unsigned char> full_viewing_key,
    uint32_t diversifier_index,
    bool internal_scope,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& recipient_raw,
    std::string& error);

PrivateOrchardBuildResult GetPrivateOrchardDiversifierIndex(
    Span<const unsigned char> full_viewing_key,
    bool internal_scope,
    Span<const unsigned char> raw_address,
    bool& matched_out,
    uint32_t& diversifier_index_out,
    std::string& error);

using PrivateOrchardSighashFn = std::function<bool(const CPrivateBundle& effects_bundle, uint256& sighash_out, std::string& error)>;

PrivateOrchardBuildResult BuildPrivateOrchardOutputBundleWithSighashCallback(
    Span<const unsigned char> recipient_raw,
    CAmount value,
    const uint256& anchor,
    const PrivateOrchardSighashFn& sighash_callback,
    CPrivateBundle& out,
    std::string& error);

PrivateOrchardBuildResult BuildPrivateOrchardSpendBundleWithSighashCallback(
    Span<const unsigned char> spending_key,
    Span<const unsigned char> note_recipient_raw,
    CAmount note_value,
    Span<const unsigned char> note_rho,
    Span<const unsigned char> note_rseed,
    uint32_t note_position,
    Span<const unsigned char> merkle_path,
    Span<const unsigned char> output_recipient_raw,
    CAmount output_value,
    bool output_ovk_internal,
    const uint256& anchor,
    const PrivateOrchardSighashFn& sighash_callback,
    CPrivateBundle& out,
    std::string& error);

PrivateOrchardBuildResult BuildPrivateOrchardBundleWithSighashCallback(
    Span<const PrivateOrchardSpendInfo> spends,
    Span<const PrivateOrchardOutputInfo> outputs,
    const uint256& anchor,
    const PrivateOrchardSighashFn& sighash_callback,
    CPrivateBundle& out,
    std::string& error);

PrivateOrchardBuildResult BuildPrivateOrchardBundleEffectsOnly(
    Span<const PrivateOrchardSpendInfo> spends,
    Span<const PrivateOrchardOutputInfo> outputs,
    const uint256& anchor,
    CPrivateBundle& out,
    std::string& error);

PrivateOrchardBuildResult DecryptPrivateOrchardOutput(
    Span<const unsigned char> spending_key,
    bool internal_scope,
    const CPrivateBundle& bundle,
    size_t action_idx,
    PrivateOrchardDecryptedNote& note_out,
    std::string& error);

PrivateOrchardBuildResult DecryptPrivateOrchardOutputWithFullViewingKey(
    Span<const unsigned char> full_viewing_key,
    bool internal_scope,
    const CPrivateBundle& bundle,
    size_t action_idx,
    PrivateOrchardDecryptedNote& note_out,
    std::string& error);

PrivateOrchardBuildResult DecryptPrivateOrchardCompactOutputsWithFullViewingKeys(
    Span<const PrivateOrchardViewingKey> viewing_keys,
    const CPrivateCompactEffects& effects,
    std::vector<PrivateOrchardCompactDecryptionResult>& results_out,
    std::string& error);

PrivateOrchardBuildResult ClassifyPrivateOrchardChangeOutputs(
    Span<const unsigned char> external_full_viewing_key,
    Span<const unsigned char> internal_full_viewing_key,
    const CPrivateBundle& bundle,
    std::vector<unsigned char>& change_out,
    std::string& error);

PrivateOrchardBuildResult ComputePrivateOrchardNoteCommitment(
    Span<const unsigned char> recipient_raw,
    CAmount value,
    Span<const unsigned char> rho,
    Span<const unsigned char> rseed,
    uint256& cmx_out,
    std::string& error);

PrivateOrchardBuildResult ComputePrivateOrchardAuthPath(
    Span<const uint256> commitments,
    uint32_t position,
    std::vector<uint256>& auth_path,
    uint256& root_out,
    std::string& error);

PrivateOrchardBuildResult ComputePrivateOrchardParent(
    uint8_t level,
    const uint256& left,
    const uint256& right,
    uint256& parent_out,
    std::string& error);

PrivateOrchardBuildResult GetPrivateOrchardEmptyRoot(
    uint8_t level,
    uint256& root_out,
    std::string& error);

uint256 PrivateBundleSighash(const CTransaction& tx);
uint256 PrivateBundleSighash(const CMutableTransaction& tx);

PrivateOrchardVerifyResult VerifyPrivateOrchardBundle(const CTransaction& tx, std::string& error);

#endif // BITCOIN_PRIVATE_ORCHARD_VERIFIER_H
