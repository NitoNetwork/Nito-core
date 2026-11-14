// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <private/orchard_verifier.h>

#include <consensus/private_tx_verify.h>
#include <hash.h>
#include <private/orchard_ffi.h>
#include <primitives/private_transaction.h>
#include <primitives/transaction.h>
#include <support/cleanse.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {
static constexpr int32_t NITO_PRIVATE_OK = 0;
static constexpr int32_t NITO_PRIVATE_ERR_NULL_PTR = 1;
static constexpr int32_t NITO_PRIVATE_ERR_BAD_ENCODING = 2;
static constexpr int32_t NITO_PRIVATE_ERR_BAD_PROOF = 3;
static constexpr int32_t NITO_PRIVATE_ERR_BAD_SPEND_SIG = 4;
static constexpr int32_t NITO_PRIVATE_ERR_BAD_BINDING_SIG = 5;
static constexpr int32_t NITO_PRIVATE_ERR_BUFFER_TOO_SMALL = 6;
static constexpr int32_t NITO_PRIVATE_ERR_BUILD = 7;
static constexpr size_t ORCHARD_RAW_ADDRESS_SIZE = 43;
static constexpr size_t ORCHARD_BUILD_ACTION_CAP = MAX_PRIVATE_ORCHARD_ACTIONS;
static constexpr size_t ORCHARD_BUILD_PROOF_CAP = 256 * 1024;

uint8_t* MutableDataPtr(std::vector<unsigned char>& value);

struct OrchardBuildBuffers {
    uint8_t flags{0};
    int64_t value_balance{0};
    size_t actions_len{0};
    size_t proof_len{0};
    std::vector<unsigned char> cv_net = std::vector<unsigned char>(ORCHARD_BUILD_ACTION_CAP * 32);
    std::vector<unsigned char> nullifier = std::vector<unsigned char>(ORCHARD_BUILD_ACTION_CAP * 32);
    std::vector<unsigned char> rk = std::vector<unsigned char>(ORCHARD_BUILD_ACTION_CAP * 32);
    std::vector<unsigned char> cmx = std::vector<unsigned char>(ORCHARD_BUILD_ACTION_CAP * 32);
    std::vector<unsigned char> ephemeral_key = std::vector<unsigned char>(ORCHARD_BUILD_ACTION_CAP * PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
    std::vector<unsigned char> enc_ciphertext = std::vector<unsigned char>(ORCHARD_BUILD_ACTION_CAP * PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE);
    std::vector<unsigned char> out_ciphertext = std::vector<unsigned char>(ORCHARD_BUILD_ACTION_CAP * PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE);
    std::vector<unsigned char> spend_auth_sig = std::vector<unsigned char>(ORCHARD_BUILD_ACTION_CAP * PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE);
    std::vector<unsigned char> proof = std::vector<unsigned char>(ORCHARD_BUILD_PROOF_CAP);
    std::vector<unsigned char> binding_sig = std::vector<unsigned char>(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE);

    NitoOrchardBuildOutput RawOutput()
    {
        return NitoOrchardBuildOutput{
            &flags,
            &value_balance,
            &actions_len,
            ORCHARD_BUILD_ACTION_CAP,
            MutableDataPtr(cv_net),
            MutableDataPtr(nullifier),
            MutableDataPtr(rk),
            MutableDataPtr(cmx),
            MutableDataPtr(ephemeral_key),
            MutableDataPtr(enc_ciphertext),
            MutableDataPtr(out_ciphertext),
            MutableDataPtr(spend_auth_sig),
            MutableDataPtr(proof),
            proof.size(),
            &proof_len,
            MutableDataPtr(binding_sig),
        };
    }
};

template <typename TxType>
uint256 PrivateBundleSighashImpl(const TxType& tx)
{
    CMutableTransaction stripped{tx};
    // Private authorization must stay stable while transparent inputs are signed.
    for (CTxIn& txin : stripped.vin) {
        txin.scriptSig.clear();
        txin.scriptWitness.SetNull();
    }
    return (HashWriter{} << std::string{"NitoPrivateOrchardSigHashV1"} << TX_NO_WITNESS(stripped)).GetHash();
}

const uint8_t* DataPtr(const uint256& value)
{
    return reinterpret_cast<const uint8_t*>(value.begin());
}

const uint8_t* DataPtr(const std::vector<unsigned char>& value)
{
    return reinterpret_cast<const uint8_t*>(value.data());
}

bool CheckPrivateOrchardVerifierBuffers(const CPrivateBundle& bundle, std::string& error)
{
    const size_t action_count = bundle.effects.actions.size();
    if (action_count == 0 || action_count > ORCHARD_BUILD_ACTION_CAP) {
        error = "private verifier action count out of range";
        return false;
    }
    if (!bundle.auth || bundle.auth->actions_auth.size() != action_count) {
        error = "private verifier authorization count mismatch";
        return false;
    }

    for (const auto& action : bundle.effects.actions) {
        if (action.ephemeral_key.size() != PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE) {
            error = "private verifier ephemeral key size mismatch";
            return false;
        }
        if (action.enc_ciphertext.size() != PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE) {
            error = "private verifier encrypted ciphertext size mismatch";
            return false;
        }
        if (action.out_ciphertext.size() != PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE) {
            error = "private verifier outgoing ciphertext size mismatch";
            return false;
        }
    }
    for (const auto& action_auth : bundle.auth->actions_auth) {
        if (action_auth.spend_auth_sig.size() != PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE) {
            error = "private verifier spend authorization size mismatch";
            return false;
        }
    }
    if (bundle.auth->proof.size() != PrivateOrchardExpectedProofSize(action_count)) {
        error = "private verifier proof size mismatch";
        return false;
    }
    if (bundle.auth->binding_sig.size() != PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE) {
        error = "private verifier binding signature size mismatch";
        return false;
    }
    return true;
}

uint8_t* MutableDataPtr(std::vector<unsigned char>& value)
{
    return reinterpret_cast<uint8_t*>(value.data());
}

uint256 ReadUint256(const std::vector<unsigned char>& value, size_t offset)
{
    return uint256{Span<const unsigned char>{value.data() + offset, 32}};
}

std::vector<unsigned char> ReadVector(const std::vector<unsigned char>& value, size_t offset, size_t size)
{
    return std::vector<unsigned char>{value.begin() + offset, value.begin() + offset + size};
}

uint256 ReadUint256Ptr(const uint8_t* value)
{
    return uint256{Span<const unsigned char>{value, 32}};
}

std::vector<unsigned char> ReadVectorPtr(const uint8_t* value, size_t size)
{
    return std::vector<unsigned char>{value, value + size};
}

struct OrchardEffectsBuffers {
    std::vector<unsigned char> cv_net;
    std::vector<unsigned char> nullifier;
    std::vector<unsigned char> rk;
    std::vector<unsigned char> cmx;
    std::vector<unsigned char> ephemeral_key;
    std::vector<unsigned char> enc_ciphertext;
    std::vector<unsigned char> out_ciphertext;

    bool Fill(const CPrivateBundle& bundle, std::string& error)
    {
        const size_t actions_len = bundle.effects.actions.size();
        cv_net.resize(actions_len * 32);
        nullifier.resize(actions_len * 32);
        rk.resize(actions_len * 32);
        cmx.resize(actions_len * 32);
        ephemeral_key.resize(actions_len * PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
        enc_ciphertext.resize(actions_len * PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE);
        out_ciphertext.resize(actions_len * PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE);

        for (size_t i = 0; i < actions_len; ++i) {
            const auto& action = bundle.effects.actions[i];
            if (action.ephemeral_key.size() != PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE ||
                action.enc_ciphertext.size() != PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE ||
                action.out_ciphertext.size() != PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE) {
                error = "private action ciphertext length mismatch";
                return false;
            }

            const size_t off32 = i * 32;
            const size_t off_enc = i * PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE;
            const size_t off_out = i * PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE;
            std::memcpy(cv_net.data() + off32, action.cv.begin(), 32);
            std::memcpy(nullifier.data() + off32, action.nullifier.begin(), 32);
            std::memcpy(rk.data() + off32, action.rk.begin(), 32);
            std::memcpy(cmx.data() + off32, action.cmx.begin(), 32);
            std::memcpy(ephemeral_key.data() + off32, action.ephemeral_key.data(), PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
            std::memcpy(enc_ciphertext.data() + off_enc, action.enc_ciphertext.data(), PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE);
            std::memcpy(out_ciphertext.data() + off_out, action.out_ciphertext.data(), PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE);
        }
        return true;
    }

    NitoOrchardEffectsView RawView(const CPrivateBundle& bundle) const
    {
        return NitoOrchardEffectsView{
            bundle.effects.flags,
            bundle.effects.value_balance,
            DataPtr(bundle.effects.anchor),
            bundle.effects.actions.size(),
            DataPtr(cv_net),
            DataPtr(nullifier),
            DataPtr(rk),
            DataPtr(cmx),
            DataPtr(ephemeral_key),
            DataPtr(enc_ciphertext),
            DataPtr(out_ciphertext),
        };
    }
};

struct OrchardCompactEffectsBuffers {
    std::vector<unsigned char> nullifier;
    std::vector<unsigned char> cmx;
    std::vector<unsigned char> ephemeral_key;
    std::vector<unsigned char> enc_ciphertext;
    std::vector<unsigned char> view_tag;

    bool Fill(const CPrivateCompactEffects& effects, std::string& error)
    {
        const size_t actions_len = effects.actions.size();
        nullifier.resize(actions_len * 32);
        cmx.resize(actions_len * 32);
        ephemeral_key.resize(actions_len * PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
        enc_ciphertext.resize(actions_len * PRIVATE_ORCHARD_COMPACT_NOTE_SIZE);
        view_tag.resize(actions_len);

        for (size_t i = 0; i < actions_len; ++i) {
            const auto& action = effects.actions[i];
            if (action.ephemeral_key.size() != PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE ||
                action.enc_ciphertext.size() != PRIVATE_ORCHARD_COMPACT_NOTE_SIZE) {
                error = "compact private action ciphertext length mismatch";
                return false;
            }
            const uint8_t expected_view_tag = action.enc_ciphertext.front() ^ PRIVATE_ORCHARD_NOTE_PLAINTEXT_VERSION;
            if (action.view_tag != expected_view_tag) {
                error = "compact private action view tag mismatch";
                return false;
            }

            const size_t off32 = i * 32;
            const size_t off_enc = i * PRIVATE_ORCHARD_COMPACT_NOTE_SIZE;
            std::memcpy(nullifier.data() + off32, action.nullifier.begin(), 32);
            std::memcpy(cmx.data() + off32, action.cmx.begin(), 32);
            std::memcpy(ephemeral_key.data() + off32, action.ephemeral_key.data(), PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
            std::memcpy(enc_ciphertext.data() + off_enc, action.enc_ciphertext.data(), PRIVATE_ORCHARD_COMPACT_NOTE_SIZE);
            view_tag[i] = action.view_tag;
        }
        return true;
    }

    NitoOrchardCompactEffectsView RawView(const CPrivateCompactEffects& effects) const
    {
        return NitoOrchardCompactEffectsView{
            effects.actions.size(),
            DataPtr(nullifier),
            DataPtr(cmx),
            DataPtr(ephemeral_key),
            DataPtr(enc_ciphertext),
            DataPtr(view_tag),
        };
    }
};

PrivateOrchardBuildResult FillDecryptedNote(
    uint8_t matched,
    uint64_t value,
    const std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& recipient_raw,
    const std::array<unsigned char, 32>& cmx_out,
    const std::array<unsigned char, 32>& nullifier_out,
    const std::array<unsigned char, NITO_ORCHARD_RHO_SIZE>& rho,
    const std::array<unsigned char, NITO_ORCHARD_RSEED_SIZE>& rseed,
    const std::array<unsigned char, NITO_ORCHARD_MEMO_SIZE>& memo,
    PrivateOrchardDecryptedNote& note_out,
    std::string& error)
{
    if (matched == 0) {
        return PrivateOrchardBuildResult::OK;
    }
    if (value > static_cast<uint64_t>(MAX_MONEY)) {
        error = "decrypted note value is out of range";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    note_out.matched = true;
    note_out.value = static_cast<CAmount>(value);
    note_out.recipient_raw = recipient_raw;
    note_out.cmx = ReadUint256Ptr(cmx_out.data());
    note_out.nullifier = ReadUint256Ptr(nullifier_out.data());
    note_out.rho = rho;
    note_out.rseed = rseed;
    note_out.memo = memo;
    return PrivateOrchardBuildResult::OK;
}

void WriteCError(char* err_out, size_t err_out_len, const std::string& error)
{
    if (err_out == nullptr || err_out_len == 0) {
        return;
    }
    const size_t copy_len = std::min(error.size(), err_out_len - 1);
    std::memcpy(err_out, error.data(), copy_len);
    err_out[copy_len] = 0;
}

PrivateOrchardBuildResult MapBuildResult(int32_t code)
{
    switch (code) {
    case NITO_PRIVATE_OK:
        return PrivateOrchardBuildResult::OK;
    case NITO_PRIVATE_ERR_BAD_ENCODING:
        return PrivateOrchardBuildResult::BadEncoding;
    case NITO_PRIVATE_ERR_BUFFER_TOO_SMALL:
        return PrivateOrchardBuildResult::BufferTooSmall;
    case NITO_PRIVATE_ERR_BUILD:
        return PrivateOrchardBuildResult::BuildError;
    default:
        return PrivateOrchardBuildResult::EngineError;
    }
}

PrivateOrchardBuildResult FillBundleFromBuffers(
    const OrchardBuildBuffers& buffers,
    const uint256& anchor,
    CPrivateBundle& out,
    std::string& error)
{
    if (buffers.actions_len == 0 || buffers.actions_len > ORCHARD_BUILD_ACTION_CAP || buffers.proof_len > buffers.proof.size()) {
        error = "orchard builder returned inconsistent output lengths";
        return PrivateOrchardBuildResult::EngineError;
    }

    CPrivateBundle bundle;
    bundle.effects.flags = buffers.flags;
    bundle.effects.anchor = anchor;
    bundle.effects.value_balance = buffers.value_balance;
    bundle.effects.actions.resize(buffers.actions_len);
    bundle.auth.emplace();
    bundle.auth->actions_auth.resize(buffers.actions_len);
    bundle.auth->proof = ReadVector(buffers.proof, 0, buffers.proof_len);
    bundle.auth->binding_sig = buffers.binding_sig;

    for (size_t i = 0; i < buffers.actions_len; ++i) {
        const size_t off32 = i * 32;
        const size_t off_sig = i * PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE;
        const size_t off_enc = i * PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE;
        const size_t off_out = i * PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE;

        CPrivateActionEffects& action = bundle.effects.actions[i];
        action.cv = ReadUint256(buffers.cv_net, off32);
        action.nullifier = ReadUint256(buffers.nullifier, off32);
        action.rk = ReadUint256(buffers.rk, off32);
        action.cmx = ReadUint256(buffers.cmx, off32);
        action.ephemeral_key = ReadVector(buffers.ephemeral_key, off32, PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
        action.enc_ciphertext = ReadVector(buffers.enc_ciphertext, off_enc, PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE);
        action.out_ciphertext = ReadVector(buffers.out_ciphertext, off_out, PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE);

        bundle.auth->actions_auth[i].spend_auth_sig =
            ReadVector(buffers.spend_auth_sig, off_sig, PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE);
    }

    out = std::move(bundle);
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult FillEffectsFromBuffers(
    const OrchardBuildBuffers& buffers,
    const uint256& anchor,
    CPrivateBundle& out,
    std::string& error)
{
    if (buffers.actions_len == 0 || buffers.actions_len > ORCHARD_BUILD_ACTION_CAP) {
        error = "orchard builder returned inconsistent effects length";
        return PrivateOrchardBuildResult::EngineError;
    }

    CPrivateBundle bundle;
    bundle.effects.flags = buffers.flags;
    bundle.effects.anchor = anchor;
    bundle.effects.value_balance = buffers.value_balance;
    bundle.effects.actions.resize(buffers.actions_len);

    for (size_t i = 0; i < buffers.actions_len; ++i) {
        const size_t off32 = i * 32;
        const size_t off_enc = i * PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE;
        const size_t off_out = i * PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE;

        CPrivateActionEffects& action = bundle.effects.actions[i];
        action.cv = ReadUint256(buffers.cv_net, off32);
        action.nullifier = ReadUint256(buffers.nullifier, off32);
        action.rk = ReadUint256(buffers.rk, off32);
        action.cmx = ReadUint256(buffers.cmx, off32);
        action.ephemeral_key = ReadVector(buffers.ephemeral_key, off32, PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
        action.enc_ciphertext = ReadVector(buffers.enc_ciphertext, off_enc, PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE);
        action.out_ciphertext = ReadVector(buffers.out_ciphertext, off_out, PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE);
    }

    out = std::move(bundle);
    return PrivateOrchardBuildResult::OK;
}

bool FillEffectsBundleFromView(const NitoOrchardEffectsView& view, const uint256& anchor, CPrivateBundle& out, std::string& error)
{
    if (view.actions_len == 0 || view.actions_len > ORCHARD_BUILD_ACTION_CAP) {
        error = "orchard builder passed inconsistent effects length";
        return false;
    }
    if (view.anchor == nullptr || view.cv_net == nullptr || view.nullifier == nullptr || view.rk == nullptr || view.cmx == nullptr ||
        view.ephemeral_key == nullptr || view.enc_ciphertext == nullptr || view.out_ciphertext == nullptr) {
        error = "orchard builder passed null effects pointer";
        return false;
    }
    const uint256 view_anchor = ReadUint256Ptr(view.anchor);
    if (view_anchor != anchor) {
        error = "orchard builder passed inconsistent anchor";
        return false;
    }

    CPrivateBundle bundle;
    bundle.effects.flags = view.flags;
    bundle.effects.anchor = view_anchor;
    bundle.effects.value_balance = view.value_balance;
    bundle.effects.actions.resize(view.actions_len);

    for (size_t i = 0; i < view.actions_len; ++i) {
        const size_t off32 = i * 32;
        const size_t off_enc = i * PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE;
        const size_t off_out = i * PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE;

        CPrivateActionEffects& action = bundle.effects.actions[i];
        action.cv = ReadUint256Ptr(view.cv_net + off32);
        action.nullifier = ReadUint256Ptr(view.nullifier + off32);
        action.rk = ReadUint256Ptr(view.rk + off32);
        action.cmx = ReadUint256Ptr(view.cmx + off32);
        action.ephemeral_key = ReadVectorPtr(view.ephemeral_key + off32, PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
        action.enc_ciphertext = ReadVectorPtr(view.enc_ciphertext + off_enc, PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE);
        action.out_ciphertext = ReadVectorPtr(view.out_ciphertext + off_out, PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE);
    }

    out = std::move(bundle);
    return true;
}

struct SighashCallbackContext {
    const PrivateOrchardSighashFn* callback{nullptr};
    const uint256* anchor{nullptr};
    std::string* error{nullptr};
};

extern "C" int32_t ComputeSighashCallback(void* ctx, const NitoOrchardEffectsView* effects, uint8_t* sighash_out, char* err_out, size_t err_out_len)
{
    if (ctx == nullptr || effects == nullptr || sighash_out == nullptr) {
        WriteCError(err_out, err_out_len, "sighash callback received a null pointer");
        return NITO_PRIVATE_ERR_NULL_PTR;
    }

    auto* context = static_cast<SighashCallbackContext*>(ctx);
    if (context->callback == nullptr || context->anchor == nullptr || context->error == nullptr) {
        WriteCError(err_out, err_out_len, "sighash callback context is incomplete");
        return NITO_PRIVATE_ERR_NULL_PTR;
    }

    try {
        CPrivateBundle effects_bundle;
        std::string local_error;
        if (!FillEffectsBundleFromView(*effects, *context->anchor, effects_bundle, local_error)) {
            *context->error = local_error;
            WriteCError(err_out, err_out_len, local_error);
            return NITO_PRIVATE_ERR_BUILD;
        }

        uint256 sighash;
        if (!(*context->callback)(effects_bundle, sighash, local_error)) {
            *context->error = local_error;
            WriteCError(err_out, err_out_len, local_error.empty() ? "sighash callback failed" : local_error);
            return NITO_PRIVATE_ERR_BUILD;
        }
        std::memcpy(sighash_out, sighash.begin(), 32);
        return NITO_PRIVATE_OK;
    } catch (const std::exception& e) {
        *context->error = e.what();
        WriteCError(err_out, err_out_len, *context->error);
        return NITO_PRIVATE_ERR_BUILD;
    } catch (...) {
        *context->error = "sighash callback threw an unknown exception";
        WriteCError(err_out, err_out_len, *context->error);
        return NITO_PRIVATE_ERR_BUILD;
    }
}
} // namespace

uint256 PrivateBundleSighash(const CTransaction& tx)
{
    return PrivateBundleSighashImpl(tx);
}

uint256 PrivateBundleSighash(const CMutableTransaction& tx)
{
    return PrivateBundleSighashImpl(tx);
}

PrivateOrchardBuildResult DerivePrivateOrchardRawAddress(
    Span<const unsigned char> spending_key,
    uint32_t diversifier_index,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& recipient_raw,
    std::string& error)
{
    return DerivePrivateOrchardRawAddressScoped(
        spending_key,
        diversifier_index,
        false,
        recipient_raw,
        error);
}

PrivateOrchardBuildResult DerivePrivateOrchardRawAddressScoped(
    Span<const unsigned char> spending_key,
    uint32_t diversifier_index,
    bool internal_scope,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& recipient_raw,
    std::string& error)
{
    error.clear();

    if (spending_key.size() != 32) {
        error = "spending_key: expected 32-byte Orchard spending key";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_raw_address_from_spending_key_scoped(
        spending_key.data(),
        diversifier_index,
        internal_scope,
        recipient_raw.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }

    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult DerivePrivateOrchardFullViewingKey(
    Span<const unsigned char> spending_key,
    std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE>& full_viewing_key,
    std::string& error)
{
    error.clear();

    if (spending_key.size() != 32) {
        error = "spending_key: expected 32-byte Orchard spending key";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_full_viewing_key_from_spending_key(
        spending_key.data(),
        full_viewing_key.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }

    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult DerivePrivateOrchardRawAddressFromFullViewingKeyScoped(
    Span<const unsigned char> full_viewing_key,
    uint32_t diversifier_index,
    bool internal_scope,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& recipient_raw,
    std::string& error)
{
    error.clear();

    if (full_viewing_key.size() != NITO_ORCHARD_FULL_VIEWING_KEY_SIZE) {
        error = "full_viewing_key: expected 96-byte Orchard full viewing key";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_raw_address_from_full_viewing_key_scoped(
        full_viewing_key.data(),
        diversifier_index,
        internal_scope,
        recipient_raw.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }

    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult GetPrivateOrchardDiversifierIndex(
    Span<const unsigned char> full_viewing_key,
    bool internal_scope,
    Span<const unsigned char> raw_address,
    bool& matched_out,
    uint32_t& diversifier_index_out,
    std::string& error)
{
    error.clear();
    matched_out = false;
    diversifier_index_out = std::numeric_limits<uint32_t>::max();

    if (full_viewing_key.size() != NITO_ORCHARD_FULL_VIEWING_KEY_SIZE) {
        error = "full_viewing_key: expected 96-byte Orchard full viewing key";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (raw_address.size() != ORCHARD_RAW_ADDRESS_SIZE) {
        error = "raw_address: expected 43-byte Orchard address";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    uint8_t matched{0};
    uint32_t diversifier_index{std::numeric_limits<uint32_t>::max()};
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_fvk_diversifier_index(
        full_viewing_key.data(),
        internal_scope,
        raw_address.data(),
        &matched,
        &diversifier_index,
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }

    matched_out = matched != 0;
    diversifier_index_out = diversifier_index;
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult BuildPrivateOrchardOutputBundle(
    Span<const unsigned char> recipient_raw,
    CAmount value,
    const uint256& anchor,
    const uint256& sighash,
    CPrivateBundle& out,
    std::string& error)
{
    error.clear();

    if (recipient_raw.size() != ORCHARD_RAW_ADDRESS_SIZE) {
        error = "recipient: expected 43-byte raw Orchard address";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (value <= 0 || !MoneyRange(value)) {
        error = "value: amount out of range";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    uint8_t flags = 0;
    int64_t value_balance = 0;
    size_t actions_len = 0;
    size_t proof_len = 0;
    std::vector<unsigned char> cv_net(ORCHARD_BUILD_ACTION_CAP * 32);
    std::vector<unsigned char> nullifier(ORCHARD_BUILD_ACTION_CAP * 32);
    std::vector<unsigned char> rk(ORCHARD_BUILD_ACTION_CAP * 32);
    std::vector<unsigned char> cmx(ORCHARD_BUILD_ACTION_CAP * 32);
    std::vector<unsigned char> ephemeral_key(ORCHARD_BUILD_ACTION_CAP * PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
    std::vector<unsigned char> enc_ciphertext(ORCHARD_BUILD_ACTION_CAP * PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE);
    std::vector<unsigned char> out_ciphertext(ORCHARD_BUILD_ACTION_CAP * PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE);
    std::vector<unsigned char> spend_auth_sig(ORCHARD_BUILD_ACTION_CAP * PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE);
    std::vector<unsigned char> proof(ORCHARD_BUILD_PROOF_CAP);
    std::vector<unsigned char> binding_sig(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE);

    NitoOrchardBuildOutput raw_out{
        &flags,
        &value_balance,
        &actions_len,
        ORCHARD_BUILD_ACTION_CAP,
        MutableDataPtr(cv_net),
        MutableDataPtr(nullifier),
        MutableDataPtr(rk),
        MutableDataPtr(cmx),
        MutableDataPtr(ephemeral_key),
        MutableDataPtr(enc_ciphertext),
        MutableDataPtr(out_ciphertext),
        MutableDataPtr(spend_auth_sig),
        MutableDataPtr(proof),
        proof.size(),
        &proof_len,
        MutableDataPtr(binding_sig),
    };

    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_build_output_bundle(
        recipient_raw.data(),
        static_cast<uint64_t>(value),
        DataPtr(anchor),
        DataPtr(sighash),
        &raw_out,
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }
    if (actions_len == 0 || actions_len > ORCHARD_BUILD_ACTION_CAP || proof_len > proof.size()) {
        error = "orchard builder returned inconsistent output lengths";
        return PrivateOrchardBuildResult::EngineError;
    }

    CPrivateBundle bundle;
    bundle.effects.flags = flags;
    bundle.effects.anchor = anchor;
    bundle.effects.value_balance = value_balance;
    bundle.effects.actions.resize(actions_len);
    bundle.auth.emplace();
    bundle.auth->actions_auth.resize(actions_len);
    bundle.auth->proof = ReadVector(proof, 0, proof_len);
    bundle.auth->binding_sig = std::move(binding_sig);

    for (size_t i = 0; i < actions_len; ++i) {
        const size_t off32 = i * 32;
        const size_t off_sig = i * PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE;
        const size_t off_enc = i * PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE;
        const size_t off_out = i * PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE;

        CPrivateActionEffects& action = bundle.effects.actions[i];
        action.cv = ReadUint256(cv_net, off32);
        action.nullifier = ReadUint256(nullifier, off32);
        action.rk = ReadUint256(rk, off32);
        action.cmx = ReadUint256(cmx, off32);
        action.ephemeral_key = ReadVector(ephemeral_key, off32, PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
        action.enc_ciphertext = ReadVector(enc_ciphertext, off_enc, PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE);
        action.out_ciphertext = ReadVector(out_ciphertext, off_out, PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE);

        bundle.auth->actions_auth[i].spend_auth_sig =
            ReadVector(spend_auth_sig, off_sig, PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE);
    }

    out = std::move(bundle);
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult BuildPrivateOrchardOutputBundleWithSighashCallback(
    Span<const unsigned char> recipient_raw,
    CAmount value,
    const uint256& anchor,
    const PrivateOrchardSighashFn& sighash_callback,
    CPrivateBundle& out,
    std::string& error)
{
    error.clear();

    if (recipient_raw.size() != ORCHARD_RAW_ADDRESS_SIZE) {
        error = "recipient: expected 43-byte raw Orchard address";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (value <= 0 || !MoneyRange(value)) {
        error = "value: amount out of range";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (!sighash_callback) {
        error = "sighash callback is not set";
        return PrivateOrchardBuildResult::BuildError;
    }

    OrchardBuildBuffers buffers;
    NitoOrchardBuildOutput raw_out = buffers.RawOutput();
    SighashCallbackContext callback_context{&sighash_callback, &anchor, &error};

    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_build_output_bundle_with_sighash_callback(
        recipient_raw.data(),
        static_cast<uint64_t>(value),
        DataPtr(anchor),
        &raw_out,
        ComputeSighashCallback,
        &callback_context,
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        if (error.empty()) {
            error = ffi_error.data();
        }
        return MapBuildResult(code);
    }

    return FillBundleFromBuffers(buffers, anchor, out, error);
}

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
    std::string& error)
{
    error.clear();

    if (spending_key.size() != 32) {
        error = "spending_key: expected 32-byte Orchard spending key";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (note_recipient_raw.size() != ORCHARD_RAW_ADDRESS_SIZE || output_recipient_raw.size() != ORCHARD_RAW_ADDRESS_SIZE) {
        error = "recipient: expected 43-byte raw Orchard address";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (note_rho.size() != NITO_ORCHARD_RHO_SIZE || note_rseed.size() != NITO_ORCHARD_RSEED_SIZE) {
        error = "note randomness: expected 32-byte rho and 32-byte rseed";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (merkle_path.size() != NITO_ORCHARD_MERKLE_PATH_SIZE) {
        error = "merkle_path: expected 32 Orchard path elements";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (note_value <= 0 || output_value <= 0 || !MoneyRange(note_value) || !MoneyRange(output_value)) {
        error = "value: amount out of range";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (!sighash_callback) {
        error = "sighash callback is not set";
        return PrivateOrchardBuildResult::BuildError;
    }

    OrchardBuildBuffers buffers;
    NitoOrchardBuildOutput raw_out = buffers.RawOutput();
    SighashCallbackContext callback_context{&sighash_callback, &anchor, &error};
    NitoOrchardSpendRequest request{
        spending_key.data(),
        note_recipient_raw.data(),
        static_cast<uint64_t>(note_value),
        note_rho.data(),
        note_rseed.data(),
        note_position,
        merkle_path.data(),
        output_recipient_raw.data(),
        static_cast<uint64_t>(output_value),
        output_ovk_internal,
    };

    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_build_spend_bundle_with_sighash_callback(
        &request,
        DataPtr(anchor),
        &raw_out,
        ComputeSighashCallback,
        &callback_context,
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        if (error.empty()) {
            error = ffi_error.data();
        }
        return MapBuildResult(code);
    }

    return FillBundleFromBuffers(buffers, anchor, out, error);
}

PrivateOrchardBuildResult BuildPrivateOrchardBundleWithSighashCallback(
    Span<const PrivateOrchardSpendInfo> spends,
    Span<const PrivateOrchardOutputInfo> outputs,
    const uint256& anchor,
    const PrivateOrchardSighashFn& sighash_callback,
    CPrivateBundle& out,
    std::string& error)
{
    error.clear();

    if (spends.empty() && outputs.empty()) {
        error = "private bundle: empty spends and outputs";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (!sighash_callback) {
        error = "sighash callback is not set";
        return PrivateOrchardBuildResult::BuildError;
    }

    std::vector<NitoOrchardSpendInput> ffi_spends;
    ffi_spends.reserve(spends.size());
    for (const auto& spend : spends) {
        if (spend.spending_key.size() != 32) {
            error = "spending_key: expected 32-byte Orchard spending key";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (spend.note_recipient_raw.size() != ORCHARD_RAW_ADDRESS_SIZE) {
            error = "note_recipient: expected 43-byte raw Orchard address";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (spend.note_rho.size() != NITO_ORCHARD_RHO_SIZE || spend.note_rseed.size() != NITO_ORCHARD_RSEED_SIZE) {
            error = "note randomness: expected 32-byte rho and 32-byte rseed";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (spend.merkle_path.size() != NITO_ORCHARD_MERKLE_PATH_SIZE) {
            error = "merkle_path: expected 32 Orchard path elements";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (spend.note_value <= 0 || !MoneyRange(spend.note_value)) {
            error = "note_value: amount out of range";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        ffi_spends.push_back(NitoOrchardSpendInput{
            spend.spending_key.data(),
            spend.note_recipient_raw.data(),
            static_cast<uint64_t>(spend.note_value),
            spend.note_rho.data(),
            spend.note_rseed.data(),
            spend.note_position,
            spend.merkle_path.data(),
        });
    }

    std::vector<NitoOrchardOutputRequest> ffi_outputs;
    ffi_outputs.reserve(outputs.size());
    for (const auto& output : outputs) {
        if (output.recipient_raw.size() != ORCHARD_RAW_ADDRESS_SIZE) {
            error = "output_recipient: expected 43-byte raw Orchard address";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (output.value <= 0 || !MoneyRange(output.value)) {
            error = "output_value: amount out of range";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        ffi_outputs.push_back(NitoOrchardOutputRequest{
            output.recipient_raw.data(),
            static_cast<uint64_t>(output.value),
            output.ovk_internal,
        });
    }

    OrchardBuildBuffers buffers;
    NitoOrchardBuildOutput raw_out = buffers.RawOutput();
    SighashCallbackContext callback_context{&sighash_callback, &anchor, &error};

    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_build_bundle_with_sighash_callback(
        ffi_spends.empty() ? nullptr : ffi_spends.data(),
        ffi_spends.size(),
        ffi_outputs.empty() ? nullptr : ffi_outputs.data(),
        ffi_outputs.size(),
        DataPtr(anchor),
        &raw_out,
        ComputeSighashCallback,
        &callback_context,
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        if (error.empty()) {
            error = ffi_error.data();
        }
        return MapBuildResult(code);
    }

    return FillBundleFromBuffers(buffers, anchor, out, error);
}

PrivateOrchardBuildResult BuildPrivateOrchardBundleEffectsOnly(
    Span<const PrivateOrchardSpendInfo> spends,
    Span<const PrivateOrchardOutputInfo> outputs,
    const uint256& anchor,
    CPrivateBundle& out,
    std::string& error)
{
    error.clear();

    if (spends.empty() && outputs.empty()) {
        error = "private bundle: empty spends and outputs";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    std::vector<NitoOrchardSpendInput> ffi_spends;
    ffi_spends.reserve(spends.size());
    for (const auto& spend : spends) {
        if (spend.spending_key.size() != 32) {
            error = "spending_key: expected 32-byte Orchard spending key";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (spend.note_recipient_raw.size() != ORCHARD_RAW_ADDRESS_SIZE) {
            error = "note_recipient: expected 43-byte raw Orchard address";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (spend.note_rho.size() != NITO_ORCHARD_RHO_SIZE || spend.note_rseed.size() != NITO_ORCHARD_RSEED_SIZE) {
            error = "note randomness: expected 32-byte rho and 32-byte rseed";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (spend.merkle_path.size() != NITO_ORCHARD_MERKLE_PATH_SIZE) {
            error = "merkle_path: expected 32 Orchard path elements";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (spend.note_value <= 0 || !MoneyRange(spend.note_value)) {
            error = "note_value: amount out of range";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        ffi_spends.push_back(NitoOrchardSpendInput{
            spend.spending_key.data(),
            spend.note_recipient_raw.data(),
            static_cast<uint64_t>(spend.note_value),
            spend.note_rho.data(),
            spend.note_rseed.data(),
            spend.note_position,
            spend.merkle_path.data(),
        });
    }

    std::vector<NitoOrchardOutputRequest> ffi_outputs;
    ffi_outputs.reserve(outputs.size());
    for (const auto& output : outputs) {
        if (output.recipient_raw.size() != ORCHARD_RAW_ADDRESS_SIZE) {
            error = "output_recipient: expected 43-byte raw Orchard address";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (output.value <= 0 || !MoneyRange(output.value)) {
            error = "output_value: amount out of range";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        ffi_outputs.push_back(NitoOrchardOutputRequest{
            output.recipient_raw.data(),
            static_cast<uint64_t>(output.value),
            output.ovk_internal,
        });
    }

    OrchardBuildBuffers buffers;
    NitoOrchardBuildOutput raw_out = buffers.RawOutput();

    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_build_bundle_effects_only(
        ffi_spends.empty() ? nullptr : ffi_spends.data(),
        ffi_spends.size(),
        ffi_outputs.empty() ? nullptr : ffi_outputs.data(),
        ffi_outputs.size(),
        DataPtr(anchor),
        &raw_out,
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }

    return FillEffectsFromBuffers(buffers, anchor, out, error);
}

PrivateOrchardBuildResult DecryptPrivateOrchardOutput(
    Span<const unsigned char> spending_key,
    bool internal_scope,
    const CPrivateBundle& bundle,
    size_t action_idx,
    PrivateOrchardDecryptedNote& note_out,
    std::string& error)
{
    error.clear();
    note_out = PrivateOrchardDecryptedNote{};

    if (spending_key.size() != 32) {
        error = "spending_key: expected 32-byte Orchard spending key";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    const size_t actions_len = bundle.effects.actions.size();
    if (actions_len == 0 || action_idx >= actions_len) {
        error = "action index out of range";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    OrchardEffectsBuffers effects_buffers;
    if (!effects_buffers.Fill(bundle, error)) {
        return PrivateOrchardBuildResult::BadEncoding;
    }
    NitoOrchardEffectsView effects = effects_buffers.RawView(bundle);

    uint8_t matched{0};
    uint64_t value{0};
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> recipient_raw{};
    std::array<unsigned char, 32> cmx_out{};
    std::array<unsigned char, 32> nullifier_out{};
    std::array<unsigned char, NITO_ORCHARD_RHO_SIZE> rho{};
    std::array<unsigned char, NITO_ORCHARD_RSEED_SIZE> rseed{};
    std::array<unsigned char, NITO_ORCHARD_MEMO_SIZE> memo{};
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_decrypt_output(
        spending_key.data(),
        internal_scope,
        &effects,
        action_idx,
        &matched,
        &value,
        recipient_raw.data(),
        cmx_out.data(),
        nullifier_out.data(),
        rho.data(),
        rseed.data(),
        memo.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }
    return FillDecryptedNote(matched, value, recipient_raw, cmx_out, nullifier_out, rho, rseed, memo, note_out, error);
}

PrivateOrchardBuildResult DecryptPrivateOrchardOutputWithFullViewingKey(
    Span<const unsigned char> full_viewing_key,
    bool internal_scope,
    const CPrivateBundle& bundle,
    size_t action_idx,
    PrivateOrchardDecryptedNote& note_out,
    std::string& error)
{
    error.clear();
    note_out = PrivateOrchardDecryptedNote{};

    if (full_viewing_key.size() != NITO_ORCHARD_FULL_VIEWING_KEY_SIZE) {
        error = "full_viewing_key: expected 96-byte Orchard full viewing key";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    const size_t actions_len = bundle.effects.actions.size();
    if (actions_len == 0 || action_idx >= actions_len) {
        error = "action index out of range";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    OrchardEffectsBuffers effects_buffers;
    if (!effects_buffers.Fill(bundle, error)) {
        return PrivateOrchardBuildResult::BadEncoding;
    }
    NitoOrchardEffectsView effects = effects_buffers.RawView(bundle);

    uint8_t matched{0};
    uint64_t value{0};
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> recipient_raw{};
    std::array<unsigned char, 32> cmx_out{};
    std::array<unsigned char, 32> nullifier_out{};
    std::array<unsigned char, NITO_ORCHARD_RHO_SIZE> rho{};
    std::array<unsigned char, NITO_ORCHARD_RSEED_SIZE> rseed{};
    std::array<unsigned char, NITO_ORCHARD_MEMO_SIZE> memo{};
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_decrypt_output_with_fvk(
        full_viewing_key.data(),
        internal_scope,
        &effects,
        action_idx,
        &matched,
        &value,
        recipient_raw.data(),
        cmx_out.data(),
        nullifier_out.data(),
        rho.data(),
        rseed.data(),
        memo.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }
    return FillDecryptedNote(matched, value, recipient_raw, cmx_out, nullifier_out, rho, rseed, memo, note_out, error);
}

PrivateOrchardBuildResult ClassifyPrivateOrchardChangeOutputs(
    Span<const unsigned char> external_full_viewing_key,
    Span<const unsigned char> internal_full_viewing_key,
    const CPrivateBundle& bundle,
    std::vector<unsigned char>& change_out,
    std::string& error)
{
    error.clear();
    change_out.clear();
    if (external_full_viewing_key.size() != NITO_ORCHARD_FULL_VIEWING_KEY_SIZE ||
        internal_full_viewing_key.size() != NITO_ORCHARD_FULL_VIEWING_KEY_SIZE) {
        error = "change classification: expected two 96-byte Orchard full viewing keys";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    OrchardEffectsBuffers effects_buffers;
    if (!effects_buffers.Fill(bundle, error)) return PrivateOrchardBuildResult::BadEncoding;
    const NitoOrchardEffectsView effects = effects_buffers.RawView(bundle);
    change_out.resize(bundle.effects.actions.size());
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_classify_change_outputs(
        external_full_viewing_key.data(), internal_full_viewing_key.data(), &effects,
        change_out.data(), change_out.size(), ffi_error.data(), ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        change_out.clear();
        error = ffi_error.data();
        return MapBuildResult(code);
    }
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult DecryptPrivateOrchardCompactOutputsWithFullViewingKeys(
    Span<const PrivateOrchardViewingKey> viewing_keys,
    const CPrivateCompactEffects& effects,
    std::vector<PrivateOrchardCompactDecryptionResult>& results_out,
    std::string& error)
{
    error.clear();
    results_out.clear();

    if (effects.actions.empty()) {
        error = "compact private effects: empty actions";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    for (const auto& key : viewing_keys) {
        if (key.full_viewing_key.size() != NITO_ORCHARD_FULL_VIEWING_KEY_SIZE) {
            error = "full_viewing_key: expected 96-byte Orchard full viewing key";
            return PrivateOrchardBuildResult::BadEncoding;
        }
        if (key.has_diversifier && key.diversifier.size() != NITO_ORCHARD_DIVERSIFIER_SIZE) {
            error = "diversifier: expected 11-byte Orchard diversifier";
            return PrivateOrchardBuildResult::BadEncoding;
        }
    }

    OrchardCompactEffectsBuffers effects_buffers;
    if (!effects_buffers.Fill(effects, error)) {
        return PrivateOrchardBuildResult::BadEncoding;
    }
    NitoOrchardCompactEffectsView compact_effects = effects_buffers.RawView(effects);

    std::vector<unsigned char> fvk_bytes(viewing_keys.size() * NITO_ORCHARD_FULL_VIEWING_KEY_SIZE);
    std::vector<unsigned char> internal_scopes(viewing_keys.size());
    std::vector<unsigned char> diversifiers(viewing_keys.size() * NITO_ORCHARD_DIVERSIFIER_SIZE);
    std::vector<unsigned char> diversifier_known(viewing_keys.size());
    for (size_t i = 0; i < viewing_keys.size(); ++i) {
        std::memcpy(fvk_bytes.data() + i * NITO_ORCHARD_FULL_VIEWING_KEY_SIZE,
                    viewing_keys[i].full_viewing_key.data(),
                    NITO_ORCHARD_FULL_VIEWING_KEY_SIZE);
        internal_scopes[i] = viewing_keys[i].internal ? 1 : 0;
        if (viewing_keys[i].has_diversifier) {
            diversifier_known[i] = 1;
            std::memcpy(diversifiers.data() + i * NITO_ORCHARD_DIVERSIFIER_SIZE,
                        viewing_keys[i].diversifier.data(),
                        NITO_ORCHARD_DIVERSIFIER_SIZE);
        }
    }

    const size_t actions_len = effects.actions.size();
    std::vector<unsigned char> matched(actions_len);
    std::vector<uint32_t> key_index(actions_len, std::numeric_limits<uint32_t>::max());
    std::vector<uint64_t> value(actions_len);
    std::vector<unsigned char> recipient_raw(actions_len * NITO_ORCHARD_RAW_ADDRESS_SIZE);
    std::vector<unsigned char> cmx(actions_len * 32);
    std::vector<unsigned char> nullifier(actions_len * 32);
    std::vector<unsigned char> rho(actions_len * NITO_ORCHARD_RHO_SIZE);
    std::vector<unsigned char> rseed(actions_len * NITO_ORCHARD_RSEED_SIZE);
    std::array<char, 256> ffi_error{};
    auto cleanse_decrypted_buffers = [&]() {
        memory_cleanse(value.data(), value.size() * sizeof(value[0]));
        memory_cleanse(recipient_raw.data(), recipient_raw.size());
        memory_cleanse(cmx.data(), cmx.size());
        memory_cleanse(nullifier.data(), nullifier.size());
        memory_cleanse(rho.data(), rho.size());
        memory_cleanse(rseed.data(), rseed.size());
    };

    const int32_t code = nito_orchard_batch_decrypt_compact_outputs_with_fvks(
        fvk_bytes.data(),
        internal_scopes.data(),
        diversifiers.data(),
        diversifier_known.data(),
        viewing_keys.size(),
        &compact_effects,
        matched.data(),
        key_index.data(),
        value.data(),
        recipient_raw.data(),
        cmx.data(),
        nullifier.data(),
        rho.data(),
        rseed.data(),
        ffi_error.data(),
        ffi_error.size());
    memory_cleanse(fvk_bytes.data(), fvk_bytes.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        cleanse_decrypted_buffers();
        return MapBuildResult(code);
    }

    results_out.resize(actions_len);
    for (size_t i = 0; i < actions_len; ++i) {
        auto& result = results_out[i];
        result.matched = matched[i] != 0;
        if (!result.matched) continue;
        if (value[i] > static_cast<uint64_t>(MAX_MONEY)) {
            error = "decrypted compact note value is out of range";
            cleanse_decrypted_buffers();
            return PrivateOrchardBuildResult::BadEncoding;
        }
        result.viewing_key_index = key_index[i];
        if (result.viewing_key_index >= viewing_keys.size()) {
            error = "decrypted compact note references an unknown viewing key";
            cleanse_decrypted_buffers();
            return PrivateOrchardBuildResult::BadEncoding;
        }
        result.note.matched = true;
        result.note.value = static_cast<CAmount>(value[i]);
        std::copy_n(recipient_raw.data() + i * NITO_ORCHARD_RAW_ADDRESS_SIZE,
                    NITO_ORCHARD_RAW_ADDRESS_SIZE,
                    result.note.recipient_raw.begin());
        result.note.cmx = ReadUint256Ptr(cmx.data() + i * 32);
        result.note.nullifier = ReadUint256Ptr(nullifier.data() + i * 32);
        std::copy_n(rho.data() + i * NITO_ORCHARD_RHO_SIZE,
                    NITO_ORCHARD_RHO_SIZE,
                    result.note.rho.begin());
        std::copy_n(rseed.data() + i * NITO_ORCHARD_RSEED_SIZE,
                    NITO_ORCHARD_RSEED_SIZE,
                    result.note.rseed.begin());
    }
    cleanse_decrypted_buffers();
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult ComputePrivateOrchardNoteCommitment(
    Span<const unsigned char> recipient_raw,
    CAmount value,
    Span<const unsigned char> rho,
    Span<const unsigned char> rseed,
    uint256& cmx_out,
    std::string& error)
{
    error.clear();
    cmx_out.SetNull();

    if (recipient_raw.size() != ORCHARD_RAW_ADDRESS_SIZE) {
        error = "recipient: expected 43-byte raw Orchard address";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (rho.size() != NITO_ORCHARD_RHO_SIZE || rseed.size() != NITO_ORCHARD_RSEED_SIZE) {
        error = "note randomness: expected 32-byte rho and 32-byte rseed";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (value <= 0 || !MoneyRange(value)) {
        error = "value: amount out of range";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    std::array<unsigned char, 32> cmx{};
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_compute_note_commitment(
        recipient_raw.data(),
        static_cast<uint64_t>(value),
        rho.data(),
        rseed.data(),
        cmx.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }

    cmx_out = ReadUint256Ptr(cmx.data());
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult ComputePrivateOrchardAuthPath(
    Span<const uint256> commitments,
    uint32_t position,
    std::vector<uint256>& auth_path,
    uint256& root_out,
    std::string& error)
{
    error.clear();
    auth_path.clear();

    if (commitments.empty()) {
        error = "commitments: empty";
        return PrivateOrchardBuildResult::BadEncoding;
    }
    if (position >= commitments.size()) {
        error = "position outside commitment list";
        return PrivateOrchardBuildResult::BadEncoding;
    }

    std::vector<unsigned char> flat;
    flat.reserve(commitments.size() * 32);
    for (const auto& cmx : commitments) {
        flat.insert(flat.end(), cmx.begin(), cmx.end());
    }

    std::vector<unsigned char> path(NITO_ORCHARD_MERKLE_PATH_SIZE);
    std::array<unsigned char, 32> root{};
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_compute_auth_path(
        flat.data(),
        commitments.size(),
        position,
        path.data(),
        root.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }

    auth_path.reserve(32);
    for (size_t i = 0; i < 32; ++i) {
        auth_path.push_back(ReadUint256(path, i * 32));
    }
    root_out = ReadUint256Ptr(root.data());
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult ComputePrivateOrchardParent(
    uint8_t level,
    const uint256& left,
    const uint256& right,
    uint256& parent_out,
    std::string& error)
{
    error.clear();
    parent_out.SetNull();

    std::array<unsigned char, 32> parent{};
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_combine_nodes(
        level,
        DataPtr(left),
        DataPtr(right),
        parent.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }

    parent_out = ReadUint256Ptr(parent.data());
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardBuildResult GetPrivateOrchardEmptyRoot(
    uint8_t level,
    uint256& root_out,
    std::string& error)
{
    error.clear();
    root_out.SetNull();

    std::array<unsigned char, 32> root{};
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_empty_root(
        level,
        root.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != NITO_PRIVATE_OK) {
        error = ffi_error.data();
        return MapBuildResult(code);
    }

    root_out = ReadUint256Ptr(root.data());
    return PrivateOrchardBuildResult::OK;
}

PrivateOrchardVerifyResult VerifyPrivateOrchardBundle(const CTransaction& tx, std::string& error)
{
    error.clear();

    if (!tx.HasPrivateBundle() || !tx.HasPrivateAuth()) {
        error = "missing private bundle or authorization";
        return PrivateOrchardVerifyResult::BadEncoding;
    }

    const CPrivateBundle& bundle = *tx.m_private_bundle;
    const CPrivateAuth& auth = *bundle.auth;
    if (!CheckPrivateOrchardVerifierBuffers(bundle, error)) {
        return PrivateOrchardVerifyResult::BadEncoding;
    }

    std::vector<NitoOrchardAction> actions;
    actions.reserve(bundle.effects.actions.size());
    for (size_t i = 0; i < bundle.effects.actions.size(); ++i) {
        const auto& effects = bundle.effects.actions[i];
        const auto& action_auth = auth.actions_auth[i];
        actions.push_back(NitoOrchardAction{
            DataPtr(effects.cv),
            DataPtr(effects.nullifier),
            DataPtr(effects.rk),
            DataPtr(effects.cmx),
            DataPtr(effects.ephemeral_key),
            DataPtr(effects.enc_ciphertext),
            DataPtr(effects.out_ciphertext),
            DataPtr(action_auth.spend_auth_sig),
        });
    }

    const uint256 sighash = PrivateBundleSighash(tx);
    NitoOrchardBundle raw_bundle{
        bundle.effects.flags,
        bundle.effects.value_balance,
        DataPtr(bundle.effects.anchor),
        actions.data(),
        actions.size(),
        DataPtr(auth.proof),
        auth.proof.size(),
        DataPtr(auth.binding_sig),
        DataPtr(sighash),
    };

    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_verify_bundle(&raw_bundle, ffi_error.data(), ffi_error.size());
    if (code == NITO_PRIVATE_OK) {
        return PrivateOrchardVerifyResult::OK;
    }

    error = ffi_error.data();
    switch (code) {
    case NITO_PRIVATE_ERR_BAD_ENCODING:
        return PrivateOrchardVerifyResult::BadEncoding;
    case NITO_PRIVATE_ERR_BAD_PROOF:
        return PrivateOrchardVerifyResult::BadProof;
    case NITO_PRIVATE_ERR_BAD_SPEND_SIG:
        return PrivateOrchardVerifyResult::BadSpendAuth;
    case NITO_PRIVATE_ERR_BAD_BINDING_SIG:
        return PrivateOrchardVerifyResult::BadBindingSig;
    default:
        return PrivateOrchardVerifyResult::EngineError;
    }
}
