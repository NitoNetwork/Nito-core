// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIVATE_ORCHARD_FFI_H
#define BITCOIN_PRIVATE_ORCHARD_FFI_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NitoOrchardAction {
    const uint8_t* cv_net;
    const uint8_t* nullifier;
    const uint8_t* rk;
    const uint8_t* cmx;
    const uint8_t* ephemeral_key;
    const uint8_t* enc_ciphertext;
    const uint8_t* out_ciphertext;
    const uint8_t* spend_auth_sig;
} NitoOrchardAction;

typedef struct NitoOrchardBundle {
    uint8_t flags;
    int64_t value_balance;
    const uint8_t* anchor;
    const NitoOrchardAction* actions;
    size_t actions_len;
    const uint8_t* proof;
    size_t proof_len;
    const uint8_t* binding_sig;
    const uint8_t* sighash;
} NitoOrchardBundle;

typedef struct NitoOrchardBuildOutput {
    uint8_t* flags_out;
    int64_t* value_balance_out;
    size_t* actions_len_out;
    size_t actions_cap;
    uint8_t* cv_net_out;
    uint8_t* nullifier_out;
    uint8_t* rk_out;
    uint8_t* cmx_out;
    uint8_t* ephemeral_key_out;
    uint8_t* enc_ciphertext_out;
    uint8_t* out_ciphertext_out;
    uint8_t* spend_auth_sig_out;
    uint8_t* proof_out;
    size_t proof_cap;
    size_t* proof_len_out;
    uint8_t* binding_sig_out;
} NitoOrchardBuildOutput;

typedef struct NitoOrchardEffectsView {
    uint8_t flags;
    int64_t value_balance;
    const uint8_t* anchor;
    size_t actions_len;
    const uint8_t* cv_net;
    const uint8_t* nullifier;
    const uint8_t* rk;
    const uint8_t* cmx;
    const uint8_t* ephemeral_key;
    const uint8_t* enc_ciphertext;
    const uint8_t* out_ciphertext;
} NitoOrchardEffectsView;

typedef struct NitoOrchardCompactEffectsView {
    size_t actions_len;
    const uint8_t* nullifier;
    const uint8_t* cmx;
    const uint8_t* ephemeral_key;
    const uint8_t* enc_ciphertext;
    const uint8_t* view_tag;
} NitoOrchardCompactEffectsView;

typedef struct NitoOrchardSpendRequest {
    const uint8_t* spending_key;
    const uint8_t* note_recipient_raw;
    uint64_t note_value;
    const uint8_t* note_rho;
    const uint8_t* note_rseed;
    uint32_t note_position;
    const uint8_t* merkle_path;
    const uint8_t* output_recipient_raw;
    uint64_t output_value;
    bool output_ovk_internal;
} NitoOrchardSpendRequest;

typedef struct NitoOrchardSpendInput {
    const uint8_t* spending_key;
    const uint8_t* note_recipient_raw;
    uint64_t note_value;
    const uint8_t* note_rho;
    const uint8_t* note_rseed;
    uint32_t note_position;
    const uint8_t* merkle_path;
} NitoOrchardSpendInput;

typedef struct NitoOrchardOutputRequest {
    const uint8_t* recipient_raw;
    uint64_t value;
    bool ovk_internal;
} NitoOrchardOutputRequest;

typedef int32_t (*NitoOrchardSighashCallback)(
    void* ctx,
    const NitoOrchardEffectsView* effects,
    uint8_t* sighash_out,
    char* err_out,
    size_t err_out_len);

int32_t nito_orchard_build_output_bundle(
    const uint8_t* recipient_raw,
    uint64_t value,
    const uint8_t* anchor,
    const uint8_t* sighash,
    NitoOrchardBuildOutput* out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_build_output_bundle_with_sighash_callback(
    const uint8_t* recipient_raw,
    uint64_t value,
    const uint8_t* anchor,
    NitoOrchardBuildOutput* out,
    NitoOrchardSighashCallback sighash_callback,
    void* sighash_ctx,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_build_spend_bundle_with_sighash_callback(
    const NitoOrchardSpendRequest* request,
    const uint8_t* anchor,
    NitoOrchardBuildOutput* out,
    NitoOrchardSighashCallback sighash_callback,
    void* sighash_ctx,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_build_bundle_with_sighash_callback(
    const NitoOrchardSpendInput* spends,
    size_t spends_len,
    const NitoOrchardOutputRequest* outputs,
    size_t outputs_len,
    const uint8_t* anchor,
    NitoOrchardBuildOutput* out,
    NitoOrchardSighashCallback sighash_callback,
    void* sighash_ctx,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_build_bundle_effects_only(
    const NitoOrchardSpendInput* spends,
    size_t spends_len,
    const NitoOrchardOutputRequest* outputs,
    size_t outputs_len,
    const uint8_t* anchor,
    NitoOrchardBuildOutput* out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_raw_address_from_spending_key(
    const uint8_t* spending_key,
    uint32_t diversifier_index,
    uint8_t* raw_address_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_raw_address_from_spending_key_scoped(
    const uint8_t* spending_key,
    uint32_t diversifier_index,
    bool internal_scope,
    uint8_t* raw_address_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_full_viewing_key_from_spending_key(
    const uint8_t* spending_key,
    uint8_t* full_viewing_key_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_raw_address_from_full_viewing_key_scoped(
    const uint8_t* full_viewing_key,
    uint32_t diversifier_index,
    bool internal_scope,
    uint8_t* raw_address_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_fvk_diversifier_index(
    const uint8_t* full_viewing_key,
    bool internal_scope,
    const uint8_t* raw_address,
    uint8_t* matched_out,
    uint32_t* diversifier_index_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_verify_bundle(const NitoOrchardBundle* bundle, char* err_out, size_t err_out_len);
int32_t nito_orchard_classify_change_outputs(
    const uint8_t* external_full_viewing_key,
    const uint8_t* internal_full_viewing_key,
    const NitoOrchardEffectsView* effects,
    uint8_t* change_out,
    size_t change_out_len,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_decrypt_output(
    const uint8_t* spending_key,
    bool internal_scope,
    const NitoOrchardEffectsView* effects,
    size_t action_idx,
    uint8_t* matched_out,
    uint64_t* value_out,
    uint8_t* recipient_raw_out,
    uint8_t* cmx_out,
    uint8_t* nullifier_out,
    uint8_t* rho_out,
    uint8_t* rseed_out,
    uint8_t* memo_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_decrypt_output_with_fvk(
    const uint8_t* full_viewing_key,
    bool internal_scope,
    const NitoOrchardEffectsView* effects,
    size_t action_idx,
    uint8_t* matched_out,
    uint64_t* value_out,
    uint8_t* recipient_raw_out,
    uint8_t* cmx_out,
    uint8_t* nullifier_out,
    uint8_t* rho_out,
    uint8_t* rseed_out,
    uint8_t* memo_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_batch_decrypt_compact_outputs_with_fvks(
    const uint8_t* full_viewing_keys,
    const uint8_t* internal_scopes,
    const uint8_t* diversifiers,
    const uint8_t* diversifier_known,
    size_t viewing_keys_len,
    const NitoOrchardCompactEffectsView* effects,
    uint8_t* matched_out,
    uint32_t* key_index_out,
    uint64_t* value_out,
    uint8_t* recipient_raw_out,
    uint8_t* cmx_out,
    uint8_t* nullifier_out,
    uint8_t* rho_out,
    uint8_t* rseed_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_compute_note_commitment(
    const uint8_t* recipient_raw,
    uint64_t value,
    const uint8_t* rho,
    const uint8_t* rseed,
    uint8_t* cmx_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_compute_auth_path(
    const uint8_t* cmx_list,
    size_t cmx_count,
    uint32_t position,
    uint8_t* path_out,
    uint8_t* root_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_compute_root(
    const uint8_t* cmx_list,
    size_t cmx_count,
    uint8_t* root_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_combine_nodes(
    uint8_t level,
    const uint8_t* left,
    const uint8_t* right,
    uint8_t* parent_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_empty_root(
    uint8_t level,
    uint8_t* root_out,
    char* err_out,
    size_t err_out_len);
int32_t nito_orchard_frontier_append(
    const uint8_t* frontier_in,
    size_t frontier_in_len,
    const uint8_t* cmx_list,
    size_t cmx_count,
    uint8_t* root_out,
    uint8_t* frontier_out,
    size_t frontier_out_capacity,
    size_t* frontier_out_len,
    char* err_out,
    size_t err_out_len);

#ifdef __cplusplus
}
#endif

#endif // BITCOIN_PRIVATE_ORCHARD_FFI_H
