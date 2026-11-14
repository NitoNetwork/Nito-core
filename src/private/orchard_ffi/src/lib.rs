use std::ffi::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::OnceLock;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use incrementalmerkletree::{
    frontier::{CommitmentTree, Frontier},
    Hashable, Level, Position,
};
use nonempty::NonEmpty;
use orchard::builder::{Builder, BundleType};
use orchard::bundle::{Authorized, BundleVersion, EffectsOnly, Flags};
use orchard::circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey};
use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::note::{
    ExtractedNoteCommitment, Note, Nullifier, RandomSeed, Rho, TransmittedNoteCiphertext,
};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use orchard::primitives::redpallas::{self, Binding, SpendAuth};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::{NoteValue, ValueCommitment};
use orchard::{Action, Address, Anchor, Bundle, Proof};
use rand_core::OsRng;
use zcash_note_encryption::{
    try_compact_note_decryption, BatchDomain, Domain, EphemeralKeyBytes, ShieldedOutput,
};

#[cfg(test)]
mod fixed_circuit_vectors;

const NITO_PRIVATE_OK: i32 = 0;
const NITO_PRIVATE_ERR_NULL_PTR: i32 = 1;
const NITO_PRIVATE_ERR_BAD_ENCODING: i32 = 2;
const NITO_PRIVATE_ERR_BAD_PROOF: i32 = 3;
const NITO_PRIVATE_ERR_BAD_SPEND_SIG: i32 = 4;
const NITO_PRIVATE_ERR_BAD_BINDING_SIG: i32 = 5;
const NITO_PRIVATE_ERR_BUFFER_TOO_SMALL: i32 = 6;
const NITO_PRIVATE_ERR_BUILD: i32 = 7;
const NITO_PRIVATE_ERR_PANIC: i32 = 255;

const ORCHARD_RAW_ADDRESS_SIZE: usize = 43;
const ORCHARD_DIVERSIFIER_SIZE: usize = 11;
const ORCHARD_EPK_SIZE: usize = 32;
const ORCHARD_ENC_CIPHERTEXT_SIZE: usize = 580;
const ORCHARD_COMPACT_NOTE_SIZE: usize = 52;
const ORCHARD_OUT_CIPHERTEXT_SIZE: usize = 80;
const REDPALLAS_SIG_SIZE: usize = 64;
const NITO_SIGNATURE_HASH_SIZE: usize = 32;
const ORCHARD_MERKLE_DEPTH: u8 = 32;
const ORCHARD_MERKLE_DEPTH_USIZE: usize = ORCHARD_MERKLE_DEPTH as usize;
const ORCHARD_FRONTIER_VERSION: u8 = 1;
const ORCHARD_FRONTIER_MAX_SIZE: usize = 1 + 8 + 32 + 1 + (32 * ORCHARD_MERKLE_DEPTH_USIZE);

static VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();
static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();

// Nito v4 intentionally uses the fixed Orchard V2 protocol and circuit. A
// future Orchard protocol version must be introduced as an explicit Nito
// consensus change, never inherited from a dependency default.
const NITO_ORCHARD_BUNDLE_VERSION: BundleVersion = BundleVersion::orchard_v2();
const NITO_ORCHARD_CIRCUIT_VERSION: OrchardCircuitVersion = OrchardCircuitVersion::FixedPostNu6_2;

fn nito_orchard_flags_byte(flags: Flags) -> u8 {
    flags
        .to_byte(NITO_ORCHARD_BUNDLE_VERSION)
        .expect("Orchard V2 flags must be representable")
}

fn nito_orchard_builder(anchor: Anchor) -> Result<Builder, (i32, String)> {
    Builder::new(
        BundleType::DEFAULT,
        NITO_ORCHARD_BUNDLE_VERSION,
        // Nito v4 consensus permits real spends and outputs in the same
        // Orchard bundle. Keep this explicit instead of inheriting a future
        // dependency default.
        Flags::ENABLED,
        anchor,
    )
    .map_err(|e| {
        (
            NITO_PRIVATE_ERR_BUILD,
            format!("orchard builder initialization failed: {e:?}"),
        )
    })
}

#[repr(C)]
pub struct NitoOrchardAction {
    pub cv_net: *const u8,
    pub nullifier: *const u8,
    pub rk: *const u8,
    pub cmx: *const u8,
    pub ephemeral_key: *const u8,
    pub enc_ciphertext: *const u8,
    pub out_ciphertext: *const u8,
    pub spend_auth_sig: *const u8,
}

#[repr(C)]
pub struct NitoOrchardBundle {
    pub flags: u8,
    pub value_balance: i64,
    pub anchor: *const u8,
    pub actions: *const NitoOrchardAction,
    pub actions_len: usize,
    pub proof: *const u8,
    pub proof_len: usize,
    pub binding_sig: *const u8,
    pub sighash: *const u8,
}

#[repr(C)]
pub struct NitoOrchardBuildOutput {
    pub flags_out: *mut u8,
    pub value_balance_out: *mut i64,
    pub actions_len_out: *mut usize,
    pub actions_cap: usize,
    pub cv_net_out: *mut u8,
    pub nullifier_out: *mut u8,
    pub rk_out: *mut u8,
    pub cmx_out: *mut u8,
    pub ephemeral_key_out: *mut u8,
    pub enc_ciphertext_out: *mut u8,
    pub out_ciphertext_out: *mut u8,
    pub spend_auth_sig_out: *mut u8,
    pub proof_out: *mut u8,
    pub proof_cap: usize,
    pub proof_len_out: *mut usize,
    pub binding_sig_out: *mut u8,
}

#[repr(C)]
pub struct NitoOrchardEffectsView {
    pub flags: u8,
    pub value_balance: i64,
    pub anchor: *const u8,
    pub actions_len: usize,
    pub cv_net: *const u8,
    pub nullifier: *const u8,
    pub rk: *const u8,
    pub cmx: *const u8,
    pub ephemeral_key: *const u8,
    pub enc_ciphertext: *const u8,
    pub out_ciphertext: *const u8,
}

#[repr(C)]
pub struct NitoOrchardCompactEffectsView {
    pub actions_len: usize,
    pub nullifier: *const u8,
    pub cmx: *const u8,
    pub ephemeral_key: *const u8,
    pub enc_ciphertext: *const u8,
    pub view_tag: *const u8,
}

#[repr(C)]
pub struct NitoOrchardSpendRequest {
    pub spending_key: *const u8,
    pub note_recipient_raw: *const u8,
    pub note_value: u64,
    pub note_rho: *const u8,
    pub note_rseed: *const u8,
    pub note_position: u32,
    pub merkle_path: *const u8,
    pub output_recipient_raw: *const u8,
    pub output_value: u64,
    pub output_ovk_internal: bool,
}

#[repr(C)]
pub struct NitoOrchardSpendInput {
    pub spending_key: *const u8,
    pub note_recipient_raw: *const u8,
    pub note_value: u64,
    pub note_rho: *const u8,
    pub note_rseed: *const u8,
    pub note_position: u32,
    pub merkle_path: *const u8,
}

#[repr(C)]
pub struct NitoOrchardOutputRequest {
    pub recipient_raw: *const u8,
    pub value: u64,
    pub ovk_internal: bool,
}

pub type NitoOrchardSighashCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        effects: *const NitoOrchardEffectsView,
        sighash_out: *mut u8,
        err_out: *mut c_char,
        err_out_len: usize,
    ) -> i32,
>;

fn set_error(dst: *mut c_char, dst_len: usize, msg: &str) {
    if dst.is_null() || dst_len == 0 {
        return;
    }

    let bytes = msg.as_bytes();
    let copy_len = bytes.len().min(dst_len.saturating_sub(1));
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), dst.cast::<u8>(), copy_len);
        *dst.cast::<u8>().add(copy_len) = 0;
    }
}

fn c_error_message(buf: &[c_char]) -> String {
    let len = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    let bytes = buf[..len].iter().map(|c| *c as u8).collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}

unsafe fn read_array<const N: usize>(ptr: *const u8, label: &str) -> Result<[u8; N], String> {
    if ptr.is_null() {
        return Err(format!("{label}: null pointer"));
    }
    let mut out = [0u8; N];
    ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), N);
    Ok(out)
}

unsafe fn read_slice(ptr: *const u8, len: usize, label: &str) -> Result<Vec<u8>, String> {
    if ptr.is_null() {
        return Err(format!("{label}: null pointer"));
    }
    if len == 0 {
        return Err(format!("{label}: empty"));
    }
    Ok(slice::from_raw_parts(ptr, len).to_vec())
}

unsafe fn write_bytes(dst: *mut u8, src: &[u8], label: &str) -> Result<(), (i32, String)> {
    if dst.is_null() {
        return Err((NITO_PRIVATE_ERR_NULL_PTR, format!("{label}: null pointer")));
    }
    ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    Ok(())
}

fn checked_ffi_buffer_len(
    count: usize,
    item_size: usize,
    label: &str,
) -> Result<usize, (i32, String)> {
    let len = count.checked_mul(item_size).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            format!("{label}: buffer length overflow"),
        )
    })?;
    if len > isize::MAX as usize {
        return Err((
            NITO_PRIVATE_ERR_BAD_ENCODING,
            format!("{label}: buffer length exceeds the Rust pointer range"),
        ));
    }
    Ok(len)
}

fn require_mut_ffi_buffer(
    ptr: *mut u8,
    count: usize,
    item_size: usize,
    label: &str,
) -> Result<(), (i32, String)> {
    let len = checked_ffi_buffer_len(count, item_size, label)?;
    if len != 0 && ptr.is_null() {
        return Err((NITO_PRIVATE_ERR_NULL_PTR, format!("{label}: null pointer")));
    }
    Ok(())
}

fn validate_effect_output_buffers(
    raw_out: &NitoOrchardBuildOutput,
    actions_len: usize,
) -> Result<(), (i32, String)> {
    require_mut_ffi_buffer(raw_out.cv_net_out, actions_len, 32, "cv_net_out")?;
    require_mut_ffi_buffer(raw_out.nullifier_out, actions_len, 32, "nullifier_out")?;
    require_mut_ffi_buffer(raw_out.rk_out, actions_len, 32, "rk_out")?;
    require_mut_ffi_buffer(raw_out.cmx_out, actions_len, 32, "cmx_out")?;
    require_mut_ffi_buffer(
        raw_out.ephemeral_key_out,
        actions_len,
        ORCHARD_EPK_SIZE,
        "ephemeral_key_out",
    )?;
    require_mut_ffi_buffer(
        raw_out.enc_ciphertext_out,
        actions_len,
        ORCHARD_ENC_CIPHERTEXT_SIZE,
        "enc_ciphertext_out",
    )?;
    require_mut_ffi_buffer(
        raw_out.out_ciphertext_out,
        actions_len,
        ORCHARD_OUT_CIPHERTEXT_SIZE,
        "out_ciphertext_out",
    )?;
    Ok(())
}

fn validate_authorization_output_buffers(
    raw_out: &NitoOrchardBuildOutput,
    actions_len: usize,
    proof_len: usize,
) -> Result<(), (i32, String)> {
    require_mut_ffi_buffer(
        raw_out.spend_auth_sig_out,
        actions_len,
        REDPALLAS_SIG_SIZE,
        "spend_auth_sig_out",
    )?;
    require_mut_ffi_buffer(raw_out.proof_out, proof_len, 1, "proof_out")?;
    require_mut_ffi_buffer(
        raw_out.binding_sig_out,
        1,
        REDPALLAS_SIG_SIZE,
        "binding_sig_out",
    )?;
    Ok(())
}

unsafe fn write_value<T: Copy>(dst: *mut T, value: T, label: &str) -> Result<(), (i32, String)> {
    if dst.is_null() {
        return Err((NITO_PRIVATE_ERR_NULL_PTR, format!("{label}: null pointer")));
    }
    ptr::write(dst, value);
    Ok(())
}

fn parse_anchor(bytes: [u8; 32]) -> Result<Anchor, String> {
    Option::<Anchor>::from(Anchor::from_bytes(bytes))
        .ok_or_else(|| "anchor: non-canonical".to_string())
}

fn parse_cv(bytes: [u8; 32]) -> Result<ValueCommitment, String> {
    Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&bytes))
        .ok_or_else(|| "cv_net: non-canonical".to_string())
}

fn parse_nullifier(bytes: [u8; 32]) -> Result<Nullifier, String> {
    Option::<Nullifier>::from(Nullifier::from_bytes(&bytes))
        .ok_or_else(|| "nullifier: non-canonical".to_string())
}

fn parse_cmx(bytes: [u8; 32]) -> Result<ExtractedNoteCommitment, String> {
    Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&bytes))
        .ok_or_else(|| "cmx: non-canonical".to_string())
}

fn parse_merkle_hash(bytes: [u8; 32]) -> Result<MerkleHashOrchard, String> {
    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes))
        .ok_or_else(|| "cmx: non-canonical".to_string())
}

fn parse_merkle_hash_slice(raw: &[u8], label: &str) -> Result<MerkleHashOrchard, String> {
    if raw.len() != 32 {
        return Err(format!("{label}: invalid length"));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(raw);
    parse_merkle_hash(bytes).map_err(|e| format!("{label}: {e}"))
}

fn decode_frontier(
    raw: &[u8],
) -> Result<Frontier<MerkleHashOrchard, ORCHARD_MERKLE_DEPTH>, String> {
    if raw.is_empty() {
        return Ok(Frontier::empty());
    }
    if raw.len() < 9 {
        return Err("frontier: truncated header".to_string());
    }
    if raw[0] != ORCHARD_FRONTIER_VERSION {
        return Err(format!("frontier: unsupported version {}", raw[0]));
    }
    let mut count_bytes = [0u8; 8];
    count_bytes.copy_from_slice(&raw[1..9]);
    let tree_size = u64::from_le_bytes(count_bytes);
    if tree_size == 0 {
        if raw.len() == 9 {
            return Ok(Frontier::empty());
        }
        return Err("frontier: trailing bytes after empty tree".to_string());
    }
    if raw.len() < 42 {
        return Err("frontier: truncated leaf".to_string());
    }
    let leaf = parse_merkle_hash_slice(&raw[9..41], "frontier leaf")?;
    let ommer_count = raw[41] as usize;
    let expected_len = 42usize
        .checked_add(
            ommer_count
                .checked_mul(32)
                .ok_or_else(|| "frontier: ommer length overflow".to_string())?,
        )
        .ok_or_else(|| "frontier: length overflow".to_string())?;
    if raw.len() != expected_len {
        return Err("frontier: invalid serialized length".to_string());
    }

    let mut ommers = Vec::with_capacity(ommer_count);
    let mut offset = 42;
    for i in 0..ommer_count {
        ommers.push(parse_merkle_hash_slice(
            &raw[offset..offset + 32],
            &format!("frontier ommer {i}"),
        )?);
        offset += 32;
    }
    Frontier::from_parts(Position::from(tree_size - 1), leaf, ommers)
        .map_err(|e| format!("frontier: invalid parts: {e:?}"))
}

fn encode_frontier(
    frontier: &Frontier<MerkleHashOrchard, ORCHARD_MERKLE_DEPTH>,
) -> Result<Vec<u8>, String> {
    let tree_size = frontier.tree_size();
    let mut out = Vec::with_capacity(ORCHARD_FRONTIER_MAX_SIZE);
    out.push(ORCHARD_FRONTIER_VERSION);
    out.extend_from_slice(&tree_size.to_le_bytes());
    if let Some(nonempty) = frontier.value() {
        let ommers = nonempty.ommers();
        if ommers.len() > ORCHARD_MERKLE_DEPTH_USIZE {
            return Err("frontier: too many ommers".to_string());
        }
        out.extend_from_slice(&nonempty.leaf().to_bytes());
        out.push(ommers.len() as u8);
        for ommer in ommers {
            out.extend_from_slice(&ommer.to_bytes());
        }
    }
    if out.len() > ORCHARD_FRONTIER_MAX_SIZE {
        return Err("frontier: encoded size overflow".to_string());
    }
    Ok(out)
}

fn parse_commitment_slice(
    raw: &[u8],
    cmx_count: usize,
) -> Result<Vec<MerkleHashOrchard>, (i32, String)> {
    let raw_len = cmx_count.checked_mul(32).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "cmx_count overflow".to_string(),
        )
    })?;
    if raw.len() != raw_len {
        return Err((
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "cmx_list length mismatch".to_string(),
        ));
    }
    let mut commitments = Vec::with_capacity(cmx_count);
    for (idx, chunk) in raw.chunks_exact(32).enumerate() {
        commitments.push(
            parse_merkle_hash_slice(chunk, &format!("cmx {idx}"))
                .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?,
        );
    }
    Ok(commitments)
}

unsafe fn parse_action(
    raw: &NitoOrchardAction,
) -> Result<Action<redpallas::Signature<SpendAuth>>, String> {
    let cv_net = parse_cv(read_array::<32>(raw.cv_net, "cv_net")?)?;
    let nf = parse_nullifier(read_array::<32>(raw.nullifier, "nullifier")?)?;
    let rk_bytes = read_array::<32>(raw.rk, "rk")?;
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(rk_bytes)
        .map_err(|_| "rk: invalid RedPallas key".to_string())?;
    let cmx = parse_cmx(read_array::<32>(raw.cmx, "cmx")?)?;
    let encrypted_note = TransmittedNoteCiphertext {
        epk_bytes: read_array::<ORCHARD_EPK_SIZE>(raw.ephemeral_key, "ephemeral_key")?,
        enc_ciphertext: read_array::<ORCHARD_ENC_CIPHERTEXT_SIZE>(
            raw.enc_ciphertext,
            "enc_ciphertext",
        )?,
        out_ciphertext: read_array::<ORCHARD_OUT_CIPHERTEXT_SIZE>(
            raw.out_ciphertext,
            "out_ciphertext",
        )?,
    };
    let spend_sig = redpallas::Signature::<SpendAuth>::from(read_array::<REDPALLAS_SIG_SIZE>(
        raw.spend_auth_sig,
        "spend_auth_sig",
    )?);

    Action::from_parts(nf, rk, cmx, encrypted_note, cv_net, spend_sig).map_err(|e| e.to_string())
}

unsafe fn parse_effect_action(
    raw: &NitoOrchardEffectsView,
    idx: usize,
) -> Result<Action<()>, String> {
    if idx >= raw.actions_len {
        return Err(format!("action index {idx} out of range"));
    }
    let off32 = idx
        .checked_mul(32)
        .ok_or_else(|| "action offset overflow".to_string())?;
    let off_enc = idx
        .checked_mul(ORCHARD_ENC_CIPHERTEXT_SIZE)
        .ok_or_else(|| "encrypted-note offset overflow".to_string())?;
    let off_out = idx
        .checked_mul(ORCHARD_OUT_CIPHERTEXT_SIZE)
        .ok_or_else(|| "out-note offset overflow".to_string())?;

    let cv_net = parse_cv(read_array::<32>(raw.cv_net.add(off32), "cv_net")?)?;
    let nf = parse_nullifier(read_array::<32>(raw.nullifier.add(off32), "nullifier")?)?;
    let rk_bytes = read_array::<32>(raw.rk.add(off32), "rk")?;
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(rk_bytes)
        .map_err(|_| "rk: invalid RedPallas key".to_string())?;
    let cmx = parse_cmx(read_array::<32>(raw.cmx.add(off32), "cmx")?)?;
    let encrypted_note = TransmittedNoteCiphertext {
        epk_bytes: read_array::<ORCHARD_EPK_SIZE>(raw.ephemeral_key.add(off32), "ephemeral_key")?,
        enc_ciphertext: read_array::<ORCHARD_ENC_CIPHERTEXT_SIZE>(
            raw.enc_ciphertext.add(off_enc),
            "enc_ciphertext",
        )?,
        out_ciphertext: read_array::<ORCHARD_OUT_CIPHERTEXT_SIZE>(
            raw.out_ciphertext.add(off_out),
            "out_ciphertext",
        )?,
    };

    Action::from_parts(nf, rk, cmx, encrypted_note, cv_net, ()).map_err(|e| e.to_string())
}

unsafe fn parse_compact_effect_action(
    raw: &NitoOrchardCompactEffectsView,
    idx: usize,
) -> Result<(OrchardDomain, CompactAction, u8), String> {
    if idx >= raw.actions_len {
        return Err(format!("compact action index {idx} out of range"));
    }
    let off32 = idx
        .checked_mul(32)
        .ok_or_else(|| "compact action offset overflow".to_string())?;
    let off_enc = idx
        .checked_mul(ORCHARD_COMPACT_NOTE_SIZE)
        .ok_or_else(|| "compact encrypted-note offset overflow".to_string())?;

    let nf = parse_nullifier(read_array::<32>(
        raw.nullifier.add(off32),
        "compact nullifier",
    )?)?;
    let cmx = parse_cmx(read_array::<32>(raw.cmx.add(off32), "compact cmx")?)?;
    let ephemeral_key = EphemeralKeyBytes(read_array::<ORCHARD_EPK_SIZE>(
        raw.ephemeral_key.add(off32),
        "compact ephemeral_key",
    )?);
    let enc_ciphertext = read_array::<ORCHARD_COMPACT_NOTE_SIZE>(
        raw.enc_ciphertext.add(off_enc),
        "compact enc_ciphertext",
    )?;
    let view_tag = *raw.view_tag.add(idx);
    let action = CompactAction::from_parts(nf, cmx, ephemeral_key, enc_ciphertext);
    let domain = OrchardDomain::for_compact_action(&action);
    Ok((domain, action, view_tag))
}

unsafe fn parse_effects_bundle(
    raw: &NitoOrchardEffectsView,
) -> Result<Bundle<EffectsOnly, i64>, (i32, String)> {
    if raw.actions_len == 0 {
        return Err((NITO_PRIVATE_ERR_BAD_ENCODING, "actions: empty".to_string()));
    }
    if raw.cv_net.is_null()
        || raw.nullifier.is_null()
        || raw.rk.is_null()
        || raw.cmx.is_null()
        || raw.ephemeral_key.is_null()
        || raw.enc_ciphertext.is_null()
        || raw.out_ciphertext.is_null()
    {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "effects: null action column".to_string(),
        ));
    }

    let flags = Flags::from_byte(raw.flags, NITO_ORCHARD_BUNDLE_VERSION).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "flags: reserved bits set".to_string(),
        )
    })?;
    let anchor = parse_anchor(
        read_array::<32>(raw.anchor, "anchor").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
    )
    .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?;

    let mut actions = Vec::with_capacity(raw.actions_len);
    for idx in 0..raw.actions_len {
        actions
            .push(parse_effect_action(raw, idx).map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?);
    }
    let nonempty_actions = NonEmpty::from_vec(actions)
        .ok_or_else(|| (NITO_PRIVATE_ERR_BAD_ENCODING, "actions: empty".to_string()))?;

    Bundle::from_parts(
        nonempty_actions,
        flags,
        raw.value_balance,
        anchor,
        EffectsOnly,
        NITO_ORCHARD_BUNDLE_VERSION,
    )
    .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e.to_string()))
}

unsafe fn verify_bundle(raw: &NitoOrchardBundle) -> Result<(), (i32, String)> {
    if raw.actions.is_null() || raw.actions_len == 0 {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "actions: empty or null".to_string(),
        ));
    }

    let flags = Flags::from_byte(raw.flags, NITO_ORCHARD_BUNDLE_VERSION).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "flags: reserved bits set".to_string(),
        )
    })?;
    let anchor = parse_anchor(
        read_array::<32>(raw.anchor, "anchor").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
    )
    .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?;
    let proof = Proof::new(
        read_slice(raw.proof, raw.proof_len, "proof")
            .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
    );
    let binding_sig = redpallas::Signature::<Binding>::from(
        read_array::<REDPALLAS_SIG_SIZE>(raw.binding_sig, "binding_sig")
            .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
    );
    let sighash = read_array::<NITO_SIGNATURE_HASH_SIZE>(raw.sighash, "sighash")
        .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;

    let actions_slice = slice::from_raw_parts(raw.actions, raw.actions_len);
    let mut actions = Vec::with_capacity(raw.actions_len);
    for action in actions_slice {
        actions.push(parse_action(action).map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?);
    }

    let nonempty_actions = NonEmpty::from_vec(actions)
        .ok_or_else(|| (NITO_PRIVATE_ERR_BAD_ENCODING, "actions: empty".to_string()))?;
    let authorization = Authorized::from_parts(proof, binding_sig);
    let bundle = Bundle::try_from_parts(
        nonempty_actions,
        flags,
        raw.value_balance,
        anchor,
        authorization,
        NITO_ORCHARD_BUNDLE_VERSION,
    )
    .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e.to_string()))?;

    // Reject forged authorization before the substantially more expensive
    // Halo2 proof verification. This does not change validity: all three
    // checks still have to succeed.
    for action in bundle.actions() {
        action
            .rk()
            .verify(&sighash, action.authorization())
            .map_err(|_| {
                (
                    NITO_PRIVATE_ERR_BAD_SPEND_SIG,
                    "spend authorization signature invalid".to_string(),
                )
            })?;
    }

    bundle
        .binding_validating_key()
        .verify(&sighash, bundle.authorization().binding_signature())
        .map_err(|_| {
            (
                NITO_PRIVATE_ERR_BAD_BINDING_SIG,
                "binding signature invalid".to_string(),
            )
        })?;

    let vk = VERIFYING_KEY.get_or_init(|| VerifyingKey::build(NITO_ORCHARD_CIRCUIT_VERSION));
    bundle.verify_proof(vk).map_err(|_| {
        (
            NITO_PRIVATE_ERR_BAD_PROOF,
            "orchard proof invalid".to_string(),
        )
    })?;

    Ok(())
}

unsafe fn build_output_bundle(
    raw_recipient: *const u8,
    value: u64,
    raw_anchor: *const u8,
    raw_sighash: *const u8,
    raw_out: &NitoOrchardBuildOutput,
) -> Result<(), (i32, String)> {
    let sighash = read_array::<NITO_SIGNATURE_HASH_SIZE>(raw_sighash, "sighash")
        .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;

    unsafe extern "C" fn fixed_sighash_callback(
        ctx: *mut c_void,
        _effects: *const NitoOrchardEffectsView,
        sighash_out: *mut u8,
        err_out: *mut c_char,
        err_out_len: usize,
    ) -> i32 {
        if ctx.is_null() {
            set_error(err_out, err_out_len, "sighash: null pointer");
            return NITO_PRIVATE_ERR_NULL_PTR;
        }
        if sighash_out.is_null() {
            set_error(err_out, err_out_len, "sighash_out: null pointer");
            return NITO_PRIVATE_ERR_NULL_PTR;
        }
        ptr::copy_nonoverlapping(ctx.cast::<u8>(), sighash_out, NITO_SIGNATURE_HASH_SIZE);
        NITO_PRIVATE_OK
    }

    build_output_bundle_with_callback(
        raw_recipient,
        value,
        raw_anchor,
        raw_out,
        Some(fixed_sighash_callback),
        sighash.as_ptr().cast_mut().cast::<c_void>(),
    )
}

unsafe fn build_output_bundle_with_callback(
    raw_recipient: *const u8,
    value: u64,
    raw_anchor: *const u8,
    raw_out: &NitoOrchardBuildOutput,
    sighash_callback: NitoOrchardSighashCallback,
    sighash_ctx: *mut c_void,
) -> Result<(), (i32, String)> {
    let recipient_bytes = read_array::<ORCHARD_RAW_ADDRESS_SIZE>(raw_recipient, "recipient")
        .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;
    let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&recipient_bytes))
        .ok_or_else(|| {
            (
                NITO_PRIVATE_ERR_BAD_ENCODING,
                "recipient: invalid Orchard raw address".to_string(),
            )
        })?;
    let anchor = parse_anchor(
        read_array::<32>(raw_anchor, "anchor").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
    )
    .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?;

    let mut builder = nito_orchard_builder(anchor)?;
    builder
        .add_output(None, recipient, NoteValue::from_raw(value), [0u8; 512])
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard add_output failed: {e:?}"),
            )
        })?;

    let pk = PROVING_KEY.get_or_init(|| ProvingKey::build(NITO_ORCHARD_CIRCUIT_VERSION));
    let mut rng = OsRng;
    let (bundle, _metadata) = builder
        .build::<i64>(&mut rng)
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard build failed: {e:?}"),
            )
        })?
        .ok_or_else(|| {
            (
                NITO_PRIVATE_ERR_BUILD,
                "orchard build produced no bundle".to_string(),
            )
        })?;

    let actions_len = bundle.actions().len();
    write_value(raw_out.actions_len_out, actions_len, "actions_len_out")?;
    if actions_len > raw_out.actions_cap {
        return Err((
            NITO_PRIVATE_ERR_BUFFER_TOO_SMALL,
            format!(
                "actions buffers too small: need {actions_len}, have {}",
                raw_out.actions_cap
            ),
        ));
    }
    validate_effect_output_buffers(raw_out, actions_len)?;

    let flags = nito_orchard_flags_byte(*bundle.flags());
    let value_balance = *bundle.value_balance();
    write_value(raw_out.flags_out, flags, "flags_out")?;
    write_value(
        raw_out.value_balance_out,
        value_balance,
        "value_balance_out",
    )?;

    for (idx, action) in bundle.actions().iter().enumerate() {
        let off32 = idx * 32;
        let off_enc = idx * ORCHARD_ENC_CIPHERTEXT_SIZE;
        let off_out = idx * ORCHARD_OUT_CIPHERTEXT_SIZE;

        write_bytes(
            raw_out.cv_net_out.add(off32),
            &action.cv_net().to_bytes(),
            "cv_net_out",
        )?;
        write_bytes(
            raw_out.nullifier_out.add(off32),
            &action.nullifier().to_bytes(),
            "nullifier_out",
        )?;
        let rk_bytes: [u8; 32] = action.rk().into();
        write_bytes(raw_out.rk_out.add(off32), &rk_bytes, "rk_out")?;
        write_bytes(
            raw_out.cmx_out.add(off32),
            &action.cmx().to_bytes(),
            "cmx_out",
        )?;
        write_bytes(
            raw_out.ephemeral_key_out.add(off32),
            &action.encrypted_note().epk_bytes,
            "ephemeral_key_out",
        )?;
        write_bytes(
            raw_out.enc_ciphertext_out.add(off_enc),
            &action.encrypted_note().enc_ciphertext,
            "enc_ciphertext_out",
        )?;
        write_bytes(
            raw_out.out_ciphertext_out.add(off_out),
            &action.encrypted_note().out_ciphertext,
            "out_ciphertext_out",
        )?;
    }

    let callback = sighash_callback.ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_NULL_PTR,
            "sighash callback: null pointer".to_string(),
        )
    })?;
    let mut sighash = [0u8; NITO_SIGNATURE_HASH_SIZE];
    let effects = NitoOrchardEffectsView {
        flags,
        value_balance,
        anchor: raw_anchor,
        actions_len,
        cv_net: raw_out.cv_net_out,
        nullifier: raw_out.nullifier_out,
        rk: raw_out.rk_out,
        cmx: raw_out.cmx_out,
        ephemeral_key: raw_out.ephemeral_key_out,
        enc_ciphertext: raw_out.enc_ciphertext_out,
        out_ciphertext: raw_out.out_ciphertext_out,
    };
    let mut callback_error = [0 as c_char; 256];
    let callback_code = callback(
        sighash_ctx,
        &effects,
        sighash.as_mut_ptr(),
        callback_error.as_mut_ptr(),
        callback_error.len(),
    );
    if callback_code != NITO_PRIVATE_OK {
        let message = c_error_message(&callback_error);
        return Err((
            callback_code,
            if message.is_empty() {
                "sighash callback failed".to_string()
            } else {
                message
            },
        ));
    }

    let bundle: Bundle<Authorized, i64> = bundle
        .create_proof(pk, &mut rng)
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard proof creation failed: {e:?}"),
            )
        })?
        .apply_signatures(&mut rng, sighash, &[])
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard signing failed: {e:?}"),
            )
        })?;

    let proof = bundle.authorization().proof().as_ref();
    write_value(raw_out.proof_len_out, proof.len(), "proof_len_out")?;
    if proof.len() > raw_out.proof_cap {
        return Err((
            NITO_PRIVATE_ERR_BUFFER_TOO_SMALL,
            format!(
                "proof buffer too small: need {}, have {}",
                proof.len(),
                raw_out.proof_cap
            ),
        ));
    }
    validate_authorization_output_buffers(raw_out, actions_len, proof.len())?;

    for (idx, action) in bundle.actions().iter().enumerate() {
        let off_sig = idx * REDPALLAS_SIG_SIZE;
        let sig_bytes: [u8; REDPALLAS_SIG_SIZE] = action.authorization().into();
        write_bytes(
            raw_out.spend_auth_sig_out.add(off_sig),
            &sig_bytes,
            "spend_auth_sig_out",
        )?;
    }

    write_bytes(raw_out.proof_out, proof, "proof_out")?;
    let binding_sig: [u8; REDPALLAS_SIG_SIZE] = bundle.authorization().binding_signature().into();
    write_bytes(raw_out.binding_sig_out, &binding_sig, "binding_sig_out")?;

    Ok(())
}

unsafe fn raw_address_from_spending_key(
    raw_spending_key: *const u8,
    diversifier_index: u32,
    internal_scope: bool,
    raw_address_out: *mut u8,
) -> Result<(), (i32, String)> {
    let spending_key_bytes = read_array::<32>(raw_spending_key, "spending_key")
        .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;
    let spending_key = Option::<SpendingKey>::from(SpendingKey::from_bytes(spending_key_bytes))
        .ok_or_else(|| {
            (
                NITO_PRIVATE_ERR_BAD_ENCODING,
                "spending_key: invalid Orchard spending key".to_string(),
            )
        })?;
    let fvk = FullViewingKey::from(&spending_key);
    let scope = if internal_scope {
        Scope::Internal
    } else {
        Scope::External
    };
    let address = fvk.address_at(diversifier_index, scope);
    write_bytes(
        raw_address_out,
        &address.to_raw_address_bytes(),
        "raw_address_out",
    )?;
    Ok(())
}

unsafe fn raw_address_from_full_viewing_key(
    raw_full_viewing_key: *const u8,
    diversifier_index: u32,
    internal_scope: bool,
    raw_address_out: *mut u8,
) -> Result<(), (i32, String)> {
    let fvk = parse_full_viewing_key(raw_full_viewing_key)?;
    let scope = if internal_scope {
        Scope::Internal
    } else {
        Scope::External
    };
    let address = fvk.address_at(diversifier_index, scope);
    write_bytes(
        raw_address_out,
        &address.to_raw_address_bytes(),
        "raw_address_out",
    )?;
    Ok(())
}

unsafe fn parse_spending_key(raw_spending_key: *const u8) -> Result<SpendingKey, (i32, String)> {
    let spending_key_bytes = read_array::<32>(raw_spending_key, "spending_key")
        .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;
    Option::<SpendingKey>::from(SpendingKey::from_bytes(spending_key_bytes)).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "spending_key: invalid Orchard spending key".to_string(),
        )
    })
}

unsafe fn parse_full_viewing_key(
    raw_full_viewing_key: *const u8,
) -> Result<FullViewingKey, (i32, String)> {
    let full_viewing_key_bytes = read_array::<96>(raw_full_viewing_key, "full_viewing_key")
        .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;
    FullViewingKey::from_bytes(&full_viewing_key_bytes).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "full_viewing_key: invalid Orchard full viewing key".to_string(),
        )
    })
}

unsafe fn parse_raw_address(raw_address: *const u8, label: &str) -> Result<Address, (i32, String)> {
    let address_bytes = read_array::<ORCHARD_RAW_ADDRESS_SIZE>(raw_address, label)
        .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;
    Option::<Address>::from(Address::from_raw_address_bytes(&address_bytes)).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            format!("{label}: invalid Orchard raw address"),
        )
    })
}

unsafe fn parse_merkle_path(
    raw_path: *const u8,
    position: u32,
) -> Result<MerklePath, (i32, String)> {
    if raw_path.is_null() {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "merkle_path: null pointer".to_string(),
        ));
    }

    let mut auth_path = [MerkleHashOrchard::empty_leaf(); ORCHARD_MERKLE_DEPTH_USIZE];
    for idx in 0..ORCHARD_MERKLE_DEPTH_USIZE {
        let element = read_array::<32>(raw_path.add(idx * 32), "merkle_path")
            .map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;
        auth_path[idx] = parse_merkle_hash(element).map_err(|e| {
            (
                NITO_PRIVATE_ERR_BAD_ENCODING,
                format!("{e} at path index {idx}"),
            )
        })?;
    }
    Ok(MerklePath::from_parts(position, auth_path))
}

unsafe fn parse_spend_note_parts(
    note_recipient_raw: *const u8,
    note_value: u64,
    note_rho: *const u8,
    note_rseed: *const u8,
) -> Result<Note, (i32, String)> {
    let recipient = parse_raw_address(note_recipient_raw, "note_recipient")?;
    let rho = Rho::from_bytes(
        &read_array::<32>(note_rho, "note_rho").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
    );
    let rho = Option::<Rho>::from(rho).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "note_rho: non-canonical".to_string(),
        )
    })?;
    let rseed = RandomSeed::from_bytes(
        read_array::<32>(note_rseed, "note_rseed").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
        &rho,
    );
    let rseed = Option::<RandomSeed>::from(rseed).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "note_rseed: invalid for rho".to_string(),
        )
    })?;
    let note = Note::from_parts(
        recipient,
        NoteValue::from_raw(note_value),
        rho,
        rseed,
        NITO_ORCHARD_BUNDLE_VERSION.note_version(),
    );
    Option::<Note>::from(note).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "note: commitment could not be derived".to_string(),
        )
    })
}

unsafe fn parse_spend_note(request: &NitoOrchardSpendRequest) -> Result<Note, (i32, String)> {
    parse_spend_note_parts(
        request.note_recipient_raw,
        request.note_value,
        request.note_rho,
        request.note_rseed,
    )
}

unsafe fn parse_input_spend_note(request: &NitoOrchardSpendInput) -> Result<Note, (i32, String)> {
    parse_spend_note_parts(
        request.note_recipient_raw,
        request.note_value,
        request.note_rho,
        request.note_rseed,
    )
}

unsafe fn build_auth_path(
    cmx_list: *const u8,
    cmx_count: usize,
    position: u32,
) -> Result<([MerkleHashOrchard; ORCHARD_MERKLE_DEPTH_USIZE], [u8; 32]), (i32, String)> {
    if cmx_list.is_null() {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "cmx_list: null pointer".to_string(),
        ));
    }
    if position as usize >= cmx_count {
        return Err((
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "position outside commitment list".to_string(),
        ));
    }

    let raw_len = cmx_count.checked_mul(32).ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "cmx_count overflow".to_string(),
        )
    })?;
    let raw = slice::from_raw_parts(cmx_list, raw_len);
    let mut layer = Vec::with_capacity(cmx_count);
    for (idx, chunk) in raw.chunks_exact(32).enumerate() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(chunk);
        let cmx = parse_merkle_hash(bytes)
            .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, format!("{e} at index {idx}")))?;
        layer.push(cmx);
    }

    let mut auth_path = [MerkleHashOrchard::empty_leaf(); ORCHARD_MERKLE_DEPTH_USIZE];
    let mut pos = position as usize;
    for level in 0..ORCHARD_MERKLE_DEPTH_USIZE {
        let empty = MerkleHashOrchard::empty_root(Level::from(level as u8));
        let sibling_index = if pos % 2 == 0 {
            pos + 1
        } else {
            pos.saturating_sub(1)
        };
        auth_path[level] = layer.get(sibling_index).copied().unwrap_or(empty);

        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = if pair.len() > 1 { pair[1] } else { empty };
            next.push(MerkleHashOrchard::combine(
                Level::from(level as u8),
                &left,
                &right,
            ));
        }
        layer = next;
        pos /= 2;
    }

    let root = layer
        .first()
        .copied()
        .unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(ORCHARD_MERKLE_DEPTH)));
    Ok((auth_path, root.to_bytes()))
}

unsafe fn build_spend_bundle_with_callback(
    request: &NitoOrchardSpendRequest,
    raw_anchor: *const u8,
    raw_out: &NitoOrchardBuildOutput,
    sighash_callback: NitoOrchardSighashCallback,
    sighash_ctx: *mut c_void,
) -> Result<(), (i32, String)> {
    let spending_key = parse_spending_key(request.spending_key)?;
    let fvk = FullViewingKey::from(&spending_key);
    let note = parse_spend_note(request)?;
    let merkle_path = parse_merkle_path(request.merkle_path, request.note_position)?;
    let output_recipient = parse_raw_address(request.output_recipient_raw, "output_recipient")?;
    let anchor = parse_anchor(
        read_array::<32>(raw_anchor, "anchor").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
    )
    .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?;

    if merkle_path.root(ExtractedNoteCommitment::from(note.commitment())) != anchor {
        return Err((
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "merkle_path: root does not match anchor".to_string(),
        ));
    }

    let mut builder = nito_orchard_builder(anchor)?;
    builder
        .add_spend(fvk.clone(), note, merkle_path)
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard add_spend failed: {e:?}"),
            )
        })?;
    let output_scope = if request.output_ovk_internal {
        Scope::Internal
    } else {
        Scope::External
    };
    builder
        .add_output(
            Some(fvk.to_ovk(output_scope)),
            output_recipient,
            NoteValue::from_raw(request.output_value),
            [0u8; 512],
        )
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard add_output failed: {e:?}"),
            )
        })?;

    let pk = PROVING_KEY.get_or_init(|| ProvingKey::build(NITO_ORCHARD_CIRCUIT_VERSION));
    let mut rng = OsRng;
    let (bundle, _metadata) = builder
        .build::<i64>(&mut rng)
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard build failed: {e:?}"),
            )
        })?
        .ok_or_else(|| {
            (
                NITO_PRIVATE_ERR_BUILD,
                "orchard build produced no bundle".to_string(),
            )
        })?;

    let actions_len = bundle.actions().len();
    write_value(raw_out.actions_len_out, actions_len, "actions_len_out")?;
    if actions_len > raw_out.actions_cap {
        return Err((
            NITO_PRIVATE_ERR_BUFFER_TOO_SMALL,
            format!(
                "actions buffers too small: need {actions_len}, have {}",
                raw_out.actions_cap
            ),
        ));
    }
    validate_effect_output_buffers(raw_out, actions_len)?;

    let flags = nito_orchard_flags_byte(*bundle.flags());
    let value_balance = *bundle.value_balance();
    write_value(raw_out.flags_out, flags, "flags_out")?;
    write_value(
        raw_out.value_balance_out,
        value_balance,
        "value_balance_out",
    )?;

    for (idx, action) in bundle.actions().iter().enumerate() {
        let off32 = idx * 32;
        let off_enc = idx * ORCHARD_ENC_CIPHERTEXT_SIZE;
        let off_out = idx * ORCHARD_OUT_CIPHERTEXT_SIZE;

        write_bytes(
            raw_out.cv_net_out.add(off32),
            &action.cv_net().to_bytes(),
            "cv_net_out",
        )?;
        write_bytes(
            raw_out.nullifier_out.add(off32),
            &action.nullifier().to_bytes(),
            "nullifier_out",
        )?;
        let rk_bytes: [u8; 32] = action.rk().into();
        write_bytes(raw_out.rk_out.add(off32), &rk_bytes, "rk_out")?;
        write_bytes(
            raw_out.cmx_out.add(off32),
            &action.cmx().to_bytes(),
            "cmx_out",
        )?;
        write_bytes(
            raw_out.ephemeral_key_out.add(off32),
            &action.encrypted_note().epk_bytes,
            "ephemeral_key_out",
        )?;
        write_bytes(
            raw_out.enc_ciphertext_out.add(off_enc),
            &action.encrypted_note().enc_ciphertext,
            "enc_ciphertext_out",
        )?;
        write_bytes(
            raw_out.out_ciphertext_out.add(off_out),
            &action.encrypted_note().out_ciphertext,
            "out_ciphertext_out",
        )?;
    }

    let callback = sighash_callback.ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_NULL_PTR,
            "sighash callback: null pointer".to_string(),
        )
    })?;
    let mut sighash = [0u8; NITO_SIGNATURE_HASH_SIZE];
    let effects = NitoOrchardEffectsView {
        flags,
        value_balance,
        anchor: raw_anchor,
        actions_len,
        cv_net: raw_out.cv_net_out,
        nullifier: raw_out.nullifier_out,
        rk: raw_out.rk_out,
        cmx: raw_out.cmx_out,
        ephemeral_key: raw_out.ephemeral_key_out,
        enc_ciphertext: raw_out.enc_ciphertext_out,
        out_ciphertext: raw_out.out_ciphertext_out,
    };
    let mut callback_error = [0 as c_char; 256];
    let callback_code = callback(
        sighash_ctx,
        &effects,
        sighash.as_mut_ptr(),
        callback_error.as_mut_ptr(),
        callback_error.len(),
    );
    if callback_code != NITO_PRIVATE_OK {
        let message = c_error_message(&callback_error);
        return Err((
            callback_code,
            if message.is_empty() {
                "sighash callback failed".to_string()
            } else {
                message
            },
        ));
    }

    let spend_auth_key = SpendAuthorizingKey::from(&spending_key);
    let bundle: Bundle<Authorized, i64> = bundle
        .create_proof(pk, &mut rng)
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard proof creation failed: {e:?}"),
            )
        })?
        .apply_signatures(&mut rng, sighash, &[spend_auth_key])
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard signing failed: {e:?}"),
            )
        })?;

    let proof = bundle.authorization().proof().as_ref();
    write_value(raw_out.proof_len_out, proof.len(), "proof_len_out")?;
    if proof.len() > raw_out.proof_cap {
        return Err((
            NITO_PRIVATE_ERR_BUFFER_TOO_SMALL,
            format!(
                "proof buffer too small: need {}, have {}",
                proof.len(),
                raw_out.proof_cap
            ),
        ));
    }
    validate_authorization_output_buffers(raw_out, actions_len, proof.len())?;

    for (idx, action) in bundle.actions().iter().enumerate() {
        let off_sig = idx * REDPALLAS_SIG_SIZE;
        let sig_bytes: [u8; REDPALLAS_SIG_SIZE] = action.authorization().into();
        write_bytes(
            raw_out.spend_auth_sig_out.add(off_sig),
            &sig_bytes,
            "spend_auth_sig_out",
        )?;
    }

    write_bytes(raw_out.proof_out, proof, "proof_out")?;
    let binding_sig: [u8; REDPALLAS_SIG_SIZE] = bundle.authorization().binding_signature().into();
    write_bytes(raw_out.binding_sig_out, &binding_sig, "binding_sig_out")?;

    Ok(())
}

unsafe fn build_bundle_with_callback(
    spends: *const NitoOrchardSpendInput,
    spends_len: usize,
    outputs: *const NitoOrchardOutputRequest,
    outputs_len: usize,
    raw_anchor: *const u8,
    raw_out: &NitoOrchardBuildOutput,
    sighash_callback: NitoOrchardSighashCallback,
    sighash_ctx: *mut c_void,
) -> Result<(), (i32, String)> {
    if spends_len == 0 && outputs_len == 0 {
        return Err((
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "bundle: empty spends and outputs".to_string(),
        ));
    }
    if spends_len != 0 && spends.is_null() {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "spends: null pointer".to_string(),
        ));
    }
    if outputs_len != 0 && outputs.is_null() {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "outputs: null pointer".to_string(),
        ));
    }

    let anchor = parse_anchor(
        read_array::<32>(raw_anchor, "anchor").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
    )
    .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?;

    let spend_slice = if spends_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(spends, spends_len)
    };
    let output_slice = if outputs_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(outputs, outputs_len)
    };

    let mut builder = nito_orchard_builder(anchor)?;
    let mut spend_auth_keys = Vec::with_capacity(spends_len);
    let mut sender_fvk = None;

    for spend in spend_slice {
        let spending_key = parse_spending_key(spend.spending_key)?;
        let fvk = FullViewingKey::from(&spending_key);
        let note = parse_input_spend_note(spend)?;
        let merkle_path = parse_merkle_path(spend.merkle_path, spend.note_position)?;
        if merkle_path.root(ExtractedNoteCommitment::from(note.commitment())) != anchor {
            return Err((
                NITO_PRIVATE_ERR_BAD_ENCODING,
                "merkle_path: root does not match anchor".to_string(),
            ));
        }
        builder
            .add_spend(fvk.clone(), note, merkle_path)
            .map_err(|e| {
                (
                    NITO_PRIVATE_ERR_BUILD,
                    format!("orchard add_spend failed: {e:?}"),
                )
            })?;
        spend_auth_keys.push(SpendAuthorizingKey::from(&spending_key));
        if sender_fvk.is_none() {
            sender_fvk = Some(fvk);
        }
    }

    for output in output_slice {
        if output.value == 0 {
            return Err((
                NITO_PRIVATE_ERR_BAD_ENCODING,
                "output_value: zero output is not allowed".to_string(),
            ));
        }
        let recipient = parse_raw_address(output.recipient_raw, "output_recipient")?;
        let ovk = sender_fvk.as_ref().map(|fvk| {
            let scope = if output.ovk_internal {
                Scope::Internal
            } else {
                Scope::External
            };
            fvk.to_ovk(scope)
        });
        builder
            .add_output(
                ovk,
                recipient,
                NoteValue::from_raw(output.value),
                [0u8; 512],
            )
            .map_err(|e| {
                (
                    NITO_PRIVATE_ERR_BUILD,
                    format!("orchard add_output failed: {e:?}"),
                )
            })?;
    }

    let pk = PROVING_KEY.get_or_init(|| ProvingKey::build(NITO_ORCHARD_CIRCUIT_VERSION));
    let mut rng = OsRng;
    let (bundle, _metadata) = builder
        .build::<i64>(&mut rng)
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard build failed: {e:?}"),
            )
        })?
        .ok_or_else(|| {
            (
                NITO_PRIVATE_ERR_BUILD,
                "orchard build produced no bundle".to_string(),
            )
        })?;

    let actions_len = bundle.actions().len();
    write_value(raw_out.actions_len_out, actions_len, "actions_len_out")?;
    if actions_len > raw_out.actions_cap {
        return Err((
            NITO_PRIVATE_ERR_BUFFER_TOO_SMALL,
            format!(
                "actions buffers too small: need {actions_len}, have {}",
                raw_out.actions_cap
            ),
        ));
    }
    validate_effect_output_buffers(raw_out, actions_len)?;

    let flags = nito_orchard_flags_byte(*bundle.flags());
    let value_balance = *bundle.value_balance();
    write_value(raw_out.flags_out, flags, "flags_out")?;
    write_value(
        raw_out.value_balance_out,
        value_balance,
        "value_balance_out",
    )?;

    for (idx, action) in bundle.actions().iter().enumerate() {
        let off32 = idx * 32;
        let off_enc = idx * ORCHARD_ENC_CIPHERTEXT_SIZE;
        let off_out = idx * ORCHARD_OUT_CIPHERTEXT_SIZE;

        write_bytes(
            raw_out.cv_net_out.add(off32),
            &action.cv_net().to_bytes(),
            "cv_net_out",
        )?;
        write_bytes(
            raw_out.nullifier_out.add(off32),
            &action.nullifier().to_bytes(),
            "nullifier_out",
        )?;
        let rk_bytes: [u8; 32] = action.rk().into();
        write_bytes(raw_out.rk_out.add(off32), &rk_bytes, "rk_out")?;
        write_bytes(
            raw_out.cmx_out.add(off32),
            &action.cmx().to_bytes(),
            "cmx_out",
        )?;
        write_bytes(
            raw_out.ephemeral_key_out.add(off32),
            &action.encrypted_note().epk_bytes,
            "ephemeral_key_out",
        )?;
        write_bytes(
            raw_out.enc_ciphertext_out.add(off_enc),
            &action.encrypted_note().enc_ciphertext,
            "enc_ciphertext_out",
        )?;
        write_bytes(
            raw_out.out_ciphertext_out.add(off_out),
            &action.encrypted_note().out_ciphertext,
            "out_ciphertext_out",
        )?;
    }

    let callback = sighash_callback.ok_or_else(|| {
        (
            NITO_PRIVATE_ERR_NULL_PTR,
            "sighash callback: null pointer".to_string(),
        )
    })?;
    let mut sighash = [0u8; NITO_SIGNATURE_HASH_SIZE];
    let effects = NitoOrchardEffectsView {
        flags,
        value_balance,
        anchor: raw_anchor,
        actions_len,
        cv_net: raw_out.cv_net_out,
        nullifier: raw_out.nullifier_out,
        rk: raw_out.rk_out,
        cmx: raw_out.cmx_out,
        ephemeral_key: raw_out.ephemeral_key_out,
        enc_ciphertext: raw_out.enc_ciphertext_out,
        out_ciphertext: raw_out.out_ciphertext_out,
    };
    let mut callback_error = [0 as c_char; 256];
    let callback_code = callback(
        sighash_ctx,
        &effects,
        sighash.as_mut_ptr(),
        callback_error.as_mut_ptr(),
        callback_error.len(),
    );
    if callback_code != NITO_PRIVATE_OK {
        let message = c_error_message(&callback_error);
        return Err((
            callback_code,
            if message.is_empty() {
                "sighash callback failed".to_string()
            } else {
                message
            },
        ));
    }

    let bundle: Bundle<Authorized, i64> = bundle
        .create_proof(pk, &mut rng)
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard proof creation failed: {e:?}"),
            )
        })?
        .apply_signatures(&mut rng, sighash, &spend_auth_keys)
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard signing failed: {e:?}"),
            )
        })?;

    let proof = bundle.authorization().proof().as_ref();
    write_value(raw_out.proof_len_out, proof.len(), "proof_len_out")?;
    if proof.len() > raw_out.proof_cap {
        return Err((
            NITO_PRIVATE_ERR_BUFFER_TOO_SMALL,
            format!(
                "proof buffer too small: need {}, have {}",
                proof.len(),
                raw_out.proof_cap
            ),
        ));
    }
    validate_authorization_output_buffers(raw_out, actions_len, proof.len())?;

    for (idx, action) in bundle.actions().iter().enumerate() {
        let off_sig = idx * REDPALLAS_SIG_SIZE;
        let sig_bytes: [u8; REDPALLAS_SIG_SIZE] = action.authorization().into();
        write_bytes(
            raw_out.spend_auth_sig_out.add(off_sig),
            &sig_bytes,
            "spend_auth_sig_out",
        )?;
    }

    write_bytes(raw_out.proof_out, proof, "proof_out")?;
    let binding_sig: [u8; REDPALLAS_SIG_SIZE] = bundle.authorization().binding_signature().into();
    write_bytes(raw_out.binding_sig_out, &binding_sig, "binding_sig_out")?;

    Ok(())
}

unsafe fn build_bundle_effects_only_inner(
    spends: *const NitoOrchardSpendInput,
    spends_len: usize,
    outputs: *const NitoOrchardOutputRequest,
    outputs_len: usize,
    raw_anchor: *const u8,
    raw_out: &NitoOrchardBuildOutput,
) -> Result<(), (i32, String)> {
    if spends_len == 0 && outputs_len == 0 {
        return Err((
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "bundle: empty spends and outputs".to_string(),
        ));
    }
    if spends_len != 0 && spends.is_null() {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "spends: null pointer".to_string(),
        ));
    }
    if outputs_len != 0 && outputs.is_null() {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "outputs: null pointer".to_string(),
        ));
    }

    let anchor = parse_anchor(
        read_array::<32>(raw_anchor, "anchor").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?,
    )
    .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?;

    let spend_slice = if spends_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(spends, spends_len)
    };
    let output_slice = if outputs_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(outputs, outputs_len)
    };

    let mut builder = nito_orchard_builder(anchor)?;
    let mut sender_fvk = None;

    for spend in spend_slice {
        let spending_key = parse_spending_key(spend.spending_key)?;
        let fvk = FullViewingKey::from(&spending_key);
        let note = parse_input_spend_note(spend)?;
        let merkle_path = parse_merkle_path(spend.merkle_path, spend.note_position)?;
        if merkle_path.root(ExtractedNoteCommitment::from(note.commitment())) != anchor {
            return Err((
                NITO_PRIVATE_ERR_BAD_ENCODING,
                "merkle_path: root does not match anchor".to_string(),
            ));
        }
        builder
            .add_spend(fvk.clone(), note, merkle_path)
            .map_err(|e| {
                (
                    NITO_PRIVATE_ERR_BUILD,
                    format!("orchard add_spend failed: {e:?}"),
                )
            })?;
        if sender_fvk.is_none() {
            sender_fvk = Some(fvk);
        }
    }

    for output in output_slice {
        if output.value == 0 {
            return Err((
                NITO_PRIVATE_ERR_BAD_ENCODING,
                "output_value: zero output is not allowed".to_string(),
            ));
        }
        let recipient = parse_raw_address(output.recipient_raw, "output_recipient")?;
        let ovk = sender_fvk.as_ref().map(|fvk| {
            let scope = if output.ovk_internal {
                Scope::Internal
            } else {
                Scope::External
            };
            fvk.to_ovk(scope)
        });
        builder
            .add_output(
                ovk,
                recipient,
                NoteValue::from_raw(output.value),
                [0u8; 512],
            )
            .map_err(|e| {
                (
                    NITO_PRIVATE_ERR_BUILD,
                    format!("orchard add_output failed: {e:?}"),
                )
            })?;
    }

    let mut rng = OsRng;
    let (bundle, _metadata) = builder
        .build::<i64>(&mut rng)
        .map_err(|e| {
            (
                NITO_PRIVATE_ERR_BUILD,
                format!("orchard build failed: {e:?}"),
            )
        })?
        .ok_or_else(|| {
            (
                NITO_PRIVATE_ERR_BUILD,
                "orchard build produced no bundle".to_string(),
            )
        })?;

    let actions_len = bundle.actions().len();
    write_value(raw_out.actions_len_out, actions_len, "actions_len_out")?;
    if actions_len > raw_out.actions_cap {
        return Err((
            NITO_PRIVATE_ERR_BUFFER_TOO_SMALL,
            format!(
                "actions buffers too small: need {actions_len}, have {}",
                raw_out.actions_cap
            ),
        ));
    }
    validate_effect_output_buffers(raw_out, actions_len)?;

    let flags = nito_orchard_flags_byte(*bundle.flags());
    let value_balance = *bundle.value_balance();
    write_value(raw_out.flags_out, flags, "flags_out")?;
    write_value(
        raw_out.value_balance_out,
        value_balance,
        "value_balance_out",
    )?;
    write_value(raw_out.proof_len_out, 0usize, "proof_len_out")?;

    for (idx, action) in bundle.actions().iter().enumerate() {
        let off32 = idx * 32;
        let off_enc = idx * ORCHARD_ENC_CIPHERTEXT_SIZE;
        let off_out = idx * ORCHARD_OUT_CIPHERTEXT_SIZE;

        write_bytes(
            raw_out.cv_net_out.add(off32),
            &action.cv_net().to_bytes(),
            "cv_net_out",
        )?;
        write_bytes(
            raw_out.nullifier_out.add(off32),
            &action.nullifier().to_bytes(),
            "nullifier_out",
        )?;
        let rk_bytes: [u8; 32] = action.rk().into();
        write_bytes(raw_out.rk_out.add(off32), &rk_bytes, "rk_out")?;
        write_bytes(
            raw_out.cmx_out.add(off32),
            &action.cmx().to_bytes(),
            "cmx_out",
        )?;
        write_bytes(
            raw_out.ephemeral_key_out.add(off32),
            &action.encrypted_note().epk_bytes,
            "ephemeral_key_out",
        )?;
        write_bytes(
            raw_out.enc_ciphertext_out.add(off_enc),
            &action.encrypted_note().enc_ciphertext,
            "enc_ciphertext_out",
        )?;
        write_bytes(
            raw_out.out_ciphertext_out.add(off_out),
            &action.encrypted_note().out_ciphertext,
            "out_ciphertext_out",
        )?;
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn nito_orchard_build_output_bundle(
    recipient_raw: *const u8,
    value: u64,
    anchor: *const u8,
    sighash: *const u8,
    out: *mut NitoOrchardBuildOutput,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if out.is_null() {
            return Err((NITO_PRIVATE_ERR_NULL_PTR, "out: null pointer".to_string()));
        }
        build_output_bundle(recipient_raw, value, anchor, sighash, &*out)
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_build_output_bundle",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_build_output_bundle_with_sighash_callback(
    recipient_raw: *const u8,
    value: u64,
    anchor: *const u8,
    out: *mut NitoOrchardBuildOutput,
    sighash_callback: NitoOrchardSighashCallback,
    sighash_ctx: *mut c_void,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if out.is_null() {
            return Err((NITO_PRIVATE_ERR_NULL_PTR, "out: null pointer".to_string()));
        }
        build_output_bundle_with_callback(
            recipient_raw,
            value,
            anchor,
            &*out,
            sighash_callback,
            sighash_ctx,
        )
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_build_output_bundle_with_sighash_callback",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_build_spend_bundle_with_sighash_callback(
    request: *const NitoOrchardSpendRequest,
    anchor: *const u8,
    out: *mut NitoOrchardBuildOutput,
    sighash_callback: NitoOrchardSighashCallback,
    sighash_ctx: *mut c_void,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if request.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "request: null pointer".to_string(),
            ));
        }
        if out.is_null() {
            return Err((NITO_PRIVATE_ERR_NULL_PTR, "out: null pointer".to_string()));
        }
        build_spend_bundle_with_callback(&*request, anchor, &*out, sighash_callback, sighash_ctx)
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_build_spend_bundle_with_sighash_callback",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_build_bundle_with_sighash_callback(
    spends: *const NitoOrchardSpendInput,
    spends_len: usize,
    outputs: *const NitoOrchardOutputRequest,
    outputs_len: usize,
    anchor: *const u8,
    out: *mut NitoOrchardBuildOutput,
    sighash_callback: NitoOrchardSighashCallback,
    sighash_ctx: *mut c_void,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if out.is_null() {
            return Err((NITO_PRIVATE_ERR_NULL_PTR, "out: null pointer".to_string()));
        }
        build_bundle_with_callback(
            spends,
            spends_len,
            outputs,
            outputs_len,
            anchor,
            &*out,
            sighash_callback,
            sighash_ctx,
        )
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_build_bundle_with_sighash_callback",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_build_bundle_effects_only(
    spends: *const NitoOrchardSpendInput,
    spends_len: usize,
    outputs: *const NitoOrchardOutputRequest,
    outputs_len: usize,
    anchor: *const u8,
    out: *mut NitoOrchardBuildOutput,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if out.is_null() {
            return Err((NITO_PRIVATE_ERR_NULL_PTR, "out: null pointer".to_string()));
        }
        build_bundle_effects_only_inner(spends, spends_len, outputs, outputs_len, anchor, &*out)
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_build_bundle_effects_only",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_raw_address_from_spending_key(
    spending_key: *const u8,
    diversifier_index: u32,
    raw_address_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        raw_address_from_spending_key(spending_key, diversifier_index, false, raw_address_out)
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_raw_address_from_spending_key",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_raw_address_from_spending_key_scoped(
    spending_key: *const u8,
    diversifier_index: u32,
    internal_scope: bool,
    raw_address_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        raw_address_from_spending_key(
            spending_key,
            diversifier_index,
            internal_scope,
            raw_address_out,
        )
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_raw_address_from_spending_key_scoped",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_full_viewing_key_from_spending_key(
    spending_key: *const u8,
    full_viewing_key_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if full_viewing_key_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "full_viewing_key_out: null pointer".to_string(),
            ));
        }
        let spending_key = parse_spending_key(spending_key)?;
        let fvk = FullViewingKey::from(&spending_key).to_bytes();
        write_bytes(full_viewing_key_out, &fvk, "full_viewing_key_out")?;
        Ok(())
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_full_viewing_key_from_spending_key",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_raw_address_from_full_viewing_key_scoped(
    full_viewing_key: *const u8,
    diversifier_index: u32,
    internal_scope: bool,
    raw_address_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if raw_address_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "raw_address_out: null pointer".to_string(),
            ));
        }
        raw_address_from_full_viewing_key(
            full_viewing_key,
            diversifier_index,
            internal_scope,
            raw_address_out,
        )
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_raw_address_from_full_viewing_key_scoped",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_fvk_diversifier_index(
    full_viewing_key: *const u8,
    internal_scope: bool,
    raw_address: *const u8,
    matched_out: *mut u8,
    diversifier_index_out: *mut u32,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if matched_out.is_null() || diversifier_index_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "diversifier index output: null pointer".to_string(),
            ));
        }
        ptr::write(matched_out, 0u8);
        ptr::write(diversifier_index_out, u32::MAX);

        let fvk = parse_full_viewing_key(full_viewing_key)?;
        let address = parse_raw_address(raw_address, "raw_address")?;
        let scope = if internal_scope {
            Scope::Internal
        } else {
            Scope::External
        };
        let ivk = fvk.to_ivk(scope);
        if let Some(index) = ivk.diversifier_index(&address) {
            if let Ok(index) = u32::try_from(index) {
                ptr::write(matched_out, 1u8);
                ptr::write(diversifier_index_out, index);
            }
        }
        Ok(())
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_fvk_diversifier_index",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_verify_bundle(
    bundle: *const NitoOrchardBundle,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if bundle.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "bundle: null pointer".to_string(),
            ));
        }
        verify_bundle(&*bundle)
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_verify_bundle",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn decrypt_output_with_full_viewing_key_impl(
    fvk: FullViewingKey,
    internal_scope: bool,
    effects: *const NitoOrchardEffectsView,
    action_idx: usize,
    matched_out: *mut u8,
    value_out: *mut u64,
    recipient_raw_out: *mut u8,
    cmx_out: *mut u8,
    nullifier_out: *mut u8,
    rho_out: *mut u8,
    rseed_out: *mut u8,
    memo_out: *mut u8,
) -> Result<(), (i32, String)> {
    if effects.is_null() {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "effects: null pointer".to_string(),
        ));
    }
    write_value(matched_out, 0u8, "matched_out")?;
    let scope = if internal_scope {
        Scope::Internal
    } else {
        Scope::External
    };
    let bundle = parse_effects_bundle(&*effects)?;

    match bundle.decrypt_output_with_key(action_idx, &fvk.to_ivk(scope)) {
        Some((note, address, memo)) => {
            write_value(matched_out, 1u8, "matched_out")?;
            write_value(value_out, note.value().inner(), "value_out")?;
            write_bytes(
                recipient_raw_out,
                &address.to_raw_address_bytes(),
                "recipient_raw_out",
            )?;
            write_bytes(
                cmx_out,
                &ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                "cmx_out",
            )?;
            write_bytes(
                nullifier_out,
                &note.nullifier(&fvk).to_bytes(),
                "nullifier_out",
            )?;
            write_bytes(rho_out, &note.rho().to_bytes(), "rho_out")?;
            write_bytes(rseed_out, note.rseed().as_bytes(), "rseed_out")?;
            write_bytes(memo_out, &memo, "memo_out")?;
            Ok(())
        }
        None => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "C" fn nito_orchard_decrypt_output(
    spending_key: *const u8,
    internal_scope: bool,
    effects: *const NitoOrchardEffectsView,
    action_idx: usize,
    matched_out: *mut u8,
    value_out: *mut u64,
    recipient_raw_out: *mut u8,
    cmx_out: *mut u8,
    nullifier_out: *mut u8,
    rho_out: *mut u8,
    rseed_out: *mut u8,
    memo_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        let spending_key = parse_spending_key(spending_key)?;
        let fvk = FullViewingKey::from(&spending_key);
        decrypt_output_with_full_viewing_key_impl(
            fvk,
            internal_scope,
            effects,
            action_idx,
            matched_out,
            value_out,
            recipient_raw_out,
            cmx_out,
            nullifier_out,
            rho_out,
            rseed_out,
            memo_out,
        )
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_decrypt_output",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "C" fn nito_orchard_decrypt_output_with_fvk(
    full_viewing_key: *const u8,
    internal_scope: bool,
    effects: *const NitoOrchardEffectsView,
    action_idx: usize,
    matched_out: *mut u8,
    value_out: *mut u64,
    recipient_raw_out: *mut u8,
    cmx_out: *mut u8,
    nullifier_out: *mut u8,
    rho_out: *mut u8,
    rseed_out: *mut u8,
    memo_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        let fvk = parse_full_viewing_key(full_viewing_key)?;
        decrypt_output_with_full_viewing_key_impl(
            fvk,
            internal_scope,
            effects,
            action_idx,
            matched_out,
            value_out,
            recipient_raw_out,
            cmx_out,
            nullifier_out,
            rho_out,
            rseed_out,
            memo_out,
        )
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_decrypt_output_with_fvk",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_classify_change_outputs(
    external_full_viewing_key: *const u8,
    internal_full_viewing_key: *const u8,
    effects: *const NitoOrchardEffectsView,
    change_out: *mut u8,
    change_out_len: usize,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if effects.is_null() || change_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "change output: null pointer".to_string(),
            ));
        }
        if change_out_len < (*effects).actions_len {
            return Err((
                NITO_PRIVATE_ERR_BUFFER_TOO_SMALL,
                "change output: buffer too small".to_string(),
            ));
        }
        // Spending keys for either receive branch can fund an output. Change uses
        // the internal OVK of the sender, independently of its recipient address.
        let ovks = [
            parse_full_viewing_key(external_full_viewing_key)?.to_ovk(Scope::Internal),
            parse_full_viewing_key(internal_full_viewing_key)?.to_ovk(Scope::Internal),
        ];
        let bundle = parse_effects_bundle(&*effects)?;
        for action_idx in 0..bundle.actions().len() {
            let is_change = ovks
                .iter()
                .any(|ovk| bundle.recover_output_with_ovk(action_idx, ovk).is_some());
            ptr::write(change_out.add(action_idx), u8::from(is_change));
        }
        Ok(())
    }));
    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_classify_change_outputs",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

fn compact_known_prefix_matches(
    key: &[u8],
    enc_ciphertext: &[u8; ORCHARD_COMPACT_NOTE_SIZE],
    view_tag: u8,
    diversifier: Option<&[u8; ORCHARD_DIVERSIFIER_SIZE]>,
) -> Result<bool, (i32, String)> {
    // The public index stores only the first Orchard plaintext-byte check. A
    // caller may optionally pass a known diversifier for single-address scans.
    // Branch scans intentionally rely on the view tag and full compact
    // decryption, then recover the diversifier index from the decrypted address.
    let mut cipher = ChaCha20::new_from_slices(key, &[0u8; 12]).map_err(|_| {
        (
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "compact view tag: invalid symmetric key length".to_string(),
        )
    })?;
    let mut prefix = [0u8; 1 + ORCHARD_DIVERSIFIER_SIZE];
    cipher.seek(64);
    cipher.apply_keystream(&mut prefix);
    if prefix[0] != view_tag {
        return Ok(false);
    }
    if let Some(diversifier) = diversifier {
        for (idx, expected) in diversifier.iter().enumerate() {
            if (enc_ciphertext[1 + idx] ^ expected) != prefix[1 + idx] {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
unsafe fn batch_decrypt_compact_outputs_with_fvks_impl(
    full_viewing_keys: *const u8,
    internal_scopes: *const u8,
    diversifiers: *const u8,
    diversifier_known: *const u8,
    viewing_keys_len: usize,
    effects: *const NitoOrchardCompactEffectsView,
    matched_out: *mut u8,
    key_index_out: *mut u32,
    value_out: *mut u64,
    recipient_raw_out: *mut u8,
    cmx_out: *mut u8,
    nullifier_out: *mut u8,
    rho_out: *mut u8,
    rseed_out: *mut u8,
) -> Result<(), (i32, String)> {
    if effects.is_null() {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "compact effects: null pointer".to_string(),
        ));
    }
    if full_viewing_keys.is_null()
        || internal_scopes.is_null()
        || diversifiers.is_null()
        || diversifier_known.is_null()
    {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "compact viewing keys: null pointer".to_string(),
        ));
    }
    if matched_out.is_null()
        || key_index_out.is_null()
        || value_out.is_null()
        || recipient_raw_out.is_null()
        || cmx_out.is_null()
        || nullifier_out.is_null()
        || rho_out.is_null()
        || rseed_out.is_null()
    {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "compact decrypt output: null pointer".to_string(),
        ));
    }

    let effects = &*effects;
    if effects.actions_len == 0 {
        return Err((
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "compact actions: empty".to_string(),
        ));
    }
    if effects.nullifier.is_null()
        || effects.cmx.is_null()
        || effects.ephemeral_key.is_null()
        || effects.enc_ciphertext.is_null()
        || effects.view_tag.is_null()
    {
        return Err((
            NITO_PRIVATE_ERR_NULL_PTR,
            "compact effects: null action column".to_string(),
        ));
    }

    for idx in 0..effects.actions_len {
        ptr::write(matched_out.add(idx), 0u8);
        ptr::write(key_index_out.add(idx), u32::MAX);
        ptr::write(value_out.add(idx), 0u64);
    }
    if viewing_keys_len == 0 {
        return Ok(());
    }
    if viewing_keys_len > u32::MAX as usize {
        return Err((
            NITO_PRIVATE_ERR_BAD_ENCODING,
            "compact viewing keys: too many keys".to_string(),
        ));
    }

    let mut fvks = Vec::with_capacity(viewing_keys_len);
    let mut ivks = Vec::with_capacity(viewing_keys_len);
    let mut expected_diversifiers = Vec::with_capacity(viewing_keys_len);
    for key_idx in 0..viewing_keys_len {
        let fvk = parse_full_viewing_key(full_viewing_keys.add(key_idx * 96))?;
        let diversifier = if *diversifier_known.add(key_idx) != 0 {
            Some(
                read_array::<ORCHARD_DIVERSIFIER_SIZE>(
                    diversifiers.add(key_idx * ORCHARD_DIVERSIFIER_SIZE),
                    "compact viewing key diversifier",
                )
                .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?,
            )
        } else {
            None
        };
        let scope = if *internal_scopes.add(key_idx) == 0 {
            Scope::External
        } else {
            Scope::Internal
        };
        ivks.push(fvk.to_ivk(scope).prepare());
        fvks.push(fvk);
        expected_diversifiers.push(diversifier);
    }

    let mut compact_outputs = Vec::with_capacity(effects.actions_len);
    for action_idx in 0..effects.actions_len {
        compact_outputs.push(
            parse_compact_effect_action(effects, action_idx)
                .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?,
        );
    }

    let ephemeral_keys = OrchardDomain::batch_epk(compact_outputs.iter().map(|(_, action, _)| {
        <CompactAction as ShieldedOutput<OrchardDomain, ORCHARD_COMPACT_NOTE_SIZE>>::ephemeral_key(
            action,
        )
    }));
    let items = ephemeral_keys.iter().flat_map(|(epk, ephemeral_key)| {
        ivks.iter().map(move |ivk| {
            (
                epk.as_ref()
                    .map(|epk| OrchardDomain::ka_agree_dec(ivk, epk)),
                ephemeral_key,
            )
        })
    });
    let keys = OrchardDomain::batch_kdf(items);

    for (action_idx, ((domain, action, view_tag), key_chunk)) in compact_outputs
        .iter()
        .zip(keys.chunks(viewing_keys_len))
        .enumerate()
    {
        for (key_idx, (key, ivk)) in key_chunk.iter().zip(ivks.iter()).enumerate() {
            let Some(key) = key.as_ref() else { continue };
            if !compact_known_prefix_matches(
                key.as_ref(),
                <CompactAction as ShieldedOutput<
                    OrchardDomain,
                    ORCHARD_COMPACT_NOTE_SIZE,
                >>::enc_ciphertext(action),
                *view_tag,
                expected_diversifiers[key_idx].as_ref(),
            )? {
                continue;
            }
            let Some((note, address)) = try_compact_note_decryption(domain, ivk, action) else {
                continue;
            };
            ptr::write(matched_out.add(action_idx), 1u8);
            ptr::write(key_index_out.add(action_idx), key_idx as u32);
            ptr::write(value_out.add(action_idx), note.value().inner());
            write_bytes(
                recipient_raw_out.add(action_idx * ORCHARD_RAW_ADDRESS_SIZE),
                &address.to_raw_address_bytes(),
                "recipient_raw_out",
            )?;
            write_bytes(
                cmx_out.add(action_idx * 32),
                &ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                "cmx_out",
            )?;
            write_bytes(
                nullifier_out.add(action_idx * 32),
                &note.nullifier(&fvks[key_idx]).to_bytes(),
                "nullifier_out",
            )?;
            write_bytes(
                rho_out.add(action_idx * 32),
                &note.rho().to_bytes(),
                "rho_out",
            )?;
            write_bytes(
                rseed_out.add(action_idx * 32),
                note.rseed().as_bytes(),
                "rseed_out",
            )?;
            break;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "C" fn nito_orchard_batch_decrypt_compact_outputs_with_fvks(
    full_viewing_keys: *const u8,
    internal_scopes: *const u8,
    diversifiers: *const u8,
    diversifier_known: *const u8,
    viewing_keys_len: usize,
    effects: *const NitoOrchardCompactEffectsView,
    matched_out: *mut u8,
    key_index_out: *mut u32,
    value_out: *mut u64,
    recipient_raw_out: *mut u8,
    cmx_out: *mut u8,
    nullifier_out: *mut u8,
    rho_out: *mut u8,
    rseed_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        batch_decrypt_compact_outputs_with_fvks_impl(
            full_viewing_keys,
            internal_scopes,
            diversifiers,
            diversifier_known,
            viewing_keys_len,
            effects,
            matched_out,
            key_index_out,
            value_out,
            recipient_raw_out,
            cmx_out,
            nullifier_out,
            rho_out,
            rseed_out,
        )
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_batch_decrypt_compact_outputs_with_fvks",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_compute_note_commitment(
    recipient_raw: *const u8,
    value: u64,
    rho: *const u8,
    rseed: *const u8,
    cmx_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if cmx_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "cmx_out: null pointer".to_string(),
            ));
        }
        if value == 0 {
            return Err((
                NITO_PRIVATE_ERR_BAD_ENCODING,
                "value: zero note value".to_string(),
            ));
        }
        let note = parse_spend_note_parts(recipient_raw, value, rho, rseed)?;
        let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
        write_bytes(cmx_out, &cmx, "cmx_out")?;
        Ok(())
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_compute_note_commitment",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_compute_auth_path(
    cmx_list: *const u8,
    cmx_count: usize,
    position: u32,
    path_out: *mut u8,
    root_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if path_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "path_out: null pointer".to_string(),
            ));
        }
        if root_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "root_out: null pointer".to_string(),
            ));
        }
        let (auth_path, root) = build_auth_path(cmx_list, cmx_count, position)?;
        for (idx, node) in auth_path.iter().enumerate() {
            write_bytes(path_out.add(idx * 32), &node.to_bytes(), "path_out")?;
        }
        write_bytes(root_out, &root, "root_out")?;
        Ok(())
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_compute_auth_path",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_compute_root(
    cmx_list: *const u8,
    cmx_count: usize,
    root_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if root_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "root_out: null pointer".to_string(),
            ));
        }
        let mut tree = CommitmentTree::<MerkleHashOrchard, ORCHARD_MERKLE_DEPTH>::empty();
        if !cmx_list.is_null() {
            let raw_len = cmx_count.checked_mul(32).ok_or_else(|| {
                (
                    NITO_PRIVATE_ERR_BAD_ENCODING,
                    "cmx_count overflow".to_string(),
                )
            })?;
            let raw = slice::from_raw_parts(cmx_list, raw_len);
            for (idx, chunk) in raw.chunks_exact(32).enumerate() {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(chunk);
                let cmx = parse_merkle_hash(bytes)
                    .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, format!("{e} at index {idx}")))?;
                tree.append(cmx).map_err(|_| {
                    (
                        NITO_PRIVATE_ERR_BAD_ENCODING,
                        "commitment tree full".to_string(),
                    )
                })?;
            }
        } else if cmx_count != 0 {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "cmx_list: null pointer".to_string(),
            ));
        }

        let root = tree.root().to_bytes();
        ptr::copy_nonoverlapping(root.as_ptr(), root_out, 32);
        Ok(())
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_compute_root",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_combine_nodes(
    level: u8,
    left: *const u8,
    right: *const u8,
    parent_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if parent_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "parent_out: null pointer".to_string(),
            ));
        }
        if level >= ORCHARD_MERKLE_DEPTH {
            return Err((
                NITO_PRIVATE_ERR_BAD_ENCODING,
                "level: outside Orchard tree".to_string(),
            ));
        }
        let left_bytes =
            read_array::<32>(left, "left").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;
        let right_bytes =
            read_array::<32>(right, "right").map_err(|e| (NITO_PRIVATE_ERR_NULL_PTR, e))?;
        let left = parse_merkle_hash(left_bytes)
            .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, format!("left: {e}")))?;
        let right = parse_merkle_hash(right_bytes)
            .map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, format!("right: {e}")))?;
        let parent = MerkleHashOrchard::combine(Level::from(level), &left, &right).to_bytes();
        write_bytes(parent_out, &parent, "parent_out")?;
        Ok(())
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_combine_nodes",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_empty_root(
    level: u8,
    root_out: *mut u8,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if root_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "root_out: null pointer".to_string(),
            ));
        }
        if level > ORCHARD_MERKLE_DEPTH {
            return Err((
                NITO_PRIVATE_ERR_BAD_ENCODING,
                "level: outside Orchard tree".to_string(),
            ));
        }
        let root = MerkleHashOrchard::empty_root(Level::from(level)).to_bytes();
        write_bytes(root_out, &root, "root_out")?;
        Ok(())
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(err_out, err_out_len, "panic inside nito_orchard_empty_root");
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[no_mangle]
pub extern "C" fn nito_orchard_frontier_append(
    frontier_in: *const u8,
    frontier_in_len: usize,
    cmx_list: *const u8,
    cmx_count: usize,
    root_out: *mut u8,
    frontier_out: *mut u8,
    frontier_out_capacity: usize,
    frontier_out_len: *mut usize,
    err_out: *mut c_char,
    err_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if root_out.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "root_out: null pointer".to_string(),
            ));
        }
        if frontier_out_len.is_null() {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "frontier_out_len: null pointer".to_string(),
            ));
        }
        if frontier_in.is_null() && frontier_in_len != 0 {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "frontier_in: null pointer".to_string(),
            ));
        }
        if cmx_list.is_null() && cmx_count != 0 {
            return Err((
                NITO_PRIVATE_ERR_NULL_PTR,
                "cmx_list: null pointer".to_string(),
            ));
        }

        let frontier_raw = if frontier_in_len == 0 {
            &[]
        } else {
            slice::from_raw_parts(frontier_in, frontier_in_len)
        };
        let mut frontier =
            decode_frontier(frontier_raw).map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?;

        let commitments_raw = if cmx_count == 0 {
            &[]
        } else {
            let raw_len = cmx_count.checked_mul(32).ok_or_else(|| {
                (
                    NITO_PRIVATE_ERR_BAD_ENCODING,
                    "cmx_count overflow".to_string(),
                )
            })?;
            slice::from_raw_parts(cmx_list, raw_len)
        };
        let commitments = parse_commitment_slice(commitments_raw, cmx_count)?;
        for (idx, cmx) in commitments.into_iter().enumerate() {
            if !frontier.append(cmx) {
                return Err((
                    NITO_PRIVATE_ERR_BAD_ENCODING,
                    format!("commitment tree full at appended index {idx}"),
                ));
            }
        }

        let root = frontier.root().to_bytes();
        ptr::copy_nonoverlapping(root.as_ptr(), root_out, 32);

        let encoded = encode_frontier(&frontier).map_err(|e| (NITO_PRIVATE_ERR_BAD_ENCODING, e))?;
        *frontier_out_len = encoded.len();
        if frontier_out.is_null() || frontier_out_capacity < encoded.len() {
            return Err((
                NITO_PRIVATE_ERR_BUFFER_TOO_SMALL,
                format!("frontier_out: buffer too small, need {}", encoded.len()),
            ));
        }
        ptr::copy_nonoverlapping(encoded.as_ptr(), frontier_out, encoded.len());
        Ok(())
    }));

    match result {
        Ok(Ok(())) => {
            set_error(err_out, err_out_len, "");
            NITO_PRIVATE_OK
        }
        Ok(Err((code, msg))) => {
            set_error(err_out, err_out_len, &msg);
            code
        }
        Err(_) => {
            set_error(
                err_out,
                err_out_len,
                "panic inside nito_orchard_frontier_append",
            );
            NITO_PRIVATE_ERR_PANIC
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn build_outputs_are_validated_before_pointer_arithmetic() {
        let byte_ptr = std::ptr::NonNull::<u8>::dangling().as_ptr();
        let mut out = NitoOrchardBuildOutput {
            flags_out: std::ptr::null_mut(),
            value_balance_out: std::ptr::null_mut(),
            actions_len_out: std::ptr::null_mut(),
            actions_cap: 2,
            cv_net_out: byte_ptr,
            nullifier_out: byte_ptr,
            rk_out: byte_ptr,
            cmx_out: byte_ptr,
            ephemeral_key_out: byte_ptr,
            enc_ciphertext_out: byte_ptr,
            out_ciphertext_out: byte_ptr,
            spend_auth_sig_out: byte_ptr,
            proof_out: byte_ptr,
            proof_cap: 128,
            proof_len_out: std::ptr::null_mut(),
            binding_sig_out: byte_ptr,
        };

        assert!(validate_effect_output_buffers(&out, 2).is_ok());
        assert!(validate_authorization_output_buffers(&out, 2, 128).is_ok());

        out.cmx_out = std::ptr::null_mut();
        let (code, message) = validate_effect_output_buffers(&out, 2).unwrap_err();
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
        assert_eq!(message, "cmx_out: null pointer");

        out.cmx_out = byte_ptr;
        out.proof_out = std::ptr::null_mut();
        let (code, message) = validate_authorization_output_buffers(&out, 2, 1).unwrap_err();
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
        assert_eq!(message, "proof_out: null pointer");

        let (code, message) = checked_ffi_buffer_len(usize::MAX, 2, "oversized").unwrap_err();
        assert_eq!(code, NITO_PRIVATE_ERR_BAD_ENCODING);
        assert_eq!(message, "oversized: buffer length overflow");
    }

    fn error_message(err: &[i8]) -> String {
        unsafe { CStr::from_ptr(err.as_ptr()).to_string_lossy().into_owned() }
    }

    fn verify_for_test(bundle: &NitoOrchardBundle) -> (i32, String) {
        let mut err = [0i8; 128];
        let code = nito_orchard_verify_bundle(bundle, err.as_mut_ptr(), err.len());
        (code, error_message(&err))
    }

    fn compute_note_commitment_for_test(
        recipient_raw: &[u8],
        value: u64,
        rho: &[u8; 32],
        rseed: &[u8; 32],
    ) -> ([u8; 32], i32, String) {
        let mut cmx = [0u8; 32];
        let mut err = [0i8; 128];
        let code = nito_orchard_compute_note_commitment(
            recipient_raw.as_ptr(),
            value,
            rho.as_ptr(),
            rseed.as_ptr(),
            cmx.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        (cmx, code, error_message(&err))
    }

    fn full_viewing_key_for_test(sk_bytes: [u8; 32]) -> ([u8; 96], i32, String) {
        let mut fvk = [0u8; 96];
        let mut err = [0i8; 128];
        let code = nito_orchard_full_viewing_key_from_spending_key(
            sk_bytes.as_ptr(),
            fvk.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        (fvk, code, error_message(&err))
    }

    unsafe extern "C" fn test_sighash_callback(
        ctx: *mut c_void,
        effects: *const NitoOrchardEffectsView,
        sighash_out: *mut u8,
        err_out: *mut c_char,
        err_out_len: usize,
    ) -> i32 {
        if ctx.is_null() {
            set_error(err_out, err_out_len, "test sighash ctx is null");
            return NITO_PRIVATE_ERR_NULL_PTR;
        }
        if effects.is_null() {
            set_error(err_out, err_out_len, "test effects view is null");
            return NITO_PRIVATE_ERR_NULL_PTR;
        }
        if sighash_out.is_null() {
            set_error(err_out, err_out_len, "test sighash output is null");
            return NITO_PRIVATE_ERR_NULL_PTR;
        }
        let effects = &*effects;
        if effects.actions_len == 0 || effects.cv_net.is_null() || effects.cmx.is_null() {
            set_error(err_out, err_out_len, "test effects view is incomplete");
            return NITO_PRIVATE_ERR_BAD_ENCODING;
        }
        ptr::copy_nonoverlapping(ctx.cast::<u8>(), sighash_out, NITO_SIGNATURE_HASH_SIZE);
        NITO_PRIVATE_OK
    }

    fn null_action() -> NitoOrchardAction {
        NitoOrchardAction {
            cv_net: ptr::null(),
            nullifier: ptr::null(),
            rk: ptr::null(),
            cmx: ptr::null(),
            ephemeral_key: ptr::null(),
            enc_ciphertext: ptr::null(),
            out_ciphertext: ptr::null(),
            spend_auth_sig: ptr::null(),
        }
    }

    struct TestBundleBuffers {
        flags: u8,
        value_balance: i64,
        actions_len: usize,
        cv: Vec<u8>,
        nf: Vec<u8>,
        rk: Vec<u8>,
        cmx: Vec<u8>,
        epk: Vec<u8>,
        enc: Vec<u8>,
        out_ct: Vec<u8>,
        spend_sigs: Vec<u8>,
        proof: Vec<u8>,
        proof_len: usize,
        binding_sig: [u8; REDPALLAS_SIG_SIZE],
        anchor: [u8; 32],
        sighash: [u8; NITO_SIGNATURE_HASH_SIZE],
    }

    impl TestBundleBuffers {
        fn actions(&self) -> Vec<NitoOrchardAction> {
            (0..self.actions_len)
                .map(|idx| NitoOrchardAction {
                    cv_net: self.cv[idx * 32..].as_ptr(),
                    nullifier: self.nf[idx * 32..].as_ptr(),
                    rk: self.rk[idx * 32..].as_ptr(),
                    cmx: self.cmx[idx * 32..].as_ptr(),
                    ephemeral_key: self.epk[idx * ORCHARD_EPK_SIZE..].as_ptr(),
                    enc_ciphertext: self.enc[idx * ORCHARD_ENC_CIPHERTEXT_SIZE..].as_ptr(),
                    out_ciphertext: self.out_ct[idx * ORCHARD_OUT_CIPHERTEXT_SIZE..].as_ptr(),
                    spend_auth_sig: self.spend_sigs[idx * REDPALLAS_SIG_SIZE..].as_ptr(),
                })
                .collect()
        }

        fn effects_view(&self) -> NitoOrchardEffectsView {
            NitoOrchardEffectsView {
                flags: self.flags,
                value_balance: self.value_balance,
                anchor: self.anchor.as_ptr(),
                actions_len: self.actions_len,
                cv_net: self.cv.as_ptr(),
                nullifier: self.nf.as_ptr(),
                rk: self.rk.as_ptr(),
                cmx: self.cmx.as_ptr(),
                ephemeral_key: self.epk.as_ptr(),
                enc_ciphertext: self.enc.as_ptr(),
                out_ciphertext: self.out_ct.as_ptr(),
            }
        }
    }

    fn new_test_build_output(
        actions_cap: usize,
    ) -> (
        u8,
        i64,
        usize,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        usize,
        [u8; REDPALLAS_SIG_SIZE],
    ) {
        (
            0,
            0,
            0,
            vec![0u8; actions_cap * 32],
            vec![0u8; actions_cap * 32],
            vec![0u8; actions_cap * 32],
            vec![0u8; actions_cap * 32],
            vec![0u8; actions_cap * ORCHARD_EPK_SIZE],
            vec![0u8; actions_cap * ORCHARD_ENC_CIPHERTEXT_SIZE],
            vec![0u8; actions_cap * ORCHARD_OUT_CIPHERTEXT_SIZE],
            vec![0u8; actions_cap * REDPALLAS_SIG_SIZE],
            vec![0u8; 8192],
            0,
            [0u8; REDPALLAS_SIG_SIZE],
        )
    }

    fn build_output_for_test(
        sk_bytes: [u8; 32],
        value: u64,
        anchor: [u8; 32],
        sighash: [u8; NITO_SIGNATURE_HASH_SIZE],
    ) -> TestBundleBuffers {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient_raw = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let actions_cap = 2usize;
        let (
            mut flags,
            mut value_balance,
            mut actions_len,
            mut cv,
            mut nf,
            mut rk,
            mut cmx,
            mut epk,
            mut enc,
            mut out_ct,
            mut spend_sigs,
            mut proof,
            mut proof_len,
            mut binding_sig,
        ) = new_test_build_output(actions_cap);

        let mut out = NitoOrchardBuildOutput {
            flags_out: &mut flags,
            value_balance_out: &mut value_balance,
            actions_len_out: &mut actions_len,
            actions_cap,
            cv_net_out: cv.as_mut_ptr(),
            nullifier_out: nf.as_mut_ptr(),
            rk_out: rk.as_mut_ptr(),
            cmx_out: cmx.as_mut_ptr(),
            ephemeral_key_out: epk.as_mut_ptr(),
            enc_ciphertext_out: enc.as_mut_ptr(),
            out_ciphertext_out: out_ct.as_mut_ptr(),
            spend_auth_sig_out: spend_sigs.as_mut_ptr(),
            proof_out: proof.as_mut_ptr(),
            proof_cap: proof.len(),
            proof_len_out: &mut proof_len,
            binding_sig_out: binding_sig.as_mut_ptr(),
        };
        let mut err = [0i8; 256];
        let code = nito_orchard_build_output_bundle_with_sighash_callback(
            recipient_raw.as_ptr(),
            value,
            anchor.as_ptr(),
            &mut out,
            Some(test_sighash_callback),
            sighash.as_ptr().cast_mut().cast::<c_void>(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
        TestBundleBuffers {
            flags,
            value_balance,
            actions_len,
            cv,
            nf,
            rk,
            cmx,
            epk,
            enc,
            out_ct,
            spend_sigs,
            proof,
            proof_len,
            binding_sig,
            anchor,
            sighash,
        }
    }

    fn verify_test_bundle(bundle: &TestBundleBuffers) {
        let actions = bundle.actions();
        let raw_bundle = NitoOrchardBundle {
            flags: bundle.flags,
            value_balance: bundle.value_balance,
            anchor: bundle.anchor.as_ptr(),
            actions: actions.as_ptr(),
            actions_len: bundle.actions_len,
            proof: bundle.proof.as_ptr(),
            proof_len: bundle.proof_len,
            binding_sig: bundle.binding_sig.as_ptr(),
            sighash: bundle.sighash.as_ptr(),
        };
        let (verify_code, verify_err) = verify_for_test(&raw_bundle);
        assert_eq!(verify_code, NITO_PRIVATE_OK, "{verify_err}");
    }

    fn reject_test_bundle(bundle: &TestBundleBuffers) -> (i32, String) {
        let actions = bundle.actions();
        let raw_bundle = NitoOrchardBundle {
            flags: bundle.flags,
            value_balance: bundle.value_balance,
            anchor: bundle.anchor.as_ptr(),
            actions: actions.as_ptr(),
            actions_len: bundle.actions_len,
            proof: bundle.proof.as_ptr(),
            proof_len: bundle.proof_len,
            binding_sig: bundle.binding_sig.as_ptr(),
            sighash: bundle.sighash.as_ptr(),
        };
        verify_for_test(&raw_bundle)
    }

    fn decrypt_first_note(
        sk_bytes: [u8; 32],
        bundle: &TestBundleBuffers,
    ) -> (
        u64,
        [u8; ORCHARD_RAW_ADDRESS_SIZE],
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        let effects = bundle.effects_view();
        for action_idx in 0..bundle.actions_len {
            let mut matched = 0u8;
            let mut value = 0u64;
            let mut recipient_raw = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
            let mut cmx = [0u8; 32];
            let mut nullifier = [0u8; 32];
            let mut rho = [0u8; 32];
            let mut rseed = [0u8; 32];
            let mut memo = [0u8; 512];
            let mut err = [0i8; 256];
            let code = nito_orchard_decrypt_output(
                sk_bytes.as_ptr(),
                false,
                &effects,
                action_idx,
                &mut matched,
                &mut value,
                recipient_raw.as_mut_ptr(),
                cmx.as_mut_ptr(),
                nullifier.as_mut_ptr(),
                rho.as_mut_ptr(),
                rseed.as_mut_ptr(),
                memo.as_mut_ptr(),
                err.as_mut_ptr(),
                err.len(),
            );
            assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
            if matched == 1 {
                return (value, recipient_raw, cmx, rho, rseed);
            }
        }
        panic!("shielded output should decrypt with the spending key");
    }

    fn decrypt_first_note_with_fvk(
        fvk_bytes: [u8; 96],
        bundle: &TestBundleBuffers,
    ) -> (
        u64,
        [u8; ORCHARD_RAW_ADDRESS_SIZE],
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        let effects = bundle.effects_view();
        for action_idx in 0..bundle.actions_len {
            let mut matched = 0u8;
            let mut value = 0u64;
            let mut recipient_raw = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
            let mut cmx = [0u8; 32];
            let mut nullifier = [0u8; 32];
            let mut rho = [0u8; 32];
            let mut rseed = [0u8; 32];
            let mut memo = [0u8; 512];
            let mut err = [0i8; 256];
            let code = nito_orchard_decrypt_output_with_fvk(
                fvk_bytes.as_ptr(),
                false,
                &effects,
                action_idx,
                &mut matched,
                &mut value,
                recipient_raw.as_mut_ptr(),
                cmx.as_mut_ptr(),
                nullifier.as_mut_ptr(),
                rho.as_mut_ptr(),
                rseed.as_mut_ptr(),
                memo.as_mut_ptr(),
                err.as_mut_ptr(),
                err.len(),
            );
            assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
            if matched == 1 {
                return (value, recipient_raw, cmx, rho, rseed);
            }
        }
        panic!("shielded output should decrypt with the full viewing key");
    }

    #[test]
    fn recomputes_decrypted_note_commitment() {
        let sk_bytes = [7u8; 32];
        let anchor = Anchor::empty_tree().to_bytes();
        let sighash = [9u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = build_output_for_test(sk_bytes, 42_000, anchor, sighash);

        let (value, recipient_raw, cmx, rho, rseed) = decrypt_first_note(sk_bytes, &bundle);
        let (computed_cmx, code, err) =
            compute_note_commitment_for_test(&recipient_raw, value, &rho, &rseed);

        assert_eq!(code, NITO_PRIVATE_OK, "{err}");
        assert_eq!(computed_cmx, cmx);
    }

    #[test]
    fn exports_full_viewing_key_from_spending_key() {
        let sk_bytes = [10u8; 32];
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let expected = FullViewingKey::from(&sk).to_bytes();

        let (fvk, code, err) = full_viewing_key_for_test(sk_bytes);

        assert_eq!(code, NITO_PRIVATE_OK, "{err}");
        assert_eq!(fvk, expected);
    }

    #[test]
    fn decrypts_output_with_full_viewing_key_without_spending_key() {
        let sk_bytes = [11u8; 32];
        let anchor = Anchor::empty_tree().to_bytes();
        let sighash = [12u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = build_output_for_test(sk_bytes, 33_000, anchor, sighash);
        let (fvk, code, err) = full_viewing_key_for_test(sk_bytes);
        assert_eq!(code, NITO_PRIVATE_OK, "{err}");

        let from_spending_key = decrypt_first_note(sk_bytes, &bundle);
        let from_viewing_key = decrypt_first_note_with_fvk(fvk, &bundle);

        assert_eq!(from_spending_key, from_viewing_key);
    }

    #[test]
    fn compact_batch_decryption_supports_known_or_branch_diversifier_scan() {
        let sk_bytes = [13u8; 32];
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient_raw = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let anchor = Anchor::empty_tree().to_bytes();
        let sighash = [14u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = build_output_for_test(sk_bytes, 44_000, anchor, sighash);
        let (full_viewing_key, code, err) = full_viewing_key_for_test(sk_bytes);
        assert_eq!(code, NITO_PRIVATE_OK, "{err}");

        let mut compact_enc = vec![0u8; bundle.actions_len * ORCHARD_COMPACT_NOTE_SIZE];
        let mut view_tags = vec![0u8; bundle.actions_len];
        for action_idx in 0..bundle.actions_len {
            let src = action_idx * ORCHARD_ENC_CIPHERTEXT_SIZE;
            let dst = action_idx * ORCHARD_COMPACT_NOTE_SIZE;
            compact_enc[dst..dst + ORCHARD_COMPACT_NOTE_SIZE]
                .copy_from_slice(&bundle.enc[src..src + ORCHARD_COMPACT_NOTE_SIZE]);
            view_tags[action_idx] = compact_enc[dst] ^ 0x02;
        }
        let compact = NitoOrchardCompactEffectsView {
            actions_len: bundle.actions_len,
            nullifier: bundle.nf.as_ptr(),
            cmx: bundle.cmx.as_ptr(),
            ephemeral_key: bundle.epk.as_ptr(),
            enc_ciphertext: compact_enc.as_ptr(),
            view_tag: view_tags.as_ptr(),
        };

        let mut matched = vec![0u8; bundle.actions_len];
        let mut key_index = vec![u32::MAX; bundle.actions_len];
        let mut value = vec![0u64; bundle.actions_len];
        let mut recipient_out = vec![0u8; bundle.actions_len * ORCHARD_RAW_ADDRESS_SIZE];
        let mut cmx_out = vec![0u8; bundle.actions_len * 32];
        let mut nullifier_out = vec![0u8; bundle.actions_len * 32];
        let mut rho_out = vec![0u8; bundle.actions_len * 32];
        let mut rseed_out = vec![0u8; bundle.actions_len * 32];
        let internal_scopes = [0u8];
        let diversifier = &recipient_raw[..ORCHARD_DIVERSIFIER_SIZE];
        let diversifier_known = [1u8];
        let mut err = [0i8; 256];
        let code = nito_orchard_batch_decrypt_compact_outputs_with_fvks(
            full_viewing_key.as_ptr(),
            internal_scopes.as_ptr(),
            diversifier.as_ptr(),
            diversifier_known.as_ptr(),
            1,
            &compact,
            matched.as_mut_ptr(),
            key_index.as_mut_ptr(),
            value.as_mut_ptr(),
            recipient_out.as_mut_ptr(),
            cmx_out.as_mut_ptr(),
            nullifier_out.as_mut_ptr(),
            rho_out.as_mut_ptr(),
            rseed_out.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert!(matched.iter().any(|m| *m == 1));

        let mut wrong_diversifier = [0u8; ORCHARD_DIVERSIFIER_SIZE];
        wrong_diversifier.copy_from_slice(diversifier);
        wrong_diversifier[0] ^= 1;
        matched.fill(0);
        key_index.fill(u32::MAX);
        value.fill(0);
        let code = nito_orchard_batch_decrypt_compact_outputs_with_fvks(
            full_viewing_key.as_ptr(),
            internal_scopes.as_ptr(),
            wrong_diversifier.as_ptr(),
            diversifier_known.as_ptr(),
            1,
            &compact,
            matched.as_mut_ptr(),
            key_index.as_mut_ptr(),
            value.as_mut_ptr(),
            recipient_out.as_mut_ptr(),
            cmx_out.as_mut_ptr(),
            nullifier_out.as_mut_ptr(),
            rho_out.as_mut_ptr(),
            rseed_out.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert!(matched.iter().all(|m| *m == 0));

        let diversifier_unknown = [0u8];
        matched.fill(0);
        key_index.fill(u32::MAX);
        value.fill(0);
        let code = nito_orchard_batch_decrypt_compact_outputs_with_fvks(
            full_viewing_key.as_ptr(),
            internal_scopes.as_ptr(),
            wrong_diversifier.as_ptr(),
            diversifier_unknown.as_ptr(),
            1,
            &compact,
            matched.as_mut_ptr(),
            key_index.as_mut_ptr(),
            value.as_mut_ptr(),
            recipient_out.as_mut_ptr(),
            cmx_out.as_mut_ptr(),
            nullifier_out.as_mut_ptr(),
            rho_out.as_mut_ptr(),
            rseed_out.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert!(matched.iter().any(|m| *m == 1));
    }

    #[test]
    fn rejects_null_bundle_pointer() {
        let mut err = [0i8; 128];
        let code = nito_orchard_verify_bundle(ptr::null(), err.as_mut_ptr(), err.len());
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
    }

    #[test]
    fn rejects_empty_actions_before_crypto_work() {
        let anchor = Anchor::empty_tree().to_bytes();
        let proof = [1u8; 8];
        let binding_sig = [2u8; REDPALLAS_SIG_SIZE];
        let sighash = [3u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = NitoOrchardBundle {
            flags: nito_orchard_flags_byte(Flags::ENABLED),
            value_balance: 0,
            anchor: anchor.as_ptr(),
            actions: ptr::null(),
            actions_len: 0,
            proof: proof.as_ptr(),
            proof_len: proof.len(),
            binding_sig: binding_sig.as_ptr(),
            sighash: sighash.as_ptr(),
        };
        let mut err = [0i8; 128];
        let code = nito_orchard_verify_bundle(&bundle, err.as_mut_ptr(), err.len());
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
    }

    #[test]
    fn rejects_reserved_flag_bits() {
        let action = null_action();
        let anchor = Anchor::empty_tree().to_bytes();
        let proof = [1u8; 8];
        let binding_sig = [2u8; REDPALLAS_SIG_SIZE];
        let sighash = [3u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = NitoOrchardBundle {
            flags: 0xff,
            value_balance: 0,
            anchor: anchor.as_ptr(),
            actions: &action,
            actions_len: 1,
            proof: proof.as_ptr(),
            proof_len: proof.len(),
            binding_sig: binding_sig.as_ptr(),
            sighash: sighash.as_ptr(),
        };

        let (code, err) = verify_for_test(&bundle);
        assert_eq!(code, NITO_PRIVATE_ERR_BAD_ENCODING);
        assert!(err.contains("flags: reserved bits set"), "{err}");
    }

    #[test]
    fn rejects_non_canonical_anchor() {
        let action = null_action();
        let non_canonical_anchor = [0xffu8; 32];
        let proof = [1u8; 8];
        let binding_sig = [2u8; REDPALLAS_SIG_SIZE];
        let sighash = [3u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = NitoOrchardBundle {
            flags: nito_orchard_flags_byte(Flags::ENABLED),
            value_balance: 0,
            anchor: non_canonical_anchor.as_ptr(),
            actions: &action,
            actions_len: 1,
            proof: proof.as_ptr(),
            proof_len: proof.len(),
            binding_sig: binding_sig.as_ptr(),
            sighash: sighash.as_ptr(),
        };

        let (code, err) = verify_for_test(&bundle);
        assert_eq!(code, NITO_PRIVATE_ERR_BAD_ENCODING);
        assert!(err.contains("anchor: non-canonical"), "{err}");
    }

    #[test]
    fn rejects_null_actions_with_nonzero_length() {
        let anchor = Anchor::empty_tree().to_bytes();
        let proof = [1u8; 8];
        let binding_sig = [2u8; REDPALLAS_SIG_SIZE];
        let sighash = [3u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = NitoOrchardBundle {
            flags: nito_orchard_flags_byte(Flags::ENABLED),
            value_balance: 0,
            anchor: anchor.as_ptr(),
            actions: ptr::null(),
            actions_len: 1,
            proof: proof.as_ptr(),
            proof_len: proof.len(),
            binding_sig: binding_sig.as_ptr(),
            sighash: sighash.as_ptr(),
        };

        let (code, err) = verify_for_test(&bundle);
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
        assert!(err.contains("actions: empty or null"), "{err}");
    }

    #[test]
    fn rejects_null_action_field_without_dereferencing_it() {
        let action = null_action();
        let anchor = Anchor::empty_tree().to_bytes();
        let proof = [1u8; 8];
        let binding_sig = [2u8; REDPALLAS_SIG_SIZE];
        let sighash = [3u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = NitoOrchardBundle {
            flags: nito_orchard_flags_byte(Flags::ENABLED),
            value_balance: 0,
            anchor: anchor.as_ptr(),
            actions: &action,
            actions_len: 1,
            proof: proof.as_ptr(),
            proof_len: proof.len(),
            binding_sig: binding_sig.as_ptr(),
            sighash: sighash.as_ptr(),
        };

        let (code, err) = verify_for_test(&bundle);
        assert_eq!(code, NITO_PRIVATE_ERR_BAD_ENCODING);
        assert!(err.contains("cv_net: null pointer"), "{err}");
    }

    #[test]
    fn rejects_empty_proof_slice() {
        let action = null_action();
        let anchor = Anchor::empty_tree().to_bytes();
        let proof = [1u8; 1];
        let binding_sig = [2u8; REDPALLAS_SIG_SIZE];
        let sighash = [3u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = NitoOrchardBundle {
            flags: nito_orchard_flags_byte(Flags::ENABLED),
            value_balance: 0,
            anchor: anchor.as_ptr(),
            actions: &action,
            actions_len: 1,
            proof: proof.as_ptr(),
            proof_len: 0,
            binding_sig: binding_sig.as_ptr(),
            sighash: sighash.as_ptr(),
        };

        let (code, err) = verify_for_test(&bundle);
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
        assert!(err.contains("proof: empty"), "{err}");
    }

    #[test]
    fn rejects_null_proof_pointer() {
        let action = null_action();
        let anchor = Anchor::empty_tree().to_bytes();
        let binding_sig = [2u8; REDPALLAS_SIG_SIZE];
        let sighash = [3u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = NitoOrchardBundle {
            flags: nito_orchard_flags_byte(Flags::ENABLED),
            value_balance: 0,
            anchor: anchor.as_ptr(),
            actions: &action,
            actions_len: 1,
            proof: ptr::null(),
            proof_len: 1,
            binding_sig: binding_sig.as_ptr(),
            sighash: sighash.as_ptr(),
        };

        let (code, err) = verify_for_test(&bundle);
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
        assert!(err.contains("proof: null pointer"), "{err}");
    }

    #[test]
    fn rejects_null_binding_signature_pointer() {
        let action = null_action();
        let anchor = Anchor::empty_tree().to_bytes();
        let proof = [1u8; 8];
        let sighash = [3u8; NITO_SIGNATURE_HASH_SIZE];
        let bundle = NitoOrchardBundle {
            flags: nito_orchard_flags_byte(Flags::ENABLED),
            value_balance: 0,
            anchor: anchor.as_ptr(),
            actions: &action,
            actions_len: 1,
            proof: proof.as_ptr(),
            proof_len: proof.len(),
            binding_sig: ptr::null(),
            sighash: sighash.as_ptr(),
        };

        let (code, err) = verify_for_test(&bundle);
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
        assert!(err.contains("binding_sig: null pointer"), "{err}");
    }

    #[test]
    fn derives_raw_address_from_spending_key() {
        let sk_bytes = [9u8; 32];
        let expected_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let expected = FullViewingKey::from(&expected_sk)
            .address_at(7u32, Scope::External)
            .to_raw_address_bytes();
        let mut raw_address = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
        let mut err = [0i8; 128];
        let code = nito_orchard_raw_address_from_spending_key(
            sk_bytes.as_ptr(),
            7,
            raw_address.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(raw_address, expected);
    }

    #[test]
    fn derives_scoped_raw_addresses_from_spending_key() {
        let sk_bytes = [9u8; 32];
        let expected_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let fvk = FullViewingKey::from(&expected_sk);
        let expected_external = fvk
            .address_at(11u32, Scope::External)
            .to_raw_address_bytes();
        let expected_internal = fvk
            .address_at(11u32, Scope::Internal)
            .to_raw_address_bytes();

        let mut external_raw = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
        let mut internal_raw = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
        let mut err = [0i8; 128];

        let external_code = nito_orchard_raw_address_from_spending_key_scoped(
            sk_bytes.as_ptr(),
            11,
            false,
            external_raw.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(external_code, NITO_PRIVATE_OK, "{}", error_message(&err));

        let internal_code = nito_orchard_raw_address_from_spending_key_scoped(
            sk_bytes.as_ptr(),
            11,
            true,
            internal_raw.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(internal_code, NITO_PRIVATE_OK, "{}", error_message(&err));

        assert_eq!(external_raw, expected_external);
        assert_eq!(internal_raw, expected_internal);
        assert_ne!(external_raw, internal_raw);
    }

    #[test]
    fn roundtrips_distant_diversifier_indices_through_branch_fvk() {
        let sk_bytes = [9u8; 32];
        let (fvk, fvk_code, fvk_error) = full_viewing_key_for_test(sk_bytes);
        assert_eq!(fvk_code, NITO_PRIVATE_OK, "{fvk_error}");

        for internal in [false, true] {
            for expected_index in [0u32, 63, 64, 127, 1_000, 1_000_000] {
                let mut raw_address = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
                let mut err = [0i8; 128];
                let derive_code = nito_orchard_raw_address_from_spending_key_scoped(
                    sk_bytes.as_ptr(),
                    expected_index,
                    internal,
                    raw_address.as_mut_ptr(),
                    err.as_mut_ptr(),
                    err.len(),
                );
                assert_eq!(derive_code, NITO_PRIVATE_OK, "{}", error_message(&err));

                let mut matched = 0u8;
                let mut recovered_index = u32::MAX;
                let recover_code = nito_orchard_fvk_diversifier_index(
                    fvk.as_ptr(),
                    internal,
                    raw_address.as_ptr(),
                    &mut matched,
                    &mut recovered_index,
                    err.as_mut_ptr(),
                    err.len(),
                );
                assert_eq!(recover_code, NITO_PRIVATE_OK, "{}", error_message(&err));
                assert_eq!(matched, 1);
                assert_eq!(recovered_index, expected_index);
            }
        }
    }

    #[test]
    fn rejects_null_raw_address_output() {
        let sk_bytes = [9u8; 32];
        let mut err = [0i8; 128];
        let code = nito_orchard_raw_address_from_spending_key(
            sk_bytes.as_ptr(),
            0,
            ptr::null_mut(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
        assert!(error_message(&err).contains("raw_address_out: null pointer"));
    }

    #[test]
    fn builds_output_bundle_that_verifies() {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient_raw = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let anchor = Anchor::empty_tree().to_bytes();
        let sighash = [9u8; NITO_SIGNATURE_HASH_SIZE];

        let actions_cap = 2usize;
        let mut flags = 0u8;
        let mut value_balance = 0i64;
        let mut actions_len = 0usize;
        let mut cv = vec![0u8; actions_cap * 32];
        let mut nf = vec![0u8; actions_cap * 32];
        let mut rk = vec![0u8; actions_cap * 32];
        let mut cmx = vec![0u8; actions_cap * 32];
        let mut epk = vec![0u8; actions_cap * ORCHARD_EPK_SIZE];
        let mut enc = vec![0u8; actions_cap * ORCHARD_ENC_CIPHERTEXT_SIZE];
        let mut out_ct = vec![0u8; actions_cap * ORCHARD_OUT_CIPHERTEXT_SIZE];
        let mut spend_sigs = vec![0u8; actions_cap * REDPALLAS_SIG_SIZE];
        let mut proof = vec![0u8; 8192];
        let mut proof_len = 0usize;
        let mut binding_sig = [0u8; REDPALLAS_SIG_SIZE];

        let mut out = NitoOrchardBuildOutput {
            flags_out: &mut flags,
            value_balance_out: &mut value_balance,
            actions_len_out: &mut actions_len,
            actions_cap,
            cv_net_out: cv.as_mut_ptr(),
            nullifier_out: nf.as_mut_ptr(),
            rk_out: rk.as_mut_ptr(),
            cmx_out: cmx.as_mut_ptr(),
            ephemeral_key_out: epk.as_mut_ptr(),
            enc_ciphertext_out: enc.as_mut_ptr(),
            out_ciphertext_out: out_ct.as_mut_ptr(),
            spend_auth_sig_out: spend_sigs.as_mut_ptr(),
            proof_out: proof.as_mut_ptr(),
            proof_cap: proof.len(),
            proof_len_out: &mut proof_len,
            binding_sig_out: binding_sig.as_mut_ptr(),
        };
        let mut err = [0i8; 256];
        let code = nito_orchard_build_output_bundle(
            recipient_raw.as_ptr(),
            5000,
            anchor.as_ptr(),
            sighash.as_ptr(),
            &mut out,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(flags, nito_orchard_flags_byte(Flags::ENABLED));
        assert_eq!(value_balance, -5000);
        assert_eq!(actions_len, actions_cap);
        assert!(proof_len > 0);

        let actions = (0..actions_len)
            .map(|idx| NitoOrchardAction {
                cv_net: cv[idx * 32..].as_ptr(),
                nullifier: nf[idx * 32..].as_ptr(),
                rk: rk[idx * 32..].as_ptr(),
                cmx: cmx[idx * 32..].as_ptr(),
                ephemeral_key: epk[idx * ORCHARD_EPK_SIZE..].as_ptr(),
                enc_ciphertext: enc[idx * ORCHARD_ENC_CIPHERTEXT_SIZE..].as_ptr(),
                out_ciphertext: out_ct[idx * ORCHARD_OUT_CIPHERTEXT_SIZE..].as_ptr(),
                spend_auth_sig: spend_sigs[idx * REDPALLAS_SIG_SIZE..].as_ptr(),
            })
            .collect::<Vec<_>>();
        let bundle = NitoOrchardBundle {
            flags,
            value_balance,
            anchor: anchor.as_ptr(),
            actions: actions.as_ptr(),
            actions_len,
            proof: proof.as_ptr(),
            proof_len,
            binding_sig: binding_sig.as_ptr(),
            sighash: sighash.as_ptr(),
        };
        let (verify_code, verify_err) = verify_for_test(&bundle);
        assert_eq!(verify_code, NITO_PRIVATE_OK, "{verify_err}");
    }

    #[test]
    fn rejects_output_bundle_with_padded_proof() {
        let mut bundle = build_output_for_test(
            [27u8; 32],
            5000,
            Anchor::empty_tree().to_bytes(),
            [91u8; NITO_SIGNATURE_HASH_SIZE],
        );
        verify_test_bundle(&bundle);

        assert!(bundle.proof_len + 1 <= bundle.proof.len());
        bundle.proof[bundle.proof_len] = 0;
        bundle.proof_len += 1;

        let (verify_code, verify_err) = reject_test_bundle(&bundle);
        assert_eq!(verify_code, NITO_PRIVATE_ERR_BAD_ENCODING, "{verify_err}");
        assert!(
            verify_err.to_ascii_lowercase().contains("proof"),
            "{verify_err}"
        );
    }

    #[test]
    fn rejects_bad_authorization_before_bad_halo2_proof() {
        let mut bundle = build_output_for_test(
            [28u8; 32],
            5000,
            Anchor::empty_tree().to_bytes(),
            [92u8; NITO_SIGNATURE_HASH_SIZE],
        );
        verify_test_bundle(&bundle);

        bundle.proof[0] ^= 1;
        bundle.spend_sigs[0] ^= 1;

        let (verify_code, verify_err) = reject_test_bundle(&bundle);
        assert_eq!(verify_code, NITO_PRIVATE_ERR_BAD_SPEND_SIG, "{verify_err}");
        assert!(verify_err.contains("spend authorization"), "{verify_err}");
    }

    #[test]
    fn builds_output_bundle_with_callback_that_verifies() {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([8u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient_raw = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let anchor = Anchor::empty_tree().to_bytes();
        let sighash = [11u8; NITO_SIGNATURE_HASH_SIZE];

        let actions_cap = 2usize;
        let mut flags = 0u8;
        let mut value_balance = 0i64;
        let mut actions_len = 0usize;
        let mut cv = vec![0u8; actions_cap * 32];
        let mut nf = vec![0u8; actions_cap * 32];
        let mut rk = vec![0u8; actions_cap * 32];
        let mut cmx = vec![0u8; actions_cap * 32];
        let mut epk = vec![0u8; actions_cap * ORCHARD_EPK_SIZE];
        let mut enc = vec![0u8; actions_cap * ORCHARD_ENC_CIPHERTEXT_SIZE];
        let mut out_ct = vec![0u8; actions_cap * ORCHARD_OUT_CIPHERTEXT_SIZE];
        let mut spend_sigs = vec![0u8; actions_cap * REDPALLAS_SIG_SIZE];
        let mut proof = vec![0u8; 8192];
        let mut proof_len = 0usize;
        let mut binding_sig = [0u8; REDPALLAS_SIG_SIZE];

        let mut out = NitoOrchardBuildOutput {
            flags_out: &mut flags,
            value_balance_out: &mut value_balance,
            actions_len_out: &mut actions_len,
            actions_cap,
            cv_net_out: cv.as_mut_ptr(),
            nullifier_out: nf.as_mut_ptr(),
            rk_out: rk.as_mut_ptr(),
            cmx_out: cmx.as_mut_ptr(),
            ephemeral_key_out: epk.as_mut_ptr(),
            enc_ciphertext_out: enc.as_mut_ptr(),
            out_ciphertext_out: out_ct.as_mut_ptr(),
            spend_auth_sig_out: spend_sigs.as_mut_ptr(),
            proof_out: proof.as_mut_ptr(),
            proof_cap: proof.len(),
            proof_len_out: &mut proof_len,
            binding_sig_out: binding_sig.as_mut_ptr(),
        };
        let mut err = [0i8; 256];
        let code = nito_orchard_build_output_bundle_with_sighash_callback(
            recipient_raw.as_ptr(),
            7000,
            anchor.as_ptr(),
            &mut out,
            Some(test_sighash_callback),
            sighash.as_ptr().cast_mut().cast::<c_void>(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(flags, nito_orchard_flags_byte(Flags::ENABLED));
        assert_eq!(value_balance, -7000);
        assert_eq!(actions_len, actions_cap);
        assert!(proof_len > 0);

        let actions = (0..actions_len)
            .map(|idx| NitoOrchardAction {
                cv_net: cv[idx * 32..].as_ptr(),
                nullifier: nf[idx * 32..].as_ptr(),
                rk: rk[idx * 32..].as_ptr(),
                cmx: cmx[idx * 32..].as_ptr(),
                ephemeral_key: epk[idx * ORCHARD_EPK_SIZE..].as_ptr(),
                enc_ciphertext: enc[idx * ORCHARD_ENC_CIPHERTEXT_SIZE..].as_ptr(),
                out_ciphertext: out_ct[idx * ORCHARD_OUT_CIPHERTEXT_SIZE..].as_ptr(),
                spend_auth_sig: spend_sigs[idx * REDPALLAS_SIG_SIZE..].as_ptr(),
            })
            .collect::<Vec<_>>();
        let bundle = NitoOrchardBundle {
            flags,
            value_balance,
            anchor: anchor.as_ptr(),
            actions: actions.as_ptr(),
            actions_len,
            proof: proof.as_ptr(),
            proof_len,
            binding_sig: binding_sig.as_ptr(),
            sighash: sighash.as_ptr(),
        };
        let (verify_code, verify_err) = verify_for_test(&bundle);
        assert_eq!(verify_code, NITO_PRIVATE_OK, "{verify_err}");
    }

    #[test]
    fn decrypts_output_computes_auth_path_and_builds_spend_bundle_that_verifies() {
        let sk_bytes = [12u8; 32];
        let anchor = Anchor::empty_tree().to_bytes();
        let shielding_sighash = [21u8; NITO_SIGNATURE_HASH_SIZE];
        let shield = build_output_for_test(sk_bytes, 5000, anchor, shielding_sighash);
        verify_test_bundle(&shield);

        let effects = shield.effects_view();
        let mut matched_note = None;
        for action_idx in 0..shield.actions_len {
            let mut matched = 0u8;
            let mut value = 0u64;
            let mut recipient_raw = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
            let mut cmx = [0u8; 32];
            let mut nullifier = [0u8; 32];
            let mut rho = [0u8; 32];
            let mut rseed = [0u8; 32];
            let mut memo = [0u8; 512];
            let mut err = [0i8; 256];
            let code = nito_orchard_decrypt_output(
                sk_bytes.as_ptr(),
                false,
                &effects,
                action_idx,
                &mut matched,
                &mut value,
                recipient_raw.as_mut_ptr(),
                cmx.as_mut_ptr(),
                nullifier.as_mut_ptr(),
                rho.as_mut_ptr(),
                rseed.as_mut_ptr(),
                memo.as_mut_ptr(),
                err.as_mut_ptr(),
                err.len(),
            );
            assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
            if matched == 1 {
                matched_note = Some((value, recipient_raw, cmx, nullifier, rho, rseed));
                break;
            }
        }

        let (note_value, note_recipient_raw, note_cmx, _note_nullifier, note_rho, note_rseed) =
            matched_note.expect("shielded output should decrypt with the spending key");
        assert_eq!(note_value, 5000);

        let mut auth_path = [0u8; ORCHARD_MERKLE_DEPTH_USIZE * 32];
        let mut auth_root = [0u8; 32];
        let mut err = [0i8; 256];
        let path_code = nito_orchard_compute_auth_path(
            note_cmx.as_ptr(),
            1,
            0,
            auth_path.as_mut_ptr(),
            auth_root.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(path_code, NITO_PRIVATE_OK, "{}", error_message(&err));

        let mut direct_root = [0u8; 32];
        let root_code = nito_orchard_compute_root(
            note_cmx.as_ptr(),
            1,
            direct_root.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(root_code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(auth_root, direct_root);

        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let output_recipient = fvk.address_at(2u32, Scope::External).to_raw_address_bytes();

        let actions_cap = 2usize;
        let (
            mut flags,
            mut value_balance,
            mut actions_len,
            mut cv,
            mut nf,
            mut rk,
            mut cmx,
            mut epk,
            mut enc,
            mut out_ct,
            mut spend_sigs,
            mut proof,
            mut proof_len,
            mut binding_sig,
        ) = new_test_build_output(actions_cap);
        let mut out = NitoOrchardBuildOutput {
            flags_out: &mut flags,
            value_balance_out: &mut value_balance,
            actions_len_out: &mut actions_len,
            actions_cap,
            cv_net_out: cv.as_mut_ptr(),
            nullifier_out: nf.as_mut_ptr(),
            rk_out: rk.as_mut_ptr(),
            cmx_out: cmx.as_mut_ptr(),
            ephemeral_key_out: epk.as_mut_ptr(),
            enc_ciphertext_out: enc.as_mut_ptr(),
            out_ciphertext_out: out_ct.as_mut_ptr(),
            spend_auth_sig_out: spend_sigs.as_mut_ptr(),
            proof_out: proof.as_mut_ptr(),
            proof_cap: proof.len(),
            proof_len_out: &mut proof_len,
            binding_sig_out: binding_sig.as_mut_ptr(),
        };
        let request = NitoOrchardSpendRequest {
            spending_key: sk_bytes.as_ptr(),
            note_recipient_raw: note_recipient_raw.as_ptr(),
            note_value,
            note_rho: note_rho.as_ptr(),
            note_rseed: note_rseed.as_ptr(),
            note_position: 0,
            merkle_path: auth_path.as_ptr(),
            output_recipient_raw: output_recipient.as_ptr(),
            output_value: 5000,
            output_ovk_internal: false,
        };
        let spend_sighash = [22u8; NITO_SIGNATURE_HASH_SIZE];
        let spend_code = nito_orchard_build_spend_bundle_with_sighash_callback(
            &request,
            auth_root.as_ptr(),
            &mut out,
            Some(test_sighash_callback),
            spend_sighash.as_ptr().cast_mut().cast::<c_void>(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(spend_code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(flags, nito_orchard_flags_byte(Flags::ENABLED));
        assert_eq!(value_balance, 0);
        assert_eq!(actions_len, actions_cap);
        assert!(proof_len > 0);

        let spend = TestBundleBuffers {
            flags,
            value_balance,
            actions_len,
            cv,
            nf,
            rk,
            cmx,
            epk,
            enc,
            out_ct,
            spend_sigs,
            proof,
            proof_len,
            binding_sig,
            anchor: auth_root,
            sighash: spend_sighash,
        };
        verify_test_bundle(&spend);
    }

    #[test]
    fn builds_spend_bundle_with_private_change_that_verifies() {
        let sk_bytes = [13u8; 32];
        let anchor = Anchor::empty_tree().to_bytes();
        let shielding_sighash = [31u8; NITO_SIGNATURE_HASH_SIZE];
        let shield = build_output_for_test(sk_bytes, 8000, anchor, shielding_sighash);
        verify_test_bundle(&shield);

        let effects = shield.effects_view();
        let mut matched_note = None;
        for action_idx in 0..shield.actions_len {
            let mut matched = 0u8;
            let mut value = 0u64;
            let mut recipient_raw = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
            let mut cmx = [0u8; 32];
            let mut nullifier = [0u8; 32];
            let mut rho = [0u8; 32];
            let mut rseed = [0u8; 32];
            let mut memo = [0u8; 512];
            let mut err = [0i8; 256];
            let code = nito_orchard_decrypt_output(
                sk_bytes.as_ptr(),
                false,
                &effects,
                action_idx,
                &mut matched,
                &mut value,
                recipient_raw.as_mut_ptr(),
                cmx.as_mut_ptr(),
                nullifier.as_mut_ptr(),
                rho.as_mut_ptr(),
                rseed.as_mut_ptr(),
                memo.as_mut_ptr(),
                err.as_mut_ptr(),
                err.len(),
            );
            assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
            if matched == 1 {
                matched_note = Some((value, recipient_raw, cmx, rho, rseed));
                break;
            }
        }

        let (note_value, note_recipient_raw, note_cmx, note_rho, note_rseed) =
            matched_note.expect("shielded output should decrypt with the spending key");
        assert_eq!(note_value, 8000);

        let mut auth_path = [0u8; ORCHARD_MERKLE_DEPTH_USIZE * 32];
        let mut auth_root = [0u8; 32];
        let mut err = [0i8; 256];
        let path_code = nito_orchard_compute_auth_path(
            note_cmx.as_ptr(),
            1,
            0,
            auth_path.as_mut_ptr(),
            auth_root.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(path_code, NITO_PRIVATE_OK, "{}", error_message(&err));

        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let fvk = FullViewingKey::from(&sk);
        // An explicit self-payment and change may use the same source address.
        let recipient_raw = note_recipient_raw;
        let change_raw = note_recipient_raw;
        let spends = [NitoOrchardSpendInput {
            spending_key: sk_bytes.as_ptr(),
            note_recipient_raw: note_recipient_raw.as_ptr(),
            note_value,
            note_rho: note_rho.as_ptr(),
            note_rseed: note_rseed.as_ptr(),
            note_position: 0,
            merkle_path: auth_path.as_ptr(),
        }];
        let outputs = [
            NitoOrchardOutputRequest {
                recipient_raw: recipient_raw.as_ptr(),
                value: 3000,
                ovk_internal: false,
            },
            NitoOrchardOutputRequest {
                recipient_raw: change_raw.as_ptr(),
                value: 4800,
                ovk_internal: true,
            },
        ];

        let actions_cap = 4usize;
        let (
            mut flags,
            mut value_balance,
            mut actions_len,
            mut cv,
            mut nf,
            mut rk,
            mut cmx,
            mut epk,
            mut enc,
            mut out_ct,
            mut spend_sigs,
            mut proof,
            mut proof_len,
            mut binding_sig,
        ) = new_test_build_output(actions_cap);
        let mut out = NitoOrchardBuildOutput {
            flags_out: &mut flags,
            value_balance_out: &mut value_balance,
            actions_len_out: &mut actions_len,
            actions_cap,
            cv_net_out: cv.as_mut_ptr(),
            nullifier_out: nf.as_mut_ptr(),
            rk_out: rk.as_mut_ptr(),
            cmx_out: cmx.as_mut_ptr(),
            ephemeral_key_out: epk.as_mut_ptr(),
            enc_ciphertext_out: enc.as_mut_ptr(),
            out_ciphertext_out: out_ct.as_mut_ptr(),
            spend_auth_sig_out: spend_sigs.as_mut_ptr(),
            proof_out: proof.as_mut_ptr(),
            proof_cap: proof.len(),
            proof_len_out: &mut proof_len,
            binding_sig_out: binding_sig.as_mut_ptr(),
        };
        let spend_sighash = [32u8; NITO_SIGNATURE_HASH_SIZE];
        let spend_code = nito_orchard_build_bundle_with_sighash_callback(
            spends.as_ptr(),
            spends.len(),
            outputs.as_ptr(),
            outputs.len(),
            auth_root.as_ptr(),
            &mut out,
            Some(test_sighash_callback),
            spend_sighash.as_ptr().cast_mut().cast::<c_void>(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(spend_code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(flags, nito_orchard_flags_byte(Flags::ENABLED));
        assert_eq!(value_balance, 200);
        assert!(actions_len > 0 && actions_len <= actions_cap);
        assert!(proof_len > 0);

        let spend = TestBundleBuffers {
            flags,
            value_balance,
            actions_len,
            cv,
            nf,
            rk,
            cmx,
            epk,
            enc,
            out_ct,
            spend_sigs,
            proof,
            proof_len,
            binding_sig,
            anchor: auth_root,
            sighash: spend_sighash,
        };
        verify_test_bundle(&spend);
        let other_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([14u8; 32])).unwrap();
        let other_fvk = FullViewingKey::from(&other_sk).to_bytes();
        let fvk_bytes = fvk.to_bytes();
        for keys in [(&fvk_bytes, &other_fvk), (&other_fvk, &fvk_bytes)] {
            let mut change = vec![0u8; actions_len + 1];
            change[actions_len] = 0xa5;
            let effects = spend.effects_view();
            assert_eq!(
                nito_orchard_classify_change_outputs(
                    keys.0.as_ptr(),
                    keys.1.as_ptr(),
                    &effects,
                    change.as_mut_ptr(),
                    actions_len,
                    err.as_mut_ptr(),
                    err.len(),
                ),
                NITO_PRIVATE_OK,
                "{}",
                error_message(&err)
            );
            assert_eq!(change[actions_len], 0xa5);
            assert_eq!(
                change[..actions_len]
                    .iter()
                    .filter(|&&flag| flag == 1)
                    .count(),
                1
            );
            let parsed = unsafe { parse_effects_bundle(&effects).unwrap() };
            for (idx, &flag) in change[..actions_len].iter().enumerate() {
                if let Some((note, address, _)) =
                    parsed.decrypt_output_with_key(idx, &fvk.to_ivk(Scope::External))
                {
                    assert_eq!(address.to_raw_address_bytes(), recipient_raw);
                    assert_eq!(flag, u8::from(note.value().inner() == 4800));
                }
            }
            assert_eq!(
                nito_orchard_classify_change_outputs(
                    keys.0.as_ptr(),
                    keys.1.as_ptr(),
                    &effects,
                    change.as_mut_ptr(),
                    actions_len - 1,
                    err.as_mut_ptr(),
                    err.len(),
                ),
                NITO_PRIVATE_ERR_BUFFER_TOO_SMALL
            );
            assert_eq!(
                nito_orchard_classify_change_outputs(
                    keys.0.as_ptr(),
                    keys.1.as_ptr(),
                    ptr::null(),
                    change.as_mut_ptr(),
                    actions_len,
                    err.as_mut_ptr(),
                    err.len(),
                ),
                NITO_PRIVATE_ERR_NULL_PTR
            );
            assert_eq!(
                nito_orchard_classify_change_outputs(
                    other_fvk.as_ptr(),
                    other_fvk.as_ptr(),
                    &effects,
                    change.as_mut_ptr(),
                    actions_len,
                    err.as_mut_ptr(),
                    err.len(),
                ),
                NITO_PRIVATE_OK
            );
            assert!(change[..actions_len].iter().all(|&flag| flag == 0));
        }
    }

    #[test]
    fn builds_spend_only_bundle_that_verifies() {
        let sk_bytes = [15u8; 32];
        let anchor = Anchor::empty_tree().to_bytes();
        let note = build_output_for_test(sk_bytes, 8000, anchor, [51u8; NITO_SIGNATURE_HASH_SIZE]);
        verify_test_bundle(&note);

        let (note_value, note_recipient_raw, note_cmx, note_rho, note_rseed) =
            decrypt_first_note(sk_bytes, &note);

        let mut auth_path = [0u8; ORCHARD_MERKLE_DEPTH_USIZE * 32];
        let mut auth_root = [0u8; 32];
        let mut err = [0i8; 256];
        let path_code = nito_orchard_compute_auth_path(
            note_cmx.as_ptr(),
            1,
            0,
            auth_path.as_mut_ptr(),
            auth_root.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(path_code, NITO_PRIVATE_OK, "{}", error_message(&err));

        let spends = [NitoOrchardSpendInput {
            spending_key: sk_bytes.as_ptr(),
            note_recipient_raw: note_recipient_raw.as_ptr(),
            note_value,
            note_rho: note_rho.as_ptr(),
            note_rseed: note_rseed.as_ptr(),
            note_position: 0,
            merkle_path: auth_path.as_ptr(),
        }];

        let actions_cap = 2usize;
        let (
            mut flags,
            mut value_balance,
            mut actions_len,
            mut cv,
            mut nf,
            mut rk,
            mut cmx,
            mut epk,
            mut enc,
            mut out_ct,
            mut spend_sigs,
            mut proof,
            mut proof_len,
            mut binding_sig,
        ) = new_test_build_output(actions_cap);
        let mut out = NitoOrchardBuildOutput {
            flags_out: &mut flags,
            value_balance_out: &mut value_balance,
            actions_len_out: &mut actions_len,
            actions_cap,
            cv_net_out: cv.as_mut_ptr(),
            nullifier_out: nf.as_mut_ptr(),
            rk_out: rk.as_mut_ptr(),
            cmx_out: cmx.as_mut_ptr(),
            ephemeral_key_out: epk.as_mut_ptr(),
            enc_ciphertext_out: enc.as_mut_ptr(),
            out_ciphertext_out: out_ct.as_mut_ptr(),
            spend_auth_sig_out: spend_sigs.as_mut_ptr(),
            proof_out: proof.as_mut_ptr(),
            proof_cap: proof.len(),
            proof_len_out: &mut proof_len,
            binding_sig_out: binding_sig.as_mut_ptr(),
        };
        let spend_sighash = [52u8; NITO_SIGNATURE_HASH_SIZE];
        let spend_code = nito_orchard_build_bundle_with_sighash_callback(
            spends.as_ptr(),
            spends.len(),
            ptr::null(),
            0,
            auth_root.as_ptr(),
            &mut out,
            Some(test_sighash_callback),
            spend_sighash.as_ptr().cast_mut().cast::<c_void>(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(spend_code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(flags, nito_orchard_flags_byte(Flags::ENABLED));
        assert_eq!(value_balance, 8000);
        assert!(actions_len > 0 && actions_len <= actions_cap);
        assert!(proof_len > 0);

        let spend = TestBundleBuffers {
            flags,
            value_balance,
            actions_len,
            cv,
            nf,
            rk,
            cmx,
            epk,
            enc,
            out_ct,
            spend_sigs,
            proof,
            proof_len,
            binding_sig,
            anchor: auth_root,
            sighash: spend_sighash,
        };
        verify_test_bundle(&spend);
    }

    #[test]
    fn builds_effects_only_bundle_without_final_auth() {
        let sk_bytes = [18u8; 32];
        let anchor = Anchor::empty_tree().to_bytes();
        let note = build_output_for_test(sk_bytes, 9000, anchor, [61u8; NITO_SIGNATURE_HASH_SIZE]);
        verify_test_bundle(&note);

        let (note_value, note_recipient_raw, note_cmx, note_rho, note_rseed) =
            decrypt_first_note(sk_bytes, &note);

        let mut auth_path = [0u8; ORCHARD_MERKLE_DEPTH_USIZE * 32];
        let mut auth_root = [0u8; 32];
        let mut err = [0i8; 256];
        let path_code = nito_orchard_compute_auth_path(
            note_cmx.as_ptr(),
            1,
            0,
            auth_path.as_mut_ptr(),
            auth_root.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(path_code, NITO_PRIVATE_OK, "{}", error_message(&err));

        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient_raw = fvk.address_at(8u32, Scope::External).to_raw_address_bytes();
        let change_raw = fvk.address_at(9u32, Scope::Internal).to_raw_address_bytes();
        let spends = [NitoOrchardSpendInput {
            spending_key: sk_bytes.as_ptr(),
            note_recipient_raw: note_recipient_raw.as_ptr(),
            note_value,
            note_rho: note_rho.as_ptr(),
            note_rseed: note_rseed.as_ptr(),
            note_position: 0,
            merkle_path: auth_path.as_ptr(),
        }];
        let outputs = [
            NitoOrchardOutputRequest {
                recipient_raw: recipient_raw.as_ptr(),
                value: 4000,
                ovk_internal: false,
            },
            NitoOrchardOutputRequest {
                recipient_raw: change_raw.as_ptr(),
                value: 4700,
                ovk_internal: true,
            },
        ];

        let actions_cap = 4usize;
        let (
            mut flags,
            mut value_balance,
            mut actions_len,
            mut cv,
            mut nf,
            mut rk,
            mut cmx,
            mut epk,
            mut enc,
            mut out_ct,
            mut spend_sigs,
            mut proof,
            mut proof_len,
            mut binding_sig,
        ) = new_test_build_output(actions_cap);
        let mut out = NitoOrchardBuildOutput {
            flags_out: &mut flags,
            value_balance_out: &mut value_balance,
            actions_len_out: &mut actions_len,
            actions_cap,
            cv_net_out: cv.as_mut_ptr(),
            nullifier_out: nf.as_mut_ptr(),
            rk_out: rk.as_mut_ptr(),
            cmx_out: cmx.as_mut_ptr(),
            ephemeral_key_out: epk.as_mut_ptr(),
            enc_ciphertext_out: enc.as_mut_ptr(),
            out_ciphertext_out: out_ct.as_mut_ptr(),
            spend_auth_sig_out: spend_sigs.as_mut_ptr(),
            proof_out: proof.as_mut_ptr(),
            proof_cap: proof.len(),
            proof_len_out: &mut proof_len,
            binding_sig_out: binding_sig.as_mut_ptr(),
        };

        let code = nito_orchard_build_bundle_effects_only(
            spends.as_ptr(),
            spends.len(),
            outputs.as_ptr(),
            outputs.len(),
            auth_root.as_ptr(),
            &mut out,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(flags, nito_orchard_flags_byte(Flags::ENABLED));
        assert_eq!(value_balance, 300);
        assert!(actions_len > 0 && actions_len <= actions_cap);
        assert_eq!(proof_len, 0);
        assert!(proof.iter().all(|byte| *byte == 0));
        assert!(binding_sig.iter().all(|byte| *byte == 0));
        assert!(spend_sigs.iter().all(|byte| *byte == 0));
        assert!(cmx.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn builds_multi_spend_bundle_that_verifies() {
        let sk_bytes = [14u8; 32];
        let anchor = Anchor::empty_tree().to_bytes();
        let note_a =
            build_output_for_test(sk_bytes, 3000, anchor, [41u8; NITO_SIGNATURE_HASH_SIZE]);
        let note_b =
            build_output_for_test(sk_bytes, 4000, anchor, [42u8; NITO_SIGNATURE_HASH_SIZE]);
        verify_test_bundle(&note_a);
        verify_test_bundle(&note_b);

        let (value_a, recipient_a, cmx_a, rho_a, rseed_a) = decrypt_first_note(sk_bytes, &note_a);
        let (value_b, recipient_b, cmx_b, rho_b, rseed_b) = decrypt_first_note(sk_bytes, &note_b);
        let mut commitments = [0u8; 64];
        commitments[..32].copy_from_slice(&cmx_a);
        commitments[32..].copy_from_slice(&cmx_b);

        let mut path_a = [0u8; ORCHARD_MERKLE_DEPTH_USIZE * 32];
        let mut path_b = [0u8; ORCHARD_MERKLE_DEPTH_USIZE * 32];
        let mut root_a = [0u8; 32];
        let mut root_b = [0u8; 32];
        let mut err = [0i8; 256];
        let path_a_code = nito_orchard_compute_auth_path(
            commitments.as_ptr(),
            2,
            0,
            path_a.as_mut_ptr(),
            root_a.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(path_a_code, NITO_PRIVATE_OK, "{}", error_message(&err));
        let path_b_code = nito_orchard_compute_auth_path(
            commitments.as_ptr(),
            2,
            1,
            path_b.as_mut_ptr(),
            root_b.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(path_b_code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(root_a, root_b);

        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient_raw = fvk.address_at(5u32, Scope::External).to_raw_address_bytes();
        let change_raw = fvk.address_at(6u32, Scope::Internal).to_raw_address_bytes();
        let spends = [
            NitoOrchardSpendInput {
                spending_key: sk_bytes.as_ptr(),
                note_recipient_raw: recipient_a.as_ptr(),
                note_value: value_a,
                note_rho: rho_a.as_ptr(),
                note_rseed: rseed_a.as_ptr(),
                note_position: 0,
                merkle_path: path_a.as_ptr(),
            },
            NitoOrchardSpendInput {
                spending_key: sk_bytes.as_ptr(),
                note_recipient_raw: recipient_b.as_ptr(),
                note_value: value_b,
                note_rho: rho_b.as_ptr(),
                note_rseed: rseed_b.as_ptr(),
                note_position: 1,
                merkle_path: path_b.as_ptr(),
            },
        ];
        let outputs = [
            NitoOrchardOutputRequest {
                recipient_raw: recipient_raw.as_ptr(),
                value: 5000,
                ovk_internal: false,
            },
            NitoOrchardOutputRequest {
                recipient_raw: change_raw.as_ptr(),
                value: 1500,
                ovk_internal: true,
            },
        ];

        let actions_cap = 4usize;
        let (
            mut flags,
            mut value_balance,
            mut actions_len,
            mut cv,
            mut nf,
            mut rk,
            mut cmx,
            mut epk,
            mut enc,
            mut out_ct,
            mut spend_sigs,
            mut proof,
            mut proof_len,
            mut binding_sig,
        ) = new_test_build_output(actions_cap);
        let mut out = NitoOrchardBuildOutput {
            flags_out: &mut flags,
            value_balance_out: &mut value_balance,
            actions_len_out: &mut actions_len,
            actions_cap,
            cv_net_out: cv.as_mut_ptr(),
            nullifier_out: nf.as_mut_ptr(),
            rk_out: rk.as_mut_ptr(),
            cmx_out: cmx.as_mut_ptr(),
            ephemeral_key_out: epk.as_mut_ptr(),
            enc_ciphertext_out: enc.as_mut_ptr(),
            out_ciphertext_out: out_ct.as_mut_ptr(),
            spend_auth_sig_out: spend_sigs.as_mut_ptr(),
            proof_out: proof.as_mut_ptr(),
            proof_cap: proof.len(),
            proof_len_out: &mut proof_len,
            binding_sig_out: binding_sig.as_mut_ptr(),
        };
        let spend_sighash = [43u8; NITO_SIGNATURE_HASH_SIZE];
        let spend_code = nito_orchard_build_bundle_with_sighash_callback(
            spends.as_ptr(),
            spends.len(),
            outputs.as_ptr(),
            outputs.len(),
            root_a.as_ptr(),
            &mut out,
            Some(test_sighash_callback),
            spend_sighash.as_ptr().cast_mut().cast::<c_void>(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(spend_code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(flags, nito_orchard_flags_byte(Flags::ENABLED));
        assert_eq!(value_balance, 500);
        assert!(actions_len > 0 && actions_len <= actions_cap);
        assert!(proof_len > 0);

        let spend = TestBundleBuffers {
            flags,
            value_balance,
            actions_len,
            cv,
            nf,
            rk,
            cmx,
            epk,
            enc,
            out_ct,
            spend_sigs,
            proof,
            proof_len,
            binding_sig,
            anchor: root_a,
            sighash: spend_sighash,
        };
        verify_test_bundle(&spend);
    }

    #[test]
    fn computes_empty_orchard_root() {
        let mut root = [0u8; 32];
        let mut err = [0i8; 128];
        let code = nito_orchard_compute_root(
            ptr::null(),
            0,
            root.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code, NITO_PRIVATE_OK);
        assert_eq!(root, Anchor::empty_tree().to_bytes());
    }

    #[test]
    fn merkle_empty_and_combine_helpers_match_orchard_tree() {
        let mut empty0 = [0u8; 32];
        let mut empty1 = [0u8; 32];
        let mut empty32 = [0u8; 32];
        let mut combined = [0u8; 32];
        let mut computed_empty = [0u8; 32];
        let mut err = [0i8; 128];

        let code_empty0 =
            nito_orchard_empty_root(0, empty0.as_mut_ptr(), err.as_mut_ptr(), err.len());
        assert_eq!(code_empty0, NITO_PRIVATE_OK, "{}", error_message(&err));
        let code_empty1 =
            nito_orchard_empty_root(1, empty1.as_mut_ptr(), err.as_mut_ptr(), err.len());
        assert_eq!(code_empty1, NITO_PRIVATE_OK, "{}", error_message(&err));
        let code_empty32 =
            nito_orchard_empty_root(32, empty32.as_mut_ptr(), err.as_mut_ptr(), err.len());
        assert_eq!(code_empty32, NITO_PRIVATE_OK, "{}", error_message(&err));

        let code_combine = nito_orchard_combine_nodes(
            0,
            empty0.as_ptr(),
            empty0.as_ptr(),
            combined.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code_combine, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(combined, empty1);

        let code_compute = nito_orchard_compute_root(
            ptr::null(),
            0,
            computed_empty.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(code_compute, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(empty32, computed_empty);
    }

    #[test]
    fn frontier_append_matches_full_root() {
        let sk_bytes = [18u8; 32];
        let anchor = Anchor::empty_tree().to_bytes();
        let note_a =
            build_output_for_test(sk_bytes, 7_000, anchor, [61u8; NITO_SIGNATURE_HASH_SIZE]);
        let note_b =
            build_output_for_test(sk_bytes, 8_000, anchor, [62u8; NITO_SIGNATURE_HASH_SIZE]);
        let (_, _, cmx_a, _, _) = decrypt_first_note(sk_bytes, &note_a);
        let (_, _, cmx_b, _, _) = decrypt_first_note(sk_bytes, &note_b);

        let mut commitments = [0u8; 64];
        commitments[..32].copy_from_slice(&cmx_a);
        commitments[32..].copy_from_slice(&cmx_b);

        let mut full_root = [0u8; 32];
        let mut err = [0i8; 256];
        let full_code = nito_orchard_compute_root(
            commitments.as_ptr(),
            2,
            full_root.as_mut_ptr(),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(full_code, NITO_PRIVATE_OK, "{}", error_message(&err));

        let mut frontier_root_a = [0u8; 32];
        let mut frontier_a = [0u8; ORCHARD_FRONTIER_MAX_SIZE];
        let mut frontier_a_len = 0usize;
        let append_a_code = nito_orchard_frontier_append(
            ptr::null(),
            0,
            commitments.as_ptr(),
            1,
            frontier_root_a.as_mut_ptr(),
            frontier_a.as_mut_ptr(),
            frontier_a.len(),
            &mut frontier_a_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(append_a_code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert!(frontier_a_len > 0);

        let mut frontier_root_b = [0u8; 32];
        let mut frontier_b = [0u8; ORCHARD_FRONTIER_MAX_SIZE];
        let mut frontier_b_len = 0usize;
        let append_b_code = nito_orchard_frontier_append(
            frontier_a.as_ptr(),
            frontier_a_len,
            commitments[32..].as_ptr(),
            1,
            frontier_root_b.as_mut_ptr(),
            frontier_b.as_mut_ptr(),
            frontier_b.len(),
            &mut frontier_b_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(append_b_code, NITO_PRIVATE_OK, "{}", error_message(&err));
        assert_eq!(frontier_root_b, full_root);
        assert!(frontier_b_len >= frontier_a_len);
    }

    #[test]
    fn rejects_null_root_output() {
        let mut err = [0i8; 128];
        let code =
            nito_orchard_compute_root(ptr::null(), 0, ptr::null_mut(), err.as_mut_ptr(), err.len());
        assert_eq!(code, NITO_PRIVATE_ERR_NULL_PTR);
        assert!(error_message(&err).contains("root_out: null pointer"));
    }
}
