// Copyright (c) 2020-2025 The Electric Coin Company
// Copyright (c) 2026 Zcash Open Development Lab
// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license; see ../test_vectors/LICENSE-MIT.

use orchard::circuit::Instance;

use super::*;

fn read_fixture(bytes: &[u8], post_nu6_3: bool) -> (Instance, Proof) {
    let prefix_len = if post_nu6_3 { 163 } else { 162 };
    assert_eq!(bytes.len(), prefix_len + 4992);
    let field = |offset: usize| -> [u8; 32] { bytes[offset..offset + 32].try_into().unwrap() };
    assert!(bytes[160] <= 1 && bytes[161] <= 1);
    if post_nu6_3 {
        // This upstream fixture is unrestricted, so its statement uses the
        // same public inputs as Orchard V2 despite having a different key.
        assert_eq!(bytes[162], 0);
    }
    let flags = Flags::from_byte(bytes[160] | (bytes[161] << 1), BundleVersion::orchard_v2())
        .expect("fixture flags must be valid");
    let instance = Instance::from_parts(
        Anchor::from_bytes(field(0)).unwrap(),
        ValueCommitment::from_bytes(&field(32)).unwrap(),
        Nullifier::from_bytes(&field(64)).unwrap(),
        redpallas::VerificationKey::<SpendAuth>::try_from(field(96)).unwrap(),
        ExtractedNoteCommitment::from_bytes(&field(128)).unwrap(),
        flags,
    )
    .expect("fixture randomized key must not be identity");
    (instance, Proof::new(bytes[prefix_len..].to_vec()))
}

#[test]
fn verifies_only_the_pinned_upstream_orchard_circuit() {
    assert_eq!(NITO_ORCHARD_BUNDLE_VERSION, BundleVersion::orchard_v2());
    let vk = VERIFYING_KEY.get_or_init(|| VerifyingKey::build(NITO_ORCHARD_CIRCUIT_VERSION));
    assert_eq!(vk.circuit_version(), OrchardCircuitVersion::FixedPostNu6_2);

    let fixtures: [(&str, &[u8], bool, bool); 3] = [
        (
            "fixed post-NU6.2",
            include_bytes!("../test_vectors/circuit_proof_test_case_fixed.bin"),
            false,
            true,
        ),
        (
            "insecure pre-NU6.2",
            include_bytes!("../test_vectors/circuit_proof_test_case_insecure.bin"),
            false,
            false,
        ),
        (
            "post-NU6.3",
            include_bytes!("../test_vectors/circuit_proof_test_case_post_nu6_3.bin"),
            true,
            false,
        ),
    ];
    for (name, bytes, post_nu6_3, expected_valid) in fixtures {
        let (instance, proof) = read_fixture(bytes, post_nu6_3);
        assert_eq!(
            proof.verify(vk, &[instance]).is_ok(),
            expected_valid,
            "{name}"
        );
    }

    let mut damaged = include_bytes!("../test_vectors/circuit_proof_test_case_fixed.bin").to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    let (instance, proof) = read_fixture(&damaged, false);
    assert!(proof.verify(vk, &[instance]).is_err());
}
