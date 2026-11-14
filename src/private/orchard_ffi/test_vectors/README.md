# Orchard circuit regression vectors

These public proof fixtures are copied unchanged from the `orchard 0.15.0`
crate published by Zcash Open Development Lab, upstream commit
`8995ee7e26f8b654a5457d05c95ee5b3132b3edd`. Their original location is
[`src/circuit_data`](https://github.com/zcash/orchard/tree/8995ee7e26f8b654a5457d05c95ee5b3132b3edd/src/circuit_data).
The included [MIT license](LICENSE-MIT) applies to these fixtures and the
adapted fixture parser.

The crate archive SHA-256, also pinned in `../Cargo.lock`, is
`cca2ede6a4a77bd729eed3be9303d98a08b217edc85190dcf4dbe004086d5a65`.

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| `circuit_proof_test_case_fixed.bin` | 5154 | `628b03e73f5533e3a21103d8c041414191f56b2b3a3affe468adfe92e99ae468` |
| `circuit_proof_test_case_insecure.bin` | 5154 | `40347437e6bf604f51af059ee7d560ee893507c2ba35b61e3dd0db5ec1358662` |
| `circuit_proof_test_case_post_nu6_3.bin` | 5155 | `3be9c159e5f238566a814b5446716b31bade2c1fd82c45ee8582ddf500df165a` |

`fixed_circuit_vectors.rs` verifies these frozen proofs against the verifying
key selected by Nito. The fixed post-NU6.2 fixture must pass; both the insecure
pre-NU6.2 and post-NU6.3 fixtures must fail. A damaged fixed proof must also fail.
No proof is generated or fixture replaced during these tests. This guards
against an accidental coordinated change to both the prover and verifier that
could escape tests which generate and verify a fresh proof together.

Each fixture starts with five 32-byte public fields: anchor, value commitment,
nullifier, randomized spend key and note commitment. Two boolean bytes encode
the spend/output flags, followed by the 4,992-byte proof. The post-NU6.3 fixture
adds one zero byte for its unrestricted cross-address setting. These files
contain public circuit statements and proofs, without spending authority.

The upstream fixed circuit description SHA-256 is
`e51a737b95b741a323c65b94745429f95bbbc13643198a0a7e985573bd7bcf6e`. This records the provenance
of the upstream description; the regression checks Nito's selected key through
proof verification because Orchard's public API does not export its pinned key
description. These tests complement the FFI authorization, encoding and
transaction-consensus tests; they do not replace them.
