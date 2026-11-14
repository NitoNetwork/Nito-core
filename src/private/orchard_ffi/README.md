# Nito Orchard FFI

This crate is the native proof engine for the Nito.network Bech32x transaction
layer. It embeds Orchard locally and exposes the C ABI used by Nito Core.

It is not a mixer, server, pool or trusted coordinator.

## Consensus Baseline

The lock file pins `orchard 0.15.0` and `halo2_gadgets 0.5.0`. Nito explicitly
selects:

- `BundleVersion::orchard_v2()`;
- `OrchardCircuitVersion::FixedPostNu6_2`;
- canonical V2 flags and exact proof length.

The crate may contain upstream code for later Orchard versions, but no later
bundle or circuit can become active through a dependency default. It requires
an explicit Nito consensus change and new fixed vectors.

## Responsibilities

The bridge:

- derives Orchard addresses and full viewing keys;
- encrypts and batch-decrypts note candidates;
- constructs and verifies V2 bundles;
- verifies RedPallas spend authorization and binding signatures;
- validates canonical encodings and exact field sizes;
- appends commitments and exposes deterministic frontier/root operations;
- computes note nullifiers and spend authorization paths.

C++ consensus remains responsible for transaction parsing, activation,
nullifier uniqueness, anchor selection, value-pool accounting and atomic
chainstate updates.

## Build Integration

- Autotools builds and links the Rust static library through
  `NITO_ORCHARD_FFI_LINK`.
- MinGW uses Cargo target `x86_64-pc-windows-gnu`.
- Linux aarch64 uses `aarch64-unknown-linux-gnu`.
- MSVC builds `nito_orchard_ffi.lib` and links the native libraries reported by
  `cargo rustc -- --print native-static-libs`.

## Validation

```bash
cargo fmt --manifest-path src/private/orchard_ffi/Cargo.toml --check
cargo test --manifest-path src/private/orchard_ffi/Cargo.toml --locked --release
```

The locked release suite contains 32 tests covering bundle construction,
verification, malformed inputs, viewing-key decryption, distant diversifier
indices, note commitments, Merkle frontiers and private spends.
Committed [fixed vectors](test_vectors/README.md) check the selected circuit
against a proof made independently of the Nito FFI builder and reject the
incompatible circuit version.
