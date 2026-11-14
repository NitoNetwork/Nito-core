# Legacy Binary Verification Helper

This directory contains inherited GPG-based verification tooling. Its `pub`
mode, default download hosts and historical version examples are not the Nito
Core V4 release-verification procedure. Do not use that mode to obtain or
validate Nito binaries.

For Nito releases, download the artifacts, `SHA256SUMS` and
`release-manifest.txt` from the
[official release page](https://github.com/NitoNetwork/Nito-core/releases).
Follow the [checksum verification instructions](../../README.md#download-and-verify)
and the [release signing policy](../../doc/release-process.md). The manifest
identifies the source commit and explicitly records whether signing was used.
V4 release binaries have not been published yet.

Bitcoin Core's [Guix signatures](https://github.com/bitcoin-core/guix.sigs)
and builder keys belong to Bitcoin Core. They do not authenticate Nito releases.
The helper must be adapted to an explicitly defined download and trust policy
before it can be used for another project's signed releases.
