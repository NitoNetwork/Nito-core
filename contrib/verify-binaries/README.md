# Legacy Binary Verification Helper

This directory contains inherited GPG-based verification tooling. Its `pub`
mode, default download hosts and historical version examples are not the Nito
Core V4 release-verification procedure. Do not use that mode to obtain or
validate Nito binaries.

For Nito Core V4 releases, download the selected package, `SHA256SUMS` and,
when supplied, `SHA256SUMS.minisig` from the
[official release page](https://github.com/NitoNetwork/Nito-core/releases).
Follow the [checksum, Minisign and provenance procedure](../../README.md#download-and-verify)
and the [release signing policy](../../doc/release-process.md). The detailed
release manifest remains workflow evidence and is not a public Release asset.

Bitcoin Core's [Guix signatures](https://github.com/bitcoin-core/guix.sigs)
and builder keys belong to Bitcoin Core. They do not authenticate Nito releases.
The helper must be adapted to an explicitly defined download and trust policy
before it can be used for another project's signed releases.
