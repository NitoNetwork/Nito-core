# Nito Core 4.1.0

Nito Core 4.1.0 brings light and dark desktop themes, easier testnet
discovery, and independent verification of official downloads.

## Changes since 4.0.1

- **Desktop wallet.** Qt follows the system's light or dark appearance by
  default. Start with `-guitheme=light` or `-guitheme=dark` to choose a fixed
  theme. Mainnet keeps the official Nito logo and blue accent. Testnet,
  signet and regtest have distinct colors, icons and badges.
- **Interface fixes.** The console tabs align with their panel, the sync
  overlay follows the selected theme, and the palette improves contrast for
  text and disabled controls. The wallet overview links to the repository and
  releases. Thanks to [Olly](https://github.com/saltedlolly) for the
  [Qt contribution](https://github.com/NitoNetwork/Nito-core/pull/14).
- **Peer discovery.** Mainnet adds the community DNS seed `seed.nito.tools`.
  Testnet uses `t1.testnet.nito.network`, `t2.testnet.nito.network` and
  `testnetseed.nito.tools`, with fixed peers available for bootstrap. The
  network keeps its existing testnet genesis and P2P port `8840`. Thanks to
  Olly for the [community seeds](https://github.com/NitoNetwork/Nito-core/pull/10).
- **Official logos.** The
  [transparent PNG kit](https://github.com/NitoNetwork/Nito-core/tree/v4.1.0/share/branding)
  provides eight sizes for pools, exchanges and explorers. The repository
  README links to it.
- **Release verification.** Official packages come from a build of the
  signed annotated tag. GitHub/Sigstore attestations bind each package and
  the checksum index to the release workflow and source commit. A separate
  offline Minisign signature authenticates `SHA256SUMS`. Thanks to Olly for
  the [provenance proposal](https://github.com/NitoNetwork/Nito-core/pull/12)
  and [release signing recommendations](https://github.com/NitoNetwork/Nito-core/issues/13).
- **Contributor tooling.** The check for documented command-line options
  now works on Windows and Unix-like development hosts.

## Upgrade notes

Back up your wallet files and shut down the previous node before replacing
the binaries. Nito Core can reuse the existing data directory and supported
wallet files. The existing mainnet Orchard activation remains at block
`1,165,432`. If you are still running V3, upgrade the backing daemon before
that height. Transparent transaction fees, mining rules and pool interfaces
retain their existing behavior.

See the [quick-start guide](https://github.com/NitoNetwork/Nito-core/blob/v4.1.0/doc/nito/quick-start.md)
and [mainnet activation guide](https://github.com/NitoNetwork/Nito-core/blob/v4.1.0/doc/nito/consensus-activation.md).

## Downloads and verification

Packages are available for Linux x86_64, Linux ARM64, Windows x64
(ZIP and installer), and macOS ARM64 (archive and DMG).

Download your package, `SHA256SUMS` and `SHA256SUMS.minisig` from this release.
Verify the checksum index with the
[official Nito Core Minisign public key](https://nito.network/security/nito-core-release.pub)
(key ID `D060C20B3417848D`) before comparing the package's SHA-256 hash.
The expected trusted comment is `Nito Core v4.1.0 SHA256SUMS`. The
[verification guide](https://github.com/NitoNetwork/Nito-core/blob/v4.1.0/README.md#download-and-verify)
also shows how to verify the GitHub attestation.

[Full change list](https://github.com/NitoNetwork/Nito-core/compare/v4.0.1...v4.1.0)
