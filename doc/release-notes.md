# Nito Core 4.0.1 Release Notes

Nito Core 4.0.1 is a maintenance update to the stable V4 release line. It keeps
the opt-in Bech32x and Orchard capabilities introduced in 4.0.0 while fixing
macOS packaging and secure Qt wallet startup.

Download the release from the
[official release page](https://github.com/NitoNetwork/Nito-core/releases) and
verify every file against the included `SHA256SUMS` before installation.

## Changes Since 4.0.0

- The macOS release workflow now re-seals `Nito-Qt.app` after adding the license
  notices and verifies the signature both before packaging and from the mounted
  final DMG. This prevents Gatekeeper from treating the distributed app as a
  damaged bundle. The signature remains ad hoc rather than Developer ID signed
  or notarized, so macOS can still require the normal manual approval.
- The advanced `qtkeepwalletsclosed=0` option again attaches configured startup
  wallets automatically. The secure default remains unchanged, and encrypted
  wallets stay hidden until their display is authorized with the wallet
  passphrase.

## Major Changes

- **Bech32x private transactions:** wallets can explicitly receive and spend
  through `nito1x...` addresses after activation. Transparent receive and send
  behavior remains the default. See the
  [Bech32x wallet guide](nito/bech32x-private-wallet.md).
- **V3 wallet compatibility:** supported Berkeley DB and SQLite V3 wallets open
  directly. `upgradeorchardwallet` adds Orchard authority without replacing
  existing transparent keys. See
  [wallet backup and restore](nito/wallet-backup-restore.md).
- **Recovery and pruning:** native V4 phrases cover deterministic transparent
  and Orchard authority and may use an optional BIP39 passphrase. Complete
  historical recovery has explicit block and index requirements; synchronized
  pruned nodes can retain Orchard operation with `orchardindex`. See the
  [recovery guide](nito/wallet-backup-restore.md) and
  [security model](nito/security-privacy-model.md).
- **Activation-aware networking:** mainnet Orchard activation is fixed at block
  `1,165,432`. After activation, peers must support protocol `70017` or later
  and advertise `NITO_PRIVATE`. See
  [consensus activation](nito/consensus-activation.md).
- **Mining compatibility:** SHA-256 proof of work, block headers, transparent
  coinbase construction, rewards and normal pool interfaces are unchanged.
  Pool operators must upgrade the backing daemon before activation. See
  [mining and pool compatibility](nito/mining-pool-compatibility.md).
- **Desktop and release delivery:** Qt 6 wallet support, updated Nito branding,
  improved encrypted-wallet handling and packages for Linux x86_64, Linux
  ARM64, Windows x64 and macOS ARM64.

## Upgrade Notes

Back up every wallet and stop the previous node cleanly before replacing its
binaries. V4 can reuse the existing chain and supported wallet files. Allow
newly enabled indexes to finish synchronizing before relying on private wallet
features or historical recovery.

Keep the pre-upgrade V3 wallet backup even after adding Orchard. An
`orchard_only` phrase restores only the added Orchard authority and does not
replace the original transparent wallet backup. Opening V4-updated wallet or
chain data in V3 is not a supported rollback procedure.

Nodes, pools, explorers and indexers must upgrade their backing daemon before
mainnet block `1,165,432`. V4 does not change the subsidy schedule or require
different mining hardware.

Start with the [quick-start guide](nito/quick-start.md). Detailed RPC additions
are documented in the [V4 RPC reference](nito/rpc-reference.md).

## Downloads

| Platform | Files |
| --- | --- |
| Linux x86_64 | `nito-4.0.1-x86_64-linux-gnu.tar.gz` |
| Linux ARM64 | `nito-4.0.1-aarch64-linux-gnu.tar.gz` |
| Windows x64 | `nito-4.0.1-win64.zip`, `nito-4.0.1-win64-setup.exe` |
| macOS ARM64 | `nito-4.0.1-arm64-apple-darwin.tar.gz`, `nito-4.0.1-arm64-apple-darwin.dmg` |

Portable archives contain a single top-level `bin/` directory with the
executables, `LICENSE.txt` and `THIRD_PARTY_LICENSES.txt`. The matching source
tag and GitHub-generated source archives are available from the release page.
See [release source information](release-sources.md) for rebuilding and
redistribution requirements.

## Validation

The 4.0.1 packages must be built from the exact reviewed release commit by the
public release workflow. Before publication, the release gate must pass for
Linux x86_64, Linux ARM64, Windows x64 and macOS ARM64, including native and Qt
tests, the locked Orchard tests, legacy-wallet backup and restore, package
inspection and aggregate SHA-256 verification.

The annotated `v4.0.1` tag must be cryptographically signed and report
**Verified** on GitHub. The attached `SHA256SUMS` covers the platform packages
and provides file-integrity verification. A signed source tag authenticates the
tag and source commit; it does not replace checking each downloaded package
against `SHA256SUMS`.
