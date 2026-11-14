# Nito Core 4.0.0 Release Notes

Nito Core 4.0.0 is the first stable V4 release. It adds opt-in Bech32x private
transactions backed by Orchard while preserving Nito's transparent chain,
wallet compatibility and SHA-256 mining interfaces.

Download the release from
[GitHub](https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0) and
verify every file against the included `SHA256SUMS` before installation.

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
| Linux x86_64 | `nito-4.0.0-x86_64-linux-gnu.tar.gz` |
| Linux ARM64 | `nito-4.0.0-aarch64-linux-gnu.tar.gz` |
| Windows x64 | `nito-4.0.0-win64.zip`, `nito-4.0.0-win64-setup.exe` |
| macOS ARM64 | `nito-4.0.0-arm64-apple-darwin.tar.gz`, `nito-4.0.0-arm64-apple-darwin.dmg` |
| Corresponding source | `nito-4.0.0-sources.tar.gz` |

Portable archives contain a single top-level `bin/` directory with the
executables, `LICENSE.txt` and `THIRD_PARTY_LICENSES.txt`. The matching source
archive contains the pinned dependency sources and locked Rust crates required
for redistribution. See [release source information](release-sources.md).

## Validation

The published binaries were built from commit
`1d81bbd5f79d6b857c80420d5c81915ea326adff` by the
[public release workflow](https://github.com/NitoNetwork/Nito-core/actions/runs/43616391797).
The successful release gate covered Linux x86_64, Linux ARM64, Windows x64 and
macOS ARM64, together with native tests, Qt tests, 32 locked Orchard tests,
legacy-wallet backup and restore, the activation-reorganization regression,
package inspection and aggregate SHA-256 verification.

The release manifest records `Signing: UNSIGNED`. `SHA256SUMS` provides file
integrity verification and must be obtained from the same official release.
