# Nito Core

<p align="center">
  <img src="doc/nito/assets/nito-v4-header.svg" alt="Nito Core v4 - Nito x Bech32x (Orchard)" width="100%">
</p>

Nito Core 4.0.0 is the current full node and wallet for Nito.network. It
preserves the existing transparent chain, wallet and SHA-256 mining interfaces
and adds opt-in Bech32x private transactions backed by Orchard cryptography.

Download the official binaries and matching source archive from the
[Nito Core 4.0.0 release](https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0).
The `v4.0` branch contains the maintained V4 source line.

## Major Additions In 4.0.0

- **Bech32x and Orchard:** opt-in private receive and send flows, with explicit
  private funding and a dedicated Orchard index. See the
  [Bech32x wallet guide](doc/nito/bech32x-private-wallet.md).
- **Compatible wallet upgrades:** supported V3 wallet files continue to open
  directly; Orchard can be added without replacing existing transparent keys.
  See [wallet backup and restore](doc/nito/wallet-backup-restore.md).
- **Complete deterministic recovery:** native V4 phrases cover transparent and
  Orchard authority, with an optional BIP39 passphrase and explicit index
  requirements for historical recovery.
- **Operational continuity:** transparent consensus, SHA-256 mining, block
  headers, rewards and normal pool interfaces remain unchanged. See
  [activation](doc/nito/consensus-activation.md) and
  [mining compatibility](doc/nito/mining-pool-compatibility.md).
- **Multi-platform delivery:** release packages are provided for Linux x86_64,
  Linux ARM64, Windows x64 and macOS ARM64, with aggregate SHA-256 checksums.

## Upgrade Requirement

This code activates Orchard on mainnet at block `1,165,432`. Publishing or
selecting a Git branch does not change that consensus rule. The existing block
reward and subsidy schedule are unchanged.

Before activation, v3 peers and transparent traffic remain compatible. Once
the activation block is connected, peers must advertise protocol version
`70017` or later and the `NITO_PRIVATE` service capability. Nodes, pools,
explorers and indexers must upgrade their backing daemon before that height.
Mining keeps the existing SHA-256 hardware, block-header and transparent
coinbase format.

## Download And Verify

Obtain Nito Core 4.0.0 from the
[official release page](https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0)
and verify the selected file against the accompanying `SHA256SUMS`.

Linux:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

macOS:

```bash
shasum -a 256 nito-4.0.0-arm64-apple-darwin.dmg
```

Windows PowerShell:

```powershell
Get-FileHash .\nito-4.0.0-win64.zip -Algorithm SHA256
```

Compare the complete reported hash with the matching line in `SHA256SUMS`.
Portable archives contain a single top-level `bin/` directory. Executables,
`LICENSE.txt` and the consolidated `THIRD_PARTY_LICENSES.txt` are kept directly
inside it.

## Start A Node

```bash
nitod -daemon
nito-cli getblockchaininfo
nito-cli getorchardpools
nito-cli getindexinfo
```

Wait for the chain and required indexes to synchronize before using the
wallet. The [quick-start guide](doc/nito/quick-start.md) covers Windows,
Linux, macOS and the available networks.

## Wallets And Bech32x

Bech32 remains the default receive type. Bech32x is an explicit private receive
type with `nito1x...` mainnet addresses:

```bash
nito-cli -named createwallet wallet_name=main descriptors=true
nito-cli -rpcwallet=main getnewaddress "" bech32
nito-cli -rpcwallet=main getnewaddress "" bech32x
```

Normal sends use transparent funds. Use `sendprivate` or the Qt private-balance
control when private notes should fund a transaction.

Supported v3 Berkeley DB and SQLite wallet files open directly and keep their
transparent keys, labels and address sequence. Adding Orchard to a v3 wallet is
an explicit operation:

```bash
nito-cli -rpcwallet=legacy upgradeorchardwallet
```

Keep both the reported pre-upgrade backup and the returned `orchard_only`
phrase. That phrase covers the added Orchard authority; it does not replace the
original v3 wallet backup. Retain that `wallet.dat` backup for life for the
original transparent keys.

An encrypted wallet opened in Qt asks for its passphrase before showing wallet
data. Qt then locks the spending key while keeping an authenticated viewing
session. Every Bech32x address creation or send that needs private keys asks
for the passphrase again.

## Backup And Recovery

A wallet-file backup preserves keys and wallet metadata. A native v4
`full_wallet` phrase restores deterministic transparent and Orchard authority,
but it does not restore labels, comments or imported keys. An optional BIP39
passphrase must also be backed up and supplied for phrase recovery if used. It
is a separate secret rather than a 13th or 25th word, is distinct from the
wallet encryption password, is never stored, and cannot be
recovered or reset. A different passphrase derives another valid wallet.
`backupwallet` and `restorewallet` preserve the derived seed record, never this
passphrase; `dumpmnemonic` does not return it. See the
[passphrase rules](doc/nito/wallet-backup-restore.md#optional-bip39-passphrase)
before creating or restoring a wallet.

Phrase recovery reconstructs chain-derived funds and history before reporting
success. On an existing chain it requires unpruned blocks,
`transparenthistoryindex=1`, and `orchardindex=1` after private activation when
the wallet has Orchard authority.

A synchronized pruned node can continue using wallet state it already knows.
With the default `orchardindex=1` built before block deletion, it can also keep
using Orchard funds. Complete phrase recovery and missing transparent history
still require an unpruned indexed node. Nito Core never starts a full
redownload automatically in response to a recovery request.

Read [wallet backup and restore](doc/nito/wallet-backup-restore.md) before
upgrading or restoring a wallet.

## Network Ports

| Network | P2P | RPC | Onion target |
| --- | ---: | ---: | ---: |
| Mainnet | `8820` | `8825` | `8821` |
| Testnet | `8840` | `8845` | `8841` |
| Signet | `8860` | `8865` | `8861` |
| Regtest | `8880` | `8885` | `8881` |

Testnet coins have no value. Orchard is active from testnet genesis. See the
[community testnet guide](doc/nito/community-testnet.md).

## Documentation

- [Nito Core v4 user and operator documentation](doc/nito/README.md)
- [Build Nito Core from source](doc/nito/source-builds.md)
- [RPC additions in v4](doc/nito/rpc-reference.md)
- [Activation and peer rules](doc/nito/consensus-activation.md)
- [Mining and pool compatibility](doc/nito/mining-pool-compatibility.md)
- [Security and privacy model](doc/nito/security-privacy-model.md)
- [Complete technical documentation index](doc/README.md)

## License

Nito Core is released under the MIT license. See [LICENSE](LICENSE) and
[COPYING](COPYING). Third-party components retain their own notices and license
terms. Release downloads include the matching source archive and notices; see
[release sources and third-party notices](doc/release-sources.md).
