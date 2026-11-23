# Nito Core

<p align="center">
  <img src="doc/nito/assets/nito-v4-header.svg" alt="Nito Core v4 - Nito x Bech32x (Orchard)" width="100%">
</p>

Nito Core V4 is the reference full node and wallet for Nito.network. It
preserves the existing transparent chain, wallet and SHA-256 mining interfaces
and adds opt-in Bech32x private transactions backed by Orchard cryptography.

[Official Nito logos](share/branding/README.md) are available for pools,
exchanges and explorers.

Download official binaries from the
[Nito Core releases](https://github.com/NitoNetwork/Nito-core/releases).
GitHub provides source archives generated from the signed release tag. The
default branch contains the maintained V4 source line.


## Major V4 Additions

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

Obtain a Nito Core V4 release from the
[official release page](https://github.com/NitoNetwork/Nito-core/releases) and
verify the selected file against the accompanying `SHA256SUMS`.

Official Nito Core release tags are annotated and cryptographically signed and
must display GitHub's **Verified** status. The tag signature authenticates the
tag and its source commit; it does not replace checksum verification of the
downloaded packages.

Releases published under the current signing policy also include
`SHA256SUMS.minisig`. Before trusting the checksum file, confirm that the
repository key and the independently hosted
[official Nito.network public key](https://nito.network/security/nito-core-release.pub)
both have key ID `D060C20B3417848D`, then verify the detached signature:

```bash
minisign -Vm SHA256SUMS \
  -x SHA256SUMS.minisig \
  -P RWSNhBc0C8Jg0H6yw7+V3qiCv/k/7NZox9P9oIGV/veXmCUrI6Bmn9oJ
```

The repository key is
[`contrib/release/nito-core-release.pub`](contrib/release/nito-core-release.pub).
Successful verification must report the trusted comment
`Nito Core vX.Y.Z SHA256SUMS` for the release being checked.
A key downloaded only from the same GitHub Release is not an independent
authentication path. Some earlier V4 releases predate this detached
checksum-signing policy and therefore do not include `SHA256SUMS.minisig`.

After authenticating the checksum index when its detached signature is
available, verify the selected package.

Linux:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

macOS:

```bash
shasum -a 256 nito-X.Y.Z-arm64-apple-darwin.dmg
```

Windows PowerShell:

```powershell
Get-FileHash .\nito-X.Y.Z-win64.zip -Algorithm SHA256
```

Compare the complete reported hash with the matching line in `SHA256SUMS`.

Official tagged release files built after provenance support was introduced
carry GitHub build attestations. With the
[GitHub CLI](https://cli.github.com/), constrain verification to Nito Core's
release workflow and the release tag:

```bash
gh attestation verify nito-X.Y.Z-x86_64-linux-gnu.tar.gz \
  --repo NitoNetwork/Nito-core \
  --signer-workflow NitoNetwork/Nito-core/.github/workflows/build-release.yml \
  --source-ref refs/tags/vX.Y.Z \
  --source-digest FULL_SIGNED_TAG_TARGET_SHA
```

Replace `X.Y.Z` with the release version and replace
`FULL_SIGNED_TAG_TARGET_SHA` with the complete commit SHA obtained by
independently verifying and peeling the signed annotated tag. Earlier releases
have no attestations, so this check fails for them. An attestation proves where
matching bytes were built; it does not by itself prove reproducibility or
maintainer approval.

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
type with `nito1x...` mainnet addresses. Create a native v4 wallet with the
guided command:

```bash
nito-cli -named -interactive createwallet wallet_name=main descriptors=true load_on_startup=true
```

The wizard asks independently whether to encrypt the wallet file and whether
to protect the recovery phrase with a BIP39 passphrase, covering all four
combinations. It requests and confirms only the selected secrets, without
terminal echo, shell history or process arguments. Wallet encryption protects
`wallet.dat` at rest. The separate BIP39 passphrase changes the keys derived
from the recovery phrase, is never stored and cannot be recovered or reset.
`load_on_startup=true` adds the wallet to the persistent startup list; use
`false` to remove it or omit the option to leave that list unchanged. Protected
non-interactive input for automation is documented in the
[RPC reference](doc/nito/rpc-reference.md#optional-bip39-passphrase).
Nito Qt keeps startup wallets closed by default. Operators who explicitly set
`qtkeepwalletsclosed=0` can restore automatic startup attachment; encrypted
wallets still require an explicit passphrase before Qt displays them. See
[wallet startup and display](doc/managing-wallets.md#wallet-startup-and-qt-display).

After creation, select the required receive type explicitly:

```bash
nito-cli -rpcwallet=main getnewaddress "" bech32
nito-cli -rpcwallet=main getnewaddress "" bech32x
```

Normal sends use transparent funds. Use `sendprivate` or the Qt private-balance
control when private notes should fund a transaction.

Supported v3 Berkeley DB and SQLite wallet files open directly and keep their
transparent keys, labels, address sequence and existing encryption state. No
conversion is required for transparent use. Descriptor migration is optional.
If it is wanted, run it before adding Orchard:

```bash
nito-cli -named -interactive -rpcwallet=legacy migratewallet
```

The migration wizard confirms the operation, asks whether the wallet is
encrypted and requests the current password without echo only when needed. It
creates the required legacy backup before mutation.

Adding Orchard is a separate, explicit, one-time operation. If the v3 wallet is
encrypted, first unlock it without placing its password in the command line:

```bash
nito-cli -named -interactive -rpcwallet=legacy walletpassphrase timeout=300
```

Then use the same guided Orchard command for a newly generated phrase, an
optional BIP39 passphrase or restoration of an existing Orchard phrase:

```bash
nito-cli -named -interactive -rpcwallet=legacy upgradeorchardwallet
```

The wizard confirms every supplied phrase or new secret and asks for final
approval before creating the backup and changing the wallet. Relock an
encrypted wallet afterward:

```bash
nito-cli -rpcwallet=legacy walletlock
```

Keep both the reported pre-upgrade backup and the returned `orchard_only`
phrase. That phrase covers the added Orchard authority; it does not replace the
original v3 wallet backup. Retain that `wallet.dat` backup for life for the
original transparent keys. The upgrade does not add, remove or change wallet
file encryption. See the [quick-start guide](doc/nito/quick-start.md) for the
complete decision flow.

An encrypted wallet opened in Qt asks for its passphrase before showing wallet
data. Qt then locks the spending key while keeping an authenticated viewing
session. Every Bech32x address creation or send that needs private keys asks
for the passphrase again. Cancelling the display prompt leaves the wallet
hidden but selectable, so authorization can be retried without restarting Qt.

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

Interactive creation confirms each selected secret without terminal echo and
keeps it out of shell history and process arguments. Use the documented
`-stdin` form only for protected automation. Successful creation returns the
wallet name as JSON; local validation or RPC errors return a nonzero exit code.

Human recovery uses the same guided policy. Create a blank descriptor wallet,
then initialize it from the saved phrase:

```bash
nito-cli -named -interactive createwallet wallet_name=restore blank=true descriptors=true
nito-cli -named -interactive -rpcwallet=restore walletpassphrase timeout=600
nito-cli -named -interactive -rpcwallet=restore sethdseed newkeypool=true
nito-cli -rpcwallet=restore walletlock
```

The phrase and optional BIP39 passphrase are entered twice without echo, and
the wallet is not initialized until the final confirmation. During blank-wallet
creation, the first wizard still offers wallet-file encryption but correctly
omits the BIP39 question because no phrase exists until `sethdseed`. Run the
`walletpassphrase` and `walletlock` lines only when wallet-file encryption was
selected; an encrypted blank wallet must be unlocked before `sethdseed`.

The same audited `-named -interactive` safety layer covers 49 sensitive flows:
wallet recovery and encryption, private-key and private-descriptor input,
wallet and standalone signing, descriptor-bearing scan/funding calls,
recovery-authority export, backup/restore, and legacy mutations that require a
fresh backup, plus five high-impact local chainstate changes. It keeps
credentials and private authority out of process
arguments and requires explicit approval before disclosure, signing or
high-impact mutation. Ordinary RPC forms remain unchanged for automation. See
[guided human input](doc/nito/rpc-reference.md#guided-human-input) for the
complete supported-command table and the exact boundary. `-stdin` remains
available only as the advanced automation interface.

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
terms. Platform packages include the applicable consolidated notices. Matching
source and dependency-source instructions are documented in
[release sources and third-party notices](doc/release-sources.md).
