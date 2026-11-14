# Quick Start

This guide starts Nito Core 4.0.0 with transparent and Bech32x wallet support.
Official binaries are available from the
[Nito Core 4.0.0 release](https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0).
Operators who compile Nito Core should follow the
[source-build guide](source-builds.md).

## Install And Verify

Download the artifact for your platform and `SHA256SUMS` from the
[official release page](https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0),
then verify the download before installation:

```bash
sha256sum -c SHA256SUMS
```

Windows users can run the installer or extract the zip archive. Linux
and macOS users can extract the matching archive and run the binaries from
`bin/`. Portable archives contain only that directory at their root; required
license notices are consolidated in `LICENSE.txt` and
`THIRD_PARTY_LICENSES.txt` inside it.

## Run A Node

```bash
nitod -daemon
nito-cli getblockchaininfo
nito-cli getorchardpools
```

Wait until headers and blocks are synchronized. `getorchardpools` reports the
configured private activation height and whether it is active. Mainnet enables
Orchard at block `1,165,432`. V4 preserves the existing block rewards and
subsidy reduction heights; Orchard activation does not change them.

## Choose A Network

| Network | Intended use | P2P port | RPC port |
| --- | --- | ---: | ---: |
| Mainnet | Public production network with real NITO | `8820` | `8825` |
| Testnet | Shared permissionless testing with valueless coins | `8840` | `8845` |
| Signet | Operator-controlled BIP325-style test chain | `8860` | `8865` |
| Regtest | Local deterministic development and automated testing | `8880` | `8885` |

Nito Core does not currently announce an official public Signet service.
Starting with `-signet` is useful only when an operator can satisfy the
selected challenge and provides reachable peers and block production. Use the
community testnet for shared public testing and regtest for controlled local
scenarios.

The corresponding Onion service target ports are `8821`, `8841`, `8861` and
`8881`. They are not RPC ports.

## Use The Community Testnet

Testnet uses a separate datadir, ports and valueless coins. Orchard is active
from its genesis block:

```bash
nitod -testnet -daemon
nito-cli -testnet getnetworkinfo
nito-cli -testnet getorchardpools
```

Verify that `localservicesnames` contains `NITO_PRIVATE` and that
`getorchardpools` reports activation height `0` with activation enabled. If
automatic discovery has no reachable peer, use a current community endpoint
with `-addnode=<host>:8840`. The complete procedure is in
[community-testnet.md](community-testnet.md).

## Open An Existing V3 Wallet

Supported v3 Berkeley DB and SQLite wallet files open directly. Copy or restore
the wallet through the normal v4 wallet flow, then load it:

```bash
nito-cli loadwallet legacy
```

The wallet keeps its transparent keys, labels, address sequence and default
Bech32 behavior. No Orchard conversion is required for transparent use.

To add Orchard while preserving the v3 wallet:

```bash
nito-cli -rpcwallet=legacy upgradeorchardwallet
```

Save both the returned `orchard_only` phrase and the reported pre-upgrade
backup. The phrase does not replace the v3 backup.

## Create A Native V4 Wallet

```bash
nito-cli -named -interactive createwallet wallet_name=main descriptors=true
```

Export its canonical phrase and verify the returned scope:

```bash
nito-cli -rpcwallet=main dumpmnemonic
```

A native deterministic v4 wallet reports `full_wallet`, covering deterministic
transparent and Orchard authority. A recovery phrase can also use an optional
BIP39 passphrase, distinct from wallet encryption. If used, keep it separately:
Nito Core never stores it and cannot recover or reset it. `dumpmnemonic` reports
whether one is required but never returns it. Review the
[passphrase rules](wallet-backup-restore.md#optional-bip39-passphrase) and
[RPC input examples](rpc-reference.md#optional-bip39-passphrase) before use.
The interactive command requires and confirms both a wallet encryption
passphrase and a distinct BIP39 passphrase without displaying either secret.

## Restore A Native V4 Phrase

```bash
nito-cli -named createwallet wallet_name=restore blank=true descriptors=true
nito-cli -named -stdin -rpcwallet=restore sethdseed newkeypool=true
```

Enter `seed=` followed by the complete phrase on one standard-input line. If
used, enter `bip39_passphrase=` followed by its exact value on another line.
Then end input with Ctrl-D on Linux/macOS or Ctrl-Z followed by Enter on Windows.
Keep both secrets off the command line. `-stdin` disables terminal echo when
reading from a terminal; protect redirected input and its source. Qt also
provides a recovery-phrase import form.

Restore automatically reconstructs complete chain-derived transparent and
Orchard history together with current spendable funds. On an existing chain it
requires unpruned block data, `transparenthistoryindex=1`, and `orchardindex=1`
after private activation when Orchard authority is present. During node
synchronization, the restore waits for those indexes and catches up before
reporting success.

A pruned node can continue using already synchronized transparent wallet state,
but cannot perform complete phrase recovery against existing pruned history.
For Bech32x, `orchardindex=1` is the default even on pruned nodes; an explicit
`orchardindex=0` is respected. Required blocks must be indexed before deletion.
Retain that index and the wallet backup; index
storage is additional to the prune target. Complete phrase recovery still
requires an unpruned indexed node.
Missing blocks require [explicit recovery](wallet-backup-restore.md#recovering-after-required-blocks-were-pruned),
not a simple rescan; Nito Core never starts a full resynchronization automatically.

An `orchard_only` phrase must be combined with its original v3 wallet backup:
restore the v3 file first, then pass the saved phrase to
`upgradeorchardwallet`, with its BIP39 passphrase if used. Keep the original v3
`wallet.dat` backup for life for its transparent keys.

## Receive Funds

```bash
nito-cli -rpcwallet=main getnewaddress "" bech32
nito-cli -rpcwallet=main getnewaddress "" bech32x
```

Bech32 remains the default. Bech32x requires activation, a node with a
ready `orchardindex`, and unlock when the wallet is encrypted.

## Send Funds

Transparent-source send:

```bash
nito-cli -rpcwallet=main sendtoaddress <address> 1.0
```

Private-source send:

```bash
nito-cli -rpcwallet=main sendprivate <address> 1.0
```

Qt exposes the same explicit split. Normal sends never consume private notes
unless private funding is selected.
