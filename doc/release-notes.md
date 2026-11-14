# Nito Core 4.0.0 Preview Notes

These notes describe the public `v4.0` source preview. V3.0.1 remains the stable
release; V4 binaries have not been published yet. See the
[source-build guide](nito/source-builds.md) to review or test V4.

Nito Core 4.0.0 adds opt-in Bech32x private transactions to Nito.network while
preserving transparent wallet, block, mining and pool behavior.

## Required Node Upgrade

All node, pool, explorer and indexer operators must upgrade their backing Nito
daemon before mainnet block `1,165,432`. Through block `H-1`, ordinary v3 peers
remain eligible for transparent traffic. While a v4 node's active tip is below
`H`, a v3 peer may supply a transparent-only block `H` so the node can reach
the boundary. An activation block containing Orchard transactions requires a
compatible v4 source.
Immediately after `H` connects, later block traffic requires peers using
protocol `70017` or later and advertising `NITO_PRIVATE`.

After activation, incompatible peers are disconnected and remain ineligible
after restart or a reorganization below `H`. Orchard activation is independent
of the existing subsidy schedule, including the reduction from 256 NITO to
128 NITO at block `1,042,400`. V4 does not alter that schedule, the block header,
SHA-256 proof of work or transparent
coinbase construction. The activation height is compiled into the official
chain parameters and reported by `getorchardpools`.

## Community Testnet

The separate v4 testnet activates Orchard from its genesis block. Testnet nodes
advertise `NITO_PRIVATE`, require protocol `70017` or later from every peer and
use P2P port `8840`. This lets users and integrators exercise Bech32x wallet,
transaction, validation and mining behavior without waiting for mainnet
activation. Testnet coins have no value.
Shared testing also requires reachable v4 peers and ongoing block production;
see the [testnet discovery guide](nito/community-testnet.md#peer-discovery).

## Transparent Compatibility

- Block headers and SHA-256 proof of work keep their established format.
- Transparent-only blocks remain valid before and after activation.
- Transparent coinbase, subsidy, fees and normal GBT behavior remain intact.
- Existing v3 Berkeley DB and SQLite wallet files open directly.
- Bundled Berkeley DB clears newly allocated pages completely, preventing
  previous cache contents from leaking into unused database file space.
- Qt includes upstream fixes for XML recursion and network header offset
  handling. Linux builds use Expat 2.8.5; see the [dependency list](dependencies.md).
- Transparent keys, descriptors, labels, next-address sequence and default
  Bech32 receive behavior are preserved.
- Incoming transparent payments show their input addresses in Qt transaction
  details. Multiple addresses appear as an expandable list. Resolved addresses
  are saved with the wallet; missing historical data is explicitly indicated.
- Miners do not need different SHA-256 hardware.

Compatibility covers migration from v3 to v4. V3 cannot validate Orchard or
remain connected to the v4 network after activation. Opening v4-updated wallet
or chain data in v3 is not a supported rollback procedure; keep separate
backups as described in the [wallet recovery guide](nito/wallet-backup-restore.md#upgrade-and-rollback-boundaries).

## Bech32x And Orchard

- Direct Bech32x addresses use the `nito1x...` prefix.
- Transparent-to-Bech32x, Bech32x-to-transparent and Bech32x-to-Bech32x flows
  are supported after activation.
- Private notes are selected only through an explicit private-source action.
- `orchardindex` provides compact note discovery and recovery data.
- The cryptographic baseline is `orchard 0.15.0` with the explicitly selected
  fixed post-NU6.2 Orchard V2 circuit.

## Wallet Backup And Recovery

Native v4 phrases report scope `full_wallet` and cover deterministic
transparent and Orchard authority. Existing v3 wallets can add Orchard with
`upgradeorchardwallet`; the operation creates a pre-upgrade backup and returns
an `orchard_only` phrase that does not replace the v3 backup.

Phrase restore automatically reconstructs complete chain-derived history and
current spendable funds. Existing chains require unpruned block data and the
wallet history indexes; recovery waits for enabled indexes that are still
catching up. Wallet files remain authoritative for labels, comments, imported
keys, watch-only data and other local metadata.

Complete phrase recovery against existing pruned history is unavailable.
Already synchronized transparent wallets can continue operating unless they
need a rescan across deleted transparent blocks. Bech32x wallet features also
support pruning with `orchardindex=1` built before block deletion. The index
retains compact data, Merkle paths and public Orchard transaction history;
its storage is additional to the prune target.
Orchard indexing is now enabled by default on pruned nodes as well, while
respecting explicit `orchardindex=0`. Switching to pruning preserves the index.
Missing required historical blocks stop recovery/index catch-up with clear Qt
and RPC guidance, without automatically downloading the chain again. See the
[recovery procedure](nito/wallet-backup-restore.md#recovering-after-required-blocks-were-pruned).

## Mining And Pools

Pools use the standard complete transaction entries returned by
`getblocktemplate`. Orchard bytes are opaque to pool software. Pools must honor
`depends`, preserve transaction bytes, distinguish `txid` from witness hash and
recompute the witness commitment when transaction selection changes.

Orchard proofs and private coinbase fields are never generated by a pool.

## Release Validation

The release workflow targets Linux x86_64, Linux aarch64, Windows win64
and macOS arm64. The release path uses pinned dependencies, warning-free
`-Werror` builds, native and Qt tests, the locked Orchard test suite, Berkeley DB v3
wallet backup/restore, binary inspection, checksums and an aggregate manifest.

## Downloads And Verification

When V4 binaries are published, download the archive or installer for your platform from the
[official release page](https://github.com/NitoNetwork/Nito-core/releases),
together with `SHA256SUMS` and `release-manifest.txt`. The manifest identifies
the source commit and whether the release checksums are signed. Follow the
[verification instructions](../README.md#download-and-verify) before running
the downloaded files.

The matching `nito-VERSION-sources.tar.gz` includes Nito, pinned dependencies,
locked Rust crates and their notices. Keep it available when redistributing
the binaries. See [source and license information](release-sources.md) for
rebuilding and redistribution requirements.

Back up your wallet files before upgrading and shut down the old node cleanly.
Start v4 with your existing data directory to retain the downloaded chain,
wallets and completed indexes. Additional v4 indexes can take time to catch up;
their progress is available through `getindexinfo`.

Start with [doc/nito/README.md](nito/README.md) for the complete product
documentation.
