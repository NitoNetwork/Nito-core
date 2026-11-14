# Wallet Backup And Restore

Nito Core v4 supports existing v3 wallet files, descriptor wallets, encrypted
wallets, file backups and BIP39 English recovery phrases. These recovery sources
are complementary; they do not preserve the same information.

## Recovery Sources

| Recovery source | What it preserves |
| --- | --- |
| `wallet.dat` or `backupwallet` file | Transparent and Orchard keys stored by that wallet, descriptors, imported keys, watch-only data, labels, address book, encryption state and local metadata. |
| Native v4 phrase and its BIP39 passphrase, if used, scope `full_wallet` | Deterministic transparent and Orchard authority plus funds and history recoverable from chain data. |
| V3-upgrade phrase and its BIP39 passphrase, if used, scope `orchard_only` | The added Orchard authority only. The original v3 wallet backup remains authoritative for transparent and imported keys. |

Store wallet files and recovery phrases separately. Anyone holding a phrase
and its BIP39 passphrase, if used, can spend the authority covered by its scope.

## Optional BIP39 Passphrase

A recovery phrase can have an optional BIP39 passphrase. It is a separate secret,
not a 13th or 25th recovery word. Omitting it means an empty passphrase. Nito
Core normalizes it with Unicode NFKD; spaces and case are
significant. The limit is 1024 UTF-8 bytes both before and after normalization.
Use the same phrase and passphrase when restoring. A different valid passphrase,
including a typing error, derives another valid wallet; it is not reported as an
incorrect password.

This passphrase is distinct from the password that encrypts `wallet.dat`. Nito
Core never stores the BIP39 passphrase and cannot recover or reset it. Keep a
separate offline backup of it if used. Losing it prevents phrase-based recovery
of that wallet even if the phrase is available.

`backupwallet` and `restorewallet` preserve the wallet's derived seed record,
but never the BIP39 passphrase. A wallet-file restore can therefore use the saved
derived authority without re-entering it; an encrypted file still requires its
wallet encryption password. `dumpmnemonic` exports the phrase and reports whether
a BIP39 passphrase is required, but never returns that passphrase. `dumpwallet`
exports legacy transparent keys only, not Orchard authority or the BIP39 passphrase.

## Existing V3 Wallet Files

Supported v3 Berkeley DB and SQLite wallets open directly in Nito Core v4.
Transparent keys, descriptors, labels, address sequence, encryption and default
Bech32 behavior are preserved. Transparent use does not require an Orchard
upgrade or mandatory database conversion.

Use `backupwallet` before moving a wallet between systems:

```bash
nito-cli -rpcwallet=legacy backupwallet "/secure/path/legacy-wallet.dat"
```

Restore a wallet file with the normal wallet restore flow. A file restore is the
only recovery method that can preserve wallet-local labels, comments, imported
keys and other non-chain metadata.

### Upgrade And Rollback Boundaries

V3 wallet compatibility means that supported v3 files can be opened and used
by v4. It does not establish that v3 can read every wallet or data directory
after v4 has updated it. Replacing the executable with v3 is not a supported
rollback procedure. V3 also lacks Orchard consensus and the peer capabilities
required by the v4 network after activation.

Keep the pre-upgrade backup separately. After adding Orchard, make a new
`backupwallet` backup that includes the added keys and retain the recovery
phrase with its declared scope. The old backup alone cannot restore Orchard
authority created after that backup. Restoring an older backup also does not
undo confirmed transactions.

Verify a backup by restoring it into a separate wallet or isolated data
directory, retaining the original until its recovery has been checked. Never
send a recovery phrase or wallet file to a third party for this verification.

## Add Orchard To A V3 Wallet

```bash
nito-cli -rpcwallet=legacy upgradeorchardwallet
```

The operation creates a pre-upgrade backup before adding one canonical Orchard
root. It does not replace or deactivate the v3 transparent managers. The
returned BIP39 phrase is marked `orchard_only`; keep both that phrase and the
reported backup. Keep the original v3 `wallet.dat` backup for life for its
transparent keys.

To restore this combination, first restore the corresponding v3 wallet file,
then call `upgradeorchardwallet` with the saved Orchard phrase and its BIP39
passphrase, if used. The phrase alone
cannot recover the older transparent or imported keys.

## Native V4 Phrase

A native v4 phrase is marked `full_wallet` and covers its deterministic
transparent and Orchard authority. Restore it into a blank descriptor wallet:

```bash
nito-cli -named createwallet wallet_name=restore blank=true descriptors=true
nito-cli -named -stdin -rpcwallet=restore sethdseed newkeypool=true
```

Enter `seed=` followed by the phrase on one standard-input line. If used, enter
`bip39_passphrase=` followed by its exact value on a second line. End input with
Ctrl-D on Linux/macOS or Ctrl-Z followed by Enter on Windows. Do not put either
secret on the command line. `-stdin` disables terminal echo when reading from a
terminal; redirected input and its source still need protection. Qt also provides
a recovery-phrase form.

Use `dumpmnemonic` on an unlocked wallet to export the phrase and verify its
scope. Descriptor `sethdseed` initializes a blank wallet only; it does not
rotate an active descriptor seed and does not accept WIF as an Orchard root.

Recovery phrases use the English BIP39 word list, with 12 or 24 words and an
optional BIP39 passphrase. Nito Core has two restrictions
on imported 24-word entropy: it must be a valid secp256k1 scalar and must not use
the reserved 12-word metadata prefix. Unsupported phrases are rejected before
wallet initialization. A valid BIP39 checksum alone therefore does not establish
compatibility with Nito Core, and another wallet's derivation paths may differ.

## Automatic Complete Restore

Phrase import automatically reconstructs:

- transparent UTXOs within the declared HD discovery coverage;
- Orchard notes found through stored viewing keys and `orchardindex`;
- chain-derived sends, receives, change, consolidations, internal transfers and
  private transaction rows.

Qt restores the wallet in the background. The descriptor `sethdseed` RPC waits
until recovery finishes before returning. Both paths verify that the restored
funds and history reach the same chain tip before reporting completion. Blocks
received during recovery are included, and chain reorganizations are handled
before the wallet is reported complete.

Restoring over an existing chain requires:

- unpruned block data from genesis through the target;
- `transparenthistoryindex=1`;
- `orchardindex=1` when the wallet has Orchard authority and the target is at or
  after private activation.

Enabled indexes may still be catching up. Recovery waits for them and reports
progress; disabled indexes or pruned history produce an explicit error instead
of a partial-success result. A phrase imported at block zero needs no historical
index pass: ordinary block processing builds complete history as the node
synchronizes.

### Index Preparation And Progress

A synchronized blockchain and a synchronized wallet index are separate states.
If `transparenthistoryindex` is enabled for the first time, Nito Core reads the
blocks and undo data already on disk and builds a searchable record of
transparent receipts and spends. This can take time without downloading blocks.
The database directory is `indexes/transparenthistoryindex`; the RPC name
remains `transparenthistoryindex`.

Use these commands to distinguish chain synchronization from index preparation:

```bash
nito-cli getblockchaininfo
nito-cli getindexinfo
```

Compare the chain's `blocks` with each index's `best_block_height` and check
`synced`. The wallet restore dialog reports its overall operation, so its
percentage is not the index's percentage. An index is shared by the wallets in
the same node data directory and retained across restarts. Importing another
phrase does not rebuild it. Preserve existing index files; deleting them forces
reconstruction and can make recovery impossible if their source blocks were pruned.

`dbcache` controls a shared database-memory budget. A larger value may help
index construction when memory is available, but it is divided among databases
and does not guarantee a particular speed. Check index progress before changing
settings or restarting an active recovery.

## Pruned Nodes

Pruning and complete phrase recovery serve different goals:

- a continuously synchronized pruned node can spend transparent outputs already
  known to its wallet;
- an old or restored wallet cannot rescan any required range whose blocks have
  been deleted;
- recovery-phrase import against existing pruned history is refused instead of
  creating a partial wallet;
- `orchardindex=1` is the default, also with pruning, to retain Orchard discovery,
  history and spend witnesses before block deletion; an explicit
  `orchardindex=0` is respected, and `transparenthistoryindex` remains incompatible;
- without `orchardindex`, Bech32x address generation, private balance display
  and private spending are unavailable.

Keep `wallet.dat` backups even when you have a recovery phrase. Missing required
blocks produce a recovery error in Qt and RPC, not partial success. A rescan
alone cannot recreate deleted blocks. See the explicit procedure below.

An existing synchronized Orchard wallet can operate with pruning, including
private catch-up after unlock, if its Orchard index is retained. Index storage
is additional to the prune target; see [pruned wallets](bech32x-private-wallet.md#pruned-wallets).

### Recovering After Required Blocks Were Pruned

Use this procedure only if required blocks are actually missing, not merely
because the node is pruned. A current wallet with its retained Orchard index
does not need a full resynchronization. A lagging index can catch up normally
when its missing blocks are still on disk.

1. Back up the wallet using `backupwallet` or Qt's wallet backup action. Keep
   that backup safe; a recovery phrase does not replace imported keys, V3
   transparent keys, labels or other wallet metadata. Stop Nito Core cleanly
   before changing its configuration or copying its live data directory.
   If the wallet cannot be loaded, stop the node first and preserve a copy of
   its entire wallet directory, including `wallet.dat`, before proceeding.
   Never copy database files while the wallet is open.
2. Prefer another fully synchronized, non-pruned Nito Core node with both
   `transparenthistoryindex=1` and `orchardindex=1`. Restore your own wallet
   backup or phrase there; never give it to a third-party node operator.
3. Alternatively, explicitly rebuild the existing node. Set `prune=0`,
   `transparenthistoryindex=1` and `orchardindex=1` in the configuration for the
   intended network. Start that data directory once with `-reindex` (daemon
   or Qt). This rebuilds the indexes and re-downloads missing blockchain data.
   Do not leave `reindex=1` permanently in the configuration. Merely changing
   `prune=0`, using `-reindex-chainstate`, or rescanning the wallet is not a
   substitute for the full rebuild when old blocks have been deleted.
4. Allow for blockchain downloads, synchronization time, and enough disk space
   for the full blockchain **plus** indexes and wallets. Requirements grow
   with the chain; no fixed completion time or disk-size guarantee is given.
   Wait for chain and wallet indexes to finish synchronizing, then load/restore
   the wallet and allow complete history recovery (unlock when requested).
5. Check balances and recovery completion before spending. You may return to
   pruning afterward: stop cleanly, remove the temporary `-reindex` option,
   disable `txindex`, `coinstatsindex` and `transparenthistoryindex` if they were
   explicitly enabled, and set your prune target. Keep `orchardindex` enabled
   and retain its files. Keep the wallet regularly synchronized and backed up.

If only the Orchard index is missing required data, restarting explicitly with
`orchardindex=0` lets the node run without private wallet features, provided no
other index or wallet independently needs deleted blocks. This does not recover
private balances or repair missing wallet history. Do not delete the wallet or
index files as a workaround. No full resynchronization, configuration change or
redownload is triggered automatically by the recovery error.

### Address Discovery Coverage

Transparent HD recovery uses bounded gap discovery. A phrase cannot discover an
arbitrarily distant transparent address beyond the requested coverage without
an explicit larger maximum index. The default `-keypool=1000` prepares indexes
0 through 999 on each transparent descriptor branch. Start Nito Core with a
larger value before creating the blank restore wallet when a phrase may have
used a later index; for example, `-keypool=5000` prepares indexes 0 through
4999. Orchard recovery is independent of this transparent keypool bound and
uses its indexed viewing-key scan.

## Encrypted Wallets

Qt requests the passphrase before displaying balances, transaction rows or
private wallet data. Cancelling leaves the wallet closed in Qt. Headless
`nitod` may load wallets for service operation, while spending, phrase export,
viewing-key export, private note listing and private history reconstruction
still require unlock.
