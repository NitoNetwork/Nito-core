# Bech32x Private Wallet

Bech32x is the Nito private receive family. Mainnet addresses start with
`nito1x...`; testnet and Signet use `tn1x...`, and regtest uses `nrt1x...`.
They use Orchard note encryption, commitments, nullifiers and zero-knowledge proofs.

## Address Families

| Type | Purpose |
| --- | --- |
| `legacy` | P2PKH transparent receive address. |
| `p2sh-segwit` | P2SH-wrapped SegWit transparent receive address. |
| `bech32` | Native SegWit transparent receive address and wallet default. |
| `bech32m` | Taproot transparent receive address. |
| `bech32x` | Orchard private receive address. |

Qt labels the private option `Bech32x (Orchard)`. It is visible only when
activation, index and wallet state permit private operation. Bech32 is never
silently replaced as the default.

## Key And Phrase Scopes

Nito Core stores Orchard external and internal branches and the full viewing
keys required to scan them. A full viewing key can find and decrypt notes for
its branch but cannot spend them.

A native v4 root can cover deterministic transparent and Orchard authority and
is exported with scope `full_wallet`. Orchard added to an existing v3 wallet is
exported with scope `orchard_only`; the v3 wallet backup remains required for
older transparent and imported keys.

Nito Core never derives an Orchard root from an arbitrary V3 descriptor, WIF,
imported key or existing transparent master key. `upgradeorchardwallet` is the
explicit operation that adds and verifies a canonical Orchard root.

For encrypted wallets, Qt asks for the passphrase before it displays wallet
data. It then removes the spending key from memory while retaining an
authenticated, viewing-only session for the open wallet. Each Bech32x address
creation or send that needs private keys asks for the passphrase again and
relocks the spending key when the operation finishes. Explicitly locking or
closing the wallet ends the viewing session and clears decrypted private
viewing state.

## Private Index

`orchardindex` stores compact public bundle data, anchors, note commitments,
nullifiers and the metadata required for wallet discovery. It also retains
complete public transactions containing Orchard for history hydration after
block pruning; it never stores wallet keys or decrypted notes. The wallet checks
view tags, batches candidate decryption across stored full viewing keys and
hydrates only matching transactions.

Complete recovery-phrase import requires unpruned blocks and both wallet
indexes synchronized to the requested stop height. Private spending remains unavailable when the index
is disabled, incomplete or behind the chain target.

### Pruned Wallets

An already synchronized wallet can use Bech32x addresses, display Orchard
balances and spend notes whose original blocks have been deleted. Orchard
indexing is enabled by default on both archival and new pruned nodes. For example:

```ini
prune=550
orchardindex=1
```

The explicit `orchardindex=1` above documents the default; it is not required.
An explicit `orchardindex=0` is respected and disables Bech32x wallet features.
Switching an indexed archival node to pruning preserves the same index, with
no format conversion or second pruning-specific index. Index prune locks retain
blocks until indexing catches up. Compact note discovery, nullifier tracking
and the Merkle tree remain available independently of old block files. Full
public Orchard transactions are retained separately so unlocking a wallet can
recover its pending private history without discarding transaction details.
In an authorized Qt viewing session, the wallet can retain the Orchard viewing
state needed to display balances and history while its spending key remains
locked. A fully locked or closed wallet clears that viewing state. Neither
state places spending keys in the public index.

The prune target applies to block/undo files, not the index or wallet database.
Index size grows with Orchard use; this is not a fixed-size light wallet.
An absent or rebuilt index needs the blocks from private activation; a lagging
index needs its missing range. If the required blocks still exist, normal index
catch-up is sufficient. Otherwise startup stops with recovery guidance; it does
not start a redownload or silently disable Orchard. Follow the
[recovery procedure](wallet-backup-restore.md#recovering-after-required-blocks-were-pruned)
or explicitly use `orchardindex=0` to continue without Orchard. Do not delete index files from a
pruned datadir. Reorganizations beyond retained block data still require the
normal full-node recovery procedure.

This does not make complete phrase recovery possible on pruned history. A
wallet that missed deleted transparent blocks also still needs an archival
node or full reindex. Keep the wallet loaded and synchronized, and retain
`wallet.dat` backups.

A wallet restored from a recovery phrase automatically reconstructs its
complete chain-derived transaction table and current spendable notes. On an
existing post-activation chain, recovery waits for both wallet indexes to reach
the saved target before the wallet is reported complete.

When an encrypted wallet is loaded after falling behind, its transparent state
can catch up while the wallet remains locked. Nito Core persists the exact
missed Orchard range as pending work without loading full viewing keys. The
next successful unlock scans that range through `orchardindex`, clears it only
after reaching the recorded block target, and then checks the current mempool.
This is an incremental catch-up for an existing wallet, not a new
recovery-phrase import.

## Sending

Private notes are never selected silently for a normal send. Use an explicit
private-source control:

- Qt: enable `Use private balance`;
- RPC: call `sendprivate` or select the documented private source option.

Automatic private-note selection prefers larger confirmed notes to reduce the
number of actions and avoid excluding a usable note behind many small notes.
Explicit Qt coin control instead spends exactly the selected private notes.

An Orchard transaction is limited to 50 actions by consensus; transaction
weight and fee limits apply as well. A wallet may hold more than 50 notes.
To consolidate a fragmented private balance, select at most 50 confirmed notes
in Qt coin control, send them to one of your own Bech32x addresses, and subtract
the fee from that amount. Wait for confirmation before using the consolidated
output in the next batch. Each batch has its own fee and confirmation; the
wallet never silently splits one payment into multiple transactions. If a
batch exceeds the weight limit, select fewer notes.

Supported flows after activation:

| Source | Destination | Result |
| --- | --- | --- |
| Transparent | Transparent | Standard transparent transaction. |
| Transparent | Bech32x | Transparent value creates Orchard notes. |
| Bech32x | Transparent | Orchard value creates a public transparent output. |
| Bech32x | Bech32x | Private note transfer. |

Automatic transparent change uses a fresh internal address, separate from receive
addresses. Its type follows Bitcoin Core's recipient-adaptive policy:

- An explicit `-changetype` overrides automatic type selection.
- Otherwise, `-addresstype=legacy` selects legacy change.
- Otherwise, prefer a supported recipient type in this order: Taproot, native
  SegWit key hash (P2WPKH), P2SH (using P2SH-SegWit change), then legacy P2PKH.
- If no recipient type matches, prefer Taproot when supported, then Bech32,
  then the configured default address type. A P2WSH recipient is not a P2WPKH
  match. An Orchard-only recipient also uses this fallback for transparent change.

Selection depends on recipients and wallet capabilities, not the type of input
UTXOs. Legacy wallets cannot generate Taproot addresses. Imported or watch-only
wallets without an internal keypool retain the compatible source-return fallback.
A standard transparent fee replacement reuses the original transaction's change destination.
`getrawchangeaddress` without a type uses `-changetype` or the default address type;
it has no recipients to match. Orchard change returns to an Orchard source
recipient and is not affected by this transparent policy.

For an individual transaction, `fundrawtransaction` and `walletcreatefundedpsbt`
accept `changeAddress`; `send` accepts `change_address`. These RPCs also accept
`change_type` when no custom change address is supplied. The overrides apply to
transparent change, including shielding from transparent UTXOs. With
`private=true`, change stays in Orchard and transparent change overrides are
rejected.

## History And Accounting

The Qt transaction list groups a wallet operation by transaction. The
`gettransaction` RPC returns one transaction object with a `details` array;
`listtransactions` can return several entries for the same transaction.
Details distinguish recipients, debit, credit, fee, net wallet effect and output index.
Multiple outputs to the same address remain distinct outputs. OP_RETURN data is
metadata, not a user-visible recipient.
