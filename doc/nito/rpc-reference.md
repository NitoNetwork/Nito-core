# RPC Reference

This page summarizes Nito Core v4 wallet RPCs for Bech32x, Orchard recovery and
private sends. Use `nito-cli help <rpc>` for the complete argument and result
schema shipped by the running binary.

## Activation State

`getorchardpools` reports `privateTxActivationHeight`, `activated` and the
monitored Orchard and transparent value pools. Private wallet RPCs also require
the local index and wallet state needed by the requested operation.

```bash
nito-cli getorchardpools
```

`transparent.chainValue` and `orchard.chainValue` add up to `total.chainValue`
at the returned `blocks` and `bestblockhash`. Their `chainValueNitoshi` fields
provide integer amounts for exact comparisons. These are confirmed chain totals,
not wallet balances; mempool transactions are excluded. The RPC also works before
activation, when the monitored Orchard pool is empty, and on pruned nodes.
Without a synchronized `coinstatsindex`, it scans the retained UTXO database and
can take time. If the tip changes during collection, retry the reported error.

The sum is the value remaining in the transparent UTXO set and Orchard pool,
including immature coinbase outputs. It is not necessarily the theoretical
cumulative block subsidy: the unspendable genesis reward, provably unspendable
outputs and unclaimed miner rewards reduce it. Coins whose private keys are lost
remain counted. With `coinstatsindex=1`, `gettxoutsetinfo none` additionally
reports cumulative `total_unspendable_amount`; transfers into Orchard must not
be counted as unclaimed rewards or destroyed coins.

## Address Creation

```bash
nito-cli -rpcwallet=main getnewaddress "" bech32
nito-cli -rpcwallet=main getnewaddress "" bech32x
```

`bech32x` returns a private receive address starting with `nito1x...` on
mainnet, `tn1x...` on testnet/Signet, or `nrt1x...` on regtest. Bech32 remains the
default receive type. Bech32x requires activation, a usable `orchardindex` and
wallet unlock when the wallet is encrypted.

## Balance And Notes

| RPC | Purpose |
| --- | --- |
| `getbalances` | Returns transparent balances and private balance when available. |
| `getprivatebalance` | Returns private wallet balance details. |
| `listprivateunspent` | Lists locally decrypted notes; accepts a confirmation filter and an option to include spent notes. |
| `getorchardpools` | Reports chain-level Orchard value-pool totals. |
| `getprivatekeymaninfo` | Reports Nito private key-manager and derivation metadata. |
| `getprivateviewkey` | Exports branch viewing authority with explicit disclosure scope. |

Encrypted wallets do not expose private balances, notes, viewing keys or
wallet-specific private history while locked.

Private history distinguishes explicit receipts from change even when both use
the same address. In transaction results, `private_external_credit` is the
received amount excluding change; `private_internal_credit` is change returned
to the wallet. These names do not identify the recipient's address branch.

`getwalletinfo.seed_history.locked_live` reports whether exact Orchard work is
still pending because an encrypted wallet was locked while blocks arrived or
while an unloaded wallet caught up. A successful unlock attempts that bounded
catch-up. The status remains `pending` if its index or exact chain target is not
available; it is never cleared on a partial scan.

## Sending

| RPC | Purpose |
| --- | --- |
| `sendtoaddress` | Standard send; a Bech32x destination shields transparent funds. |
| `sendprivate` | Explicitly funds a send from private notes. |
| `send` | Supports explicit private-source options for wallet integrations. |

Normal sends do not select Orchard notes automatically.

## Optional BIP39 Passphrase

`createwallet` accepts `bip39_passphrase` for a non-blank descriptor wallet with
private keys enabled. `sethdseed` accepts it when initializing a blank descriptor
wallet from a generated or supplied BIP39 phrase. `upgradeorchardwallet` accepts
it for the generated or supplied Orchard phrase. Omission means an empty
passphrase. It is distinct from `createwallet`'s `passphrase` argument, which
encrypts the wallet file.

The BIP39 passphrase is normalized with Unicode NFKD, with spaces and case
significant, and must be at most 1024 UTF-8 bytes before and after normalization.
It is never stored, recoverable or resettable. A different valid passphrase
derives another valid wallet, so a typing error is not detected as an incorrect
password. See [backup and restore](wallet-backup-restore.md#optional-bip39-passphrase).

To create a wallet with this option without exposing it in command arguments:

```bash
nito-cli -named -stdin createwallet wallet_name=main descriptors=true
```

Enter `bip39_passphrase=` followed by the chosen value on a standard-input line,
then end input. Do not type the secret in the shell command. For an encrypted
wallet, supply `passphrase=` and the separate wallet encryption password on
another standard-input line. `-stdin` disables terminal echo when reading from a
terminal; protect any redirected input and its source as well.

## Native V4 Phrase Restore

For a blank descriptor wallet, `sethdseed` accepts a BIP39 English 12- or
24-word phrase and restores chain-derived history and current spendable funds:

```bash
nito-cli -named createwallet wallet_name=restore blank=true descriptors=true
nito-cli -named -stdin -rpcwallet=restore sethdseed newkeypool=true
```

Enter `seed=` followed by the phrase on one standard-input line, then
`bip39_passphrase=` followed by its exact value on another line if used. End
standard input with Ctrl-D on Linux/macOS or Ctrl-Z followed by Enter on Windows.
Keep both secrets out of shell commands, history and process arguments.

A native v4 phrase has scope `full_wallet`. It covers deterministic transparent
and Orchard authority. Existing descriptor wallets cannot rotate their seed
with `sethdseed`. WIF input remains a legacy-wallet operation and is not
reinterpreted as an Orchard root.

## Add Orchard To An Existing V3 Wallet

```bash
nito-cli -rpcwallet=legacy upgradeorchardwallet
nito-cli -named -stdin -rpcwallet=legacy upgradeorchardwallet
```

Use the first command to create a new Orchard root, or the second to supply a
previously saved Orchard phrase through standard input. These are alternatives:
the wallet must not already have a canonical Orchard root. With the second
command, enter `mnemonic=` followed by the saved phrase on a standard-input
line, and `bip39_passphrase=` followed by its value on another line if used.
Omit the mnemonic line to generate a new phrase with the supplied passphrase.
End input as described above; keep these secrets off the command line.

`upgradeorchardwallet`:

- requires an unlocked wallet with an active transparent key manager;
- refuses a second canonical Orchard root;
- creates a `wallet-pre-orchard-*.bak` backup before mutation;
- preserves transparent managers, descriptors, addresses, labels and default
  receive behavior;
- returns `mnemonic`, `scope`, `backup` and `warning`.

The returned scope is `orchard_only`. Keep the backup permanently because the
phrase does not restore pre-existing v3 transparent or imported keys.

## Export The Recovery Phrase

```bash
nito-cli -rpcwallet=main dumpmnemonic
```

`dumpmnemonic` returns the canonical BIP39 phrase and its scope:

- `full_wallet` for a native deterministic v4 wallet;
- `orchard_only` for Orchard added to an existing v3 wallet.

The result also reports `bip39_passphrase_required`. It never returns the BIP39
passphrase; save that separately if used. `backupwallet` and `restorewallet`
preserve the derived seed record, never that passphrase. `dumpwallet` is limited
to legacy transparent keys and does not export Orchard authority or the BIP39
passphrase.

The RPC requires wallet unlock. It is intentionally unavailable when no
canonical exportable Orchard root exists.

`getprivatekeymaninfo true` returns private `or(...)` descriptors. Its warning
must be read together with the wallet seed scope: a `full_wallet` descriptor
export is equivalent in recovery authority to the full recovery phrase and
covers deterministic transparent and Orchard keys; an `orchard_only` export
covers Orchard only and cannot restore pre-existing v3 transparent or imported
keys. Keep the original v3 wallet backup permanently in the latter case.

## Restore Complete Chain History

Descriptor `sethdseed` automatically restores complete chain-derived history;
there is no separate history-rebuild RPC. On an existing chain the call waits
for `transparenthistoryindex=1` and, after private activation when Orchard
authority is present, `orchardindex=1`.
Disabled indexes or pruned historical blocks are rejected before the wallet is
reported complete. The persisted completion checkpoint contains both height
and block hash, and normal block processing advances it after recovery.

On a pruned node, an already synchronized wallet may continue normal
transparent operation, but descriptor phrase import against existing pruned
history is refused. Bech32x wallet RPCs require `orchardindex=1`, which supports
pruning when it has indexed the required blocks before deletion. The retained
index supplies compact data, history and Merkle paths independently of block
files; its storage is additional to the prune target.
Orchard indexing is enabled by default also with pruning and respects an
explicit `orchardindex=0`. If required blocks are missing, `sethdseed` and wallet
loading/restoration report the recovery options and their time, download and
disk costs. No full
resynchronization is started. See the
[recovery procedure](wallet-backup-restore.md#recovering-after-required-blocks-were-pruned).

## PSBT

Nito Core carries private effects in Nito proprietary PSBT records. Offline
signing tools must preserve unknown proprietary records and use Nito Core to
finalize Orchard bundles.

Before signing a private PSBT, call `decodepsbt` and review its
`nito_private_intent` object. It clearly decodes the unsigned transaction,
anchor, value balance, private spends, recipient addresses/raw recipients,
amounts and internal-output flags. Its `hash` commits to the unsigned
transaction and every proprietary Orchard signing-material record. Pass that
exact hash as `private_intent_hash` to `walletprocesspsbt`; private signing is
refused if the hash is missing or if any committed intent data changed.
