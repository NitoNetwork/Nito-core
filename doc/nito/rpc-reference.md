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

## Create A Native V4 Wallet

For an operator creating a wallet at a terminal, use the guided mode:

```bash
nito-cli -named -interactive createwallet wallet_name=main descriptors=true load_on_startup=true
```

The wizard asks separately whether to encrypt the wallet file and whether to
protect the recovery phrase with a BIP39 passphrase. It only asks for and
confirms the secrets that were enabled. Secret input is not echoed and is never
placed in shell history or process arguments. Answer `y`/`yes` to enable an
option; `n`/`no` or an empty answer selects No.

| Wallet-file encryption | BIP39 passphrase | Result |
| --- | --- | --- |
| No | No | Unencrypted wallet file; the recovery phrase uses an empty BIP39 passphrase. |
| Yes | No | Encrypted wallet file; the recovery phrase uses an empty BIP39 passphrase. |
| No | Yes | Unencrypted wallet file; recovery requires the phrase and its separate BIP39 passphrase. |
| Yes | Yes | Encrypted wallet file; recovery requires the phrase and its separate BIP39 passphrase. |

`load_on_startup=true` adds the wallet to the persistent startup list. `false`
removes it from that list, while omitting the argument leaves the existing
setting unchanged. On success, `createwallet` returns an object containing
`name` and optional `warnings`.

The CLI verifies RPC connectivity before asking any questions. Invalid yes/no
answers are requested again. An empty enabled secret, mismatched confirmation,
end-of-input or interrupted prompt fails locally before `createwallet` is sent.
`Ctrl+C` restores the terminal's previous echo setting. Do not combine
`-interactive` with `-stdin`, or provide either secret as a command-line
argument.

### Optional BIP39 Passphrase

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

Local CLI validation failures are printed as `error: ...` and exit with status 1
without sending `createwallet`. Server-side failures retain the normal RPC error
code and message. Use `nito-cli -help` for client options and
`nito-cli help createwallet` for the complete RPC argument/result schema.

### Advanced Automation

Automation can supply named arguments on protected standard input:

```bash
nito-cli -named -stdin createwallet wallet_name=main descriptors=true load_on_startup=true
```

Supply only the enabled secrets, one named argument per line:

| Configuration | Standard-input lines |
| --- | --- |
| Encryption only | `passphrase=<wallet encryption passphrase>` |
| BIP39 only | `bip39_passphrase=<BIP39 passphrase>` |
| Both | One `passphrase=...` line and one `bip39_passphrase=...` line |

Then end input. Omitting `passphrase` creates an unencrypted wallet; do not pass
an explicitly empty value. Omitting `bip39_passphrase` selects the empty BIP39
passphrase. `-stdin` disables terminal echo when attached to a terminal. Protect
redirected input, temporary files and their permissions; prefer the guided mode
for normal interactive use. End terminal input with Ctrl-D on Linux/macOS or
Ctrl-Z followed by Enter on Windows.

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

V3 wallet files open directly in V4 and retain their transparent keys, addresses
and behavior. No conversion is required for transparent use. The procedure below
adds Orchard authority; it does not replace or re-encrypt the V3 wallet.

If the wallet is encrypted, unlock it without placing its passphrase in the
command line:

```bash
nito-cli -stdinwalletpassphrase -rpcwallet=legacy walletpassphrase 300
```

The CLI prompts for the wallet passphrase without echo. Seeing no characters or
asterisks while typing is intentional. An unencrypted wallet does not need this
step.

To generate a new Orchard phrase without a BIP39 passphrase, run:

```bash
nito-cli -rpcwallet=legacy upgradeorchardwallet
```

Supplying a BIP39 passphrase or restoring a previously saved Orchard phrase is
an advanced protected-input operation:

```bash
nito-cli -named -stdin -rpcwallet=legacy upgradeorchardwallet
```

Enter `bip39_passphrase=<value>` to generate a new phrase protected by that
passphrase. To restore a saved Orchard root, also enter
`mnemonic=<12 or 24 words>`. Omit the BIP39 line if that saved phrase did not use
one. End input as described above and keep all secrets off the command line.

Relock a wallet that was unlocked for the upgrade:

```bash
nito-cli -rpcwallet=legacy walletlock
```

If optional legacy-to-descriptor migration is desired, run `migratewallet`
before this Orchard upgrade. `migratewallet` is refused after a canonical
Orchard root exists.

`upgradeorchardwallet`:

- requires an unlocked wallet with an active transparent key manager;
- refuses a second canonical Orchard root;
- creates a `wallet-pre-orchard-*.bak` backup before mutation;
- preserves transparent managers, descriptors, addresses, labels and default
  receive behavior;
- returns `mnemonic`, `scope`, `bip39_passphrase_required`, `backup` and
  `warning`.

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
