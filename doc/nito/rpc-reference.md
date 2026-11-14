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
| `getprivatenoteproof` | Exports one private note opening after explicit disclosure approval. |

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

## Guided Human Input

At a terminal, use `-named -interactive` for the 49 audited operations that
create, restore, enter or disclose private authority, sign with private
authority, or mutate wallet state that changes backup requirements. The same
mode protects private descriptors used by scan, PSBT, funding and mining RPCs.
It verifies RPC connectivity before asking questions, labels every requested
value, disables terminal echo for secrets and asks for explicit approval before
the single requested RPC is sent.

Guided mode refuses secrets supplied in process arguments, requires
`-named`, and cannot be combined with `-stdin` or
`-stdinwalletpassphrase`. Seeing no characters or asterisks while entering a
secret is intentional. Normal RPC errors remain unchanged and a cancelled,
incomplete or mismatched prompt exits before mutation.

| Guided category | Supported RPCs |
| --- | --- |
| Creation, recovery and encryption | `createwallet`, `migratewallet`, `upgradeorchardwallet`, `sethdseed`, `encryptwallet`, `walletpassphrase`, `walletpassphrasechange` |
| Private import and descriptor input | `importprivkey`, `importmulti`, `importdescriptors`, `getdescriptorinfo`, `deriveaddresses`, `utxoupdatepsbt`, `scantxoutset` (`start`), `scanblocks` (`start`) |
| Signing, funding and payment | `signmessagewithprivkey`, `signrawtransactionwithkey`, `descriptorprocesspsbt`, `signmessage`, `signrawtransactionwithwallet`, `walletprocesspsbt`, `fundrawtransaction`, `send`, `sendall`, `walletcreatefundedpsbt` |
| Descriptor-aware block construction | `generatetodescriptor`, `generateblock` |
| High-impact local chainstate changes | `pruneblockchain`, `preciousblock`, `invalidateblock`, `reconsiderblock`, `loadtxoutset` |
| Private disclosure and backup | `dumpprivkey`, `dumpmnemonic`, `getprivateviewkey`, `getprivatenoteproof`, `checkprivatenoteproof`, `listdescriptors`, `getprivatekeymaninfo`, `dumpwallet`, `backupwallet` |
| Backup-changing wallet lifecycle | `importwallet`, `restorewallet`, `upgradewallet`, `newkeypool`, `keypoolrefill`, `addmultisigaddress`, `importaddress`, `importpubkey` |

The ordinary forms of every RPC remain available for scripts. Transaction
payloads such as raw transactions, PSBTs, recipients and outputs are not
credentials and stay as normal named arguments. Guided mode hides only the
fields that can carry a password, private key, recovery phrase, private note
proof, private descriptor or `solving_data.descriptors`; it separately confirms
signing and backup-changing actions. Read-only RPCs and routine node
administration intentionally remain non-interactive. The five chainstate
commands above are included because they delete block files, alter block
validity or preference, or activate a snapshot.

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

When `blank=true`, `disable_private_keys=true`,
`descriptors=false` or `external_signer=true`, no native recovery phrase is
created, so guided mode omits the BIP39 question. A blank wallet can still be
encrypted during creation and then initialized through the guided
`sethdseed` flow.

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

Automation can supply named arguments on protected standard input. This
interface has no field-by-field prompts or confirmation and is not recommended
for normal human use:

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

The same automation mechanism accepts these named lines for the other guided
RPCs:

| RPC | Protected standard-input lines |
| --- | --- |
| `migratewallet` | Optional `passphrase=<current wallet password>` |
| `upgradeorchardwallet` | Optional `mnemonic=<12 or 24 words>` and optional `bip39_passphrase=<value>` |
| `sethdseed` | `seed=<12 or 24 words>` and optional `bip39_passphrase=<value>` |
| `encryptwallet` | `passphrase=<new wallet password>` |
| `walletpassphrasechange` | `oldpassphrase=<current password>` and `newpassphrase=<new password>` |
| `importprivkey` | `privkey=<WIF private key>` |
| `importmulti` | `requests=<JSON array>` |
| `importdescriptors` | `requests=<JSON array>` |
| `signmessagewithprivkey` | `privkey=<WIF private key>` |
| `signrawtransactionwithkey` | `privkeys=<JSON array>` |
| `descriptorprocesspsbt` | `descriptors=<JSON array>` |
| `getdescriptorinfo`, `deriveaddresses` | `descriptor=<descriptor>` |
| `utxoupdatepsbt` | Optional `descriptors=<JSON array>` |
| `scantxoutset`, `scanblocks` | `scanobjects=<JSON array>` |
| `generatetodescriptor` | `descriptor=<descriptor>` |
| `generateblock` | `output=<address or descriptor>` |
| `checkprivatenoteproof` | `proof=<private note proof>` |
| `fundrawtransaction`, `send`, `sendall`, `walletcreatefundedpsbt` | Optional `options=<JSON object>`; `fundrawtransaction` also accepts its legacy boolean |

Use `-named -stdin` for these automation calls. Never store the input in a
world-readable file or include it in the command line. Existing automation may
also use `-stdinwalletpassphrase` for `walletpassphrase` and
`walletpassphrasechange`; people at a terminal should use guided mode
instead because it provides complete labels, validation and confirmation.

## Native V4 Phrase Restore

For a blank descriptor wallet, `sethdseed` accepts a BIP39 English 12- or
24-word phrase and restores chain-derived history and current spendable funds:

```bash
nito-cli -named -interactive createwallet wallet_name=restore blank=true descriptors=true
nito-cli -named -interactive -rpcwallet=restore walletpassphrase timeout=600
nito-cli -named -interactive -rpcwallet=restore sethdseed newkeypool=true
nito-cli -rpcwallet=restore walletlock
```

The wizard requests and confirms the phrase without echo, asks whether it used
a BIP39 passphrase, confirms that secret when selected and requires final
approval before initializing the blank wallet. Keep both secrets out of shell
commands, history and process arguments. Automation can use the protected
named-input form listed above.

The guided blank-wallet creation asks whether to encrypt `wallet.dat` but
omits its normal BIP39 question because the wallet has no phrase until
`sethdseed`. Run `walletpassphrase` before `sethdseed` and `walletlock`
afterwards only when encryption was selected; skip those two lines otherwise.
The recovery wizard then asks whether to generate a new random BIP39 phrase or
use an existing seed, distinguishes an existing BIP39 phrase from a legacy WIF
seed, and asks separately for the phrase's BIP39
passphrase.

A native v4 phrase has scope `full_wallet`. It covers deterministic transparent
and Orchard authority. Existing descriptor wallets cannot rotate their seed
with `sethdseed`. WIF input remains a legacy-wallet operation and is not
reinterpreted as an Orchard root.

## Optional V3 Descriptor Migration

Supported V3 wallets can be used transparently without migration. If a legacy
wallet should be converted to descriptors, do it before adding Orchard:

```bash
nito-cli -named -interactive -rpcwallet=legacy migratewallet
```

The wizard asks for explicit approval, then whether the wallet is encrypted. It
requests the current wallet encryption password without echo only when needed.
The password is validated by the migration RPC; it is not a new secret and is
therefore not requested twice. Migration creates
`<wallet>-<timestamp>.legacy.bak` before mutation and returns its path. It may
also create `_watchonly` and `_solvables` wallets. Verify and retain the
backup and make new backups of every migrated wallet.

Migration is refused after a canonical Orchard root has been added. If Orchard
is already present, keep using the wallet directly so its transparent and
Orchard keys remain together.

## Add Orchard To An Existing V3 Wallet

V3 wallet files open directly in V4 and retain their transparent keys, addresses
and behavior. No conversion is required for transparent use. The procedure below
adds Orchard authority; it does not replace or re-encrypt the V3 wallet.

If the wallet is encrypted, unlock it without placing its passphrase in the
command line:

```bash
nito-cli -named -interactive -rpcwallet=legacy walletpassphrase timeout=300
```

The CLI prompts for the wallet passphrase without echo. Seeing no characters or
asterisks while typing is intentional. An unencrypted wallet does not need this
step.

Use the guided Orchard command for a new phrase, an optional BIP39 passphrase,
or restoration of an existing Orchard phrase:

```bash
nito-cli -named -interactive -rpcwallet=legacy upgradeorchardwallet
```

The wizard asks whether to restore a saved phrase. A supplied phrase is entered
and confirmed without echo; otherwise Core generates a new 24-word phrase. It
then asks whether to use a separate BIP39 passphrase, confirms that secret when
selected and requires final approval before the pre-upgrade backup and wallet
mutation. Automation can use the protected named-input form listed above.

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

## Wallet Encryption And Passphrase Changes

Encrypt an existing unencrypted wallet through the guided flow:

```bash
nito-cli -named -interactive -rpcwallet=main encryptwallet
```

The wizard asks for explicit approval, requests and confirms the new wallet
encryption password without echo, and sends nothing if the confirmation fails
or the operation is cancelled. Back up the encrypted wallet immediately using
`backupwallet`; backups made before encryption remain unencrypted.

Change an existing wallet encryption password with:

```bash
nito-cli -named -interactive -rpcwallet=main walletpassphrasechange
```

The current password is requested once, the new password is requested twice,
and final approval is required before the change. To unlock a wallet temporarily
for an ordinary RPC, use the dedicated hidden-input prompt:

```bash
nito-cli -named -interactive -rpcwallet=main walletpassphrase timeout=300
```

The terminal deliberately displays no characters or asterisks while the
password is entered. Lock the wallet as soon as the protected operation is
complete:

```bash
nito-cli -rpcwallet=main walletlock
```

## Private-Key Input, Signing And Sensitive Exports

Private keys, private descriptors and signing keys must not appear in shell
history or process arguments. Guided mode receives them through labeled
hidden-input prompts and confirms signing or mutation before use:

```bash
nito-cli -named -interactive -rpcwallet=legacy importprivkey label="cold key" rescan=true
nito-cli -named -interactive -rpcwallet=legacy importmulti
nito-cli -named -interactive -rpcwallet=main importdescriptors
nito-cli -named -interactive signmessagewithprivkey message="message to sign"
nito-cli -named -interactive signrawtransactionwithkey hexstring=HEX_TRANSACTION
nito-cli -named -interactive descriptorprocesspsbt psbt=BASE64_PSBT
nito-cli -named -interactive -rpcwallet=main walletprocesspsbt psbt=BASE64_PSBT
```

For `importmulti` and `importdescriptors`, enter the complete JSON request
array at the prompt. For `signrawtransactionwithkey`, enter one WIF key per
hidden prompt and finish with an empty line; an empty first line intentionally
submits an empty key array and can return an incomplete result. Non-secret
`prevtxs` and `sighashtype` may remain named command arguments. Import
operations require final approval and a new verified wallet backup afterward.

Descriptors can contain extended private keys even in otherwise read-only or
funding-oriented RPCs. Guided `getdescriptorinfo`, `deriveaddresses`,
`utxoupdatepsbt`, `scantxoutset`, `scanblocks`, `generatetodescriptor` and
`generateblock` therefore request the descriptor-bearing value without echo.
For `fundrawtransaction`, `send`, `sendall` and
`walletcreatefundedpsbt`, provide the ordinary transaction fields on the
command line; the optional `options` object is requested privately because its
`solving_data.descriptors` member can contain `xprv` data.

Wallet-owned signing uses explicit approval without moving ordinary payloads
into hidden input:

```bash
nito-cli -named -interactive -rpcwallet=main signmessage address=NITO_ADDRESS message="message"
nito-cli -named -interactive -rpcwallet=main signrawtransactionwithwallet hexstring=HEX_TRANSACTION
```

RPCs that reveal recovery authority or create a private backup require an
explicit disclosure confirmation in guided mode:

```bash
nito-cli -named -interactive -rpcwallet=legacy dumpprivkey address=NITO_ADDRESS
nito-cli -named -interactive -rpcwallet=main dumpmnemonic
nito-cli -named -interactive -rpcwallet=main getprivateviewkey address=NITO1X_ADDRESS
nito-cli -named -interactive -rpcwallet=main getprivatenoteproof cmx=NOTE_COMMITMENT
nito-cli -named -interactive -rpcwallet=main listdescriptors
nito-cli -named -interactive -rpcwallet=main getprivatekeymaninfo
nito-cli -named -interactive -rpcwallet=legacy dumpwallet filename=/secure/path/wallet.dump
nito-cli -named -interactive -rpcwallet=main backupwallet destination=/secure/path/wallet.dat
```

The guided `listdescriptors` call explicitly requests private descriptors,
and guided `getprivatekeymaninfo` explicitly requests private Orchard
descriptors. Their ordinary non-interactive forms continue to return safe
metadata by default. `dumpwallet` is legacy-transparent only;
`dumpmnemonic` and private Orchard descriptors have the recovery scope reported
by the wallet. A viewing key cannot spend funds but exposes the complete
selected Orchard branch. A private note proof cannot spend funds but reveals
the selected note amount, recipient and opening.
Treat every displayed result and created file as
sensitive, verify restrictive destination permissions, and never paste it into
support messages.

Legacy operations that change what a wallet backup must contain also support
explicit approval: `importwallet`, `restorewallet`, `upgradewallet`,
`newkeypool`, `keypoolrefill`, `addmultisigaddress`, `importaddress` and
`importpubkey`. Back up and verify the wallet after a successful operation when
the RPC help requires it. `keypoolrefill` particularly requires a fresh backup
for a non-HD legacy wallet if new keys were generated.

Ordinary read-only, routine node-administration and transaction RPCs remain
non-interactive so existing automation is preserved. `-interactive` is a
finite, audited safety layer for the commands in the table above; it is not a
general prompt wrapper and does not claim that every operational RPC needs a
human confirmation.

## Export The Recovery Phrase

```bash
nito-cli -named -interactive -rpcwallet=main dumpmnemonic
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
