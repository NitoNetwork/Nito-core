# Managing the Wallet

## 1. Backing Up and Restoring The Wallet

### 1.1 Creating the Wallet

Nito Core v4 does not create a wallet automatically.
Wallets can be created with the `createwallet` RPC or with the `Create wallet` GUI menu item.

In the GUI, the `Create a new wallet` button is displayed on the main screen when there is no wallet loaded. Alternatively, there is the option `File` ->`Create wallet`.

For normal terminal use, start the guided creator. It lets the user choose
wallet-file encryption and a separate BIP39 passphrase independently:

```bash
nito-cli -named -interactive createwallet wallet_name="wallet-01" descriptors=true load_on_startup=true
```

| Wallet-file encryption | BIP39 passphrase | Result |
| --- | --- | --- |
| No | No | Unencrypted wallet file; the recovery phrase uses an empty BIP39 passphrase. |
| Yes | No | Encrypted wallet file; the recovery phrase uses an empty BIP39 passphrase. |
| No | Yes | Unencrypted wallet file; recovery requires the phrase and its BIP39 passphrase. |
| Yes | Yes | Encrypted wallet file; recovery requires the phrase and its BIP39 passphrase. |

The wizard confirms each enabled secret without displaying characters or
asterisks. This is intentional: the secrets are not exposed on screen, in shell
history or in process arguments. A mismatch or empty enabled secret is refused
before the wallet is created. Answer `y`/`yes` to enable an option; `n`/`no` or
an empty answer selects No.

For `blank=true`, watch-only, legacy or external-signer creation, no native
V4 recovery phrase is generated and the wizard therefore omits the BIP39
question. A blank descriptor wallet can still be encrypted during creation and
then initialized through the guided `sethdseed` recovery flow.

`load_on_startup=true` adds the wallet to the persistent startup list. Set it to
`false` to remove the wallet from that list, or omit it to leave the existing
setting unchanged. Run `nito-cli help createwallet` for all creation options.

By default, wallets are created in the `wallets` folder of the data directory, which varies by operating system, as shown below. The user can change the default by using the `-datadir` or `-walletdir` initialization parameters.

| Operating System | Default wallet directory                                    |
| -----------------|:------------------------------------------------------------|
| Linux            | `/home/<user>/.nito/wallets`                             |
| Windows          | `C:\Users\<user>\AppData\Roaming\Nito\wallets`           |
| macOS            | `/Users/<user>/Library/Application Support/Nito/wallets` |

### 1.2 Encrypting the Wallet

The `wallet.dat` file is not encrypted by default and is, therefore, vulnerable if an attacker gains access to the device where the wallet or the backups are stored.

Wallet encryption may prevent unauthorized access. However, this significantly increases the risk of losing coins due to forgotten passphrases. There is no way to recover a passphrase. This tradeoff should be well thought out by the user.

Wallet encryption may also not protect against more sophisticated attacks. An attacker can, for example, obtain the password by installing a keylogger on the user's machine.

After encrypting the wallet or changing the passphrase, a new backup needs to be created immediately. Encryption keeps the current HD seed and address sequence unchanged, but the wallet file now contains new encrypted key material and metadata that should be backed up.

For a new wallet, enable encryption in the guided creator above. An existing
unencrypted wallet can be encrypted from the GUI or through the guided CLI:

```bash
nito-cli -named -interactive -rpcwallet="wallet-01" encryptwallet
```

The wizard confirms the operation, requests and confirms the new password
without echo, and sends nothing if either confirmation fails. Create and verify
a new backup immediately after successful encryption.

Change an existing encryption password with:

```bash
nito-cli -named -interactive -rpcwallet="wallet-01" walletpassphrasechange
```

The current password is requested once, the new password is requested and
confirmed, and final approval is required before the change. No entered
character or asterisk is displayed. This is intentional.

The argument passed to `-rpcwallet` is the name of the wallet to be encrypted.

Encryption protects private keys, Orchard note records and private fee-bump
records. It does not encrypt the entire wallet database: some transaction
metadata, labels and comments remain readable. Backups made before encryption
remain unencrypted. See the [privacy model](nito/security-privacy-model.md#sensitive-wallet-data).

#### Advanced Automation

For protected automation, `-named -stdin` accepts named secrets one per
line. `createwallet` accepts `passphrase=...`,
`bip39_passphrase=...`, or both. `encryptwallet` accepts
`passphrase=...`; `walletpassphrasechange` accepts
`oldpassphrase=...` and `newpassphrase=...`. End input with Ctrl-D on
Linux/macOS or Ctrl-Z followed by Enter on Windows. There are no field prompts
or confirmation in this automation mode. Protect redirected input and remove
temporary sources securely; prefer `-interactive` for a person at a terminal.

Keep the passphrase safe. A separate recovery phrase can restore only the key
domains it covers; it cannot restore imported keys or the older transparent
keys of a V3 wallet upgraded with an `orchard_only` phrase. See
[recovery sources](nito/wallet-backup-restore.md#recovery-sources).

### 1.3 Unlocking the Wallet

If the wallet is encrypted and the user tries any operation related to private keys, such as sending nitos, an error message will be displayed.

```
$ nito-cli -rpcwallet="wallet-01" sendtoaddress "nito1qc2s0au0j4e7yzp26ngqk0utaxqn9gd4mpe97fv" 0.01
error code: -13
error message:
Error: Please enter the wallet passphrase with walletpassphrase first.
```

To unlock the wallet and allow it to run these operations, the `walletpassphrase` RPC is required.

This command takes the passphrase and an argument called `timeout`, which specifies the time in seconds that the wallet decryption key is stored in memory. After this period expires, the user needs to execute this RPC again.

```bash
nito-cli -named -interactive -rpcwallet="wallet-01" walletpassphrase timeout=120
```

The CLI prompts without echo. No characters or asterisks appear while typing;
this is intentional. The timeout is not a passphrase and can safely remain in
the command line. Lock the wallet early with
`nito-cli -rpcwallet="wallet-01" walletlock` when the operation is complete.

Qt requests authorization before displaying an encrypted wallet and again
when an operation needs private keys that are currently locked. Cancelling the
initial authorization leaves that wallet closed in Qt.

### 1.4 Backing Up the Wallet

To backup the wallet, the `backupwallet` RPC or the `Backup Wallet` GUI menu item must be used to ensure the file is in a safe state when the copy is made.

In the RPC, the destination parameter must include the name of the file. Otherwise, the command will return an error message like "Error: Wallet backup failed!" for descriptor wallets. If it is a legacy wallet, it will be copied and a file will be created with the default file name `wallet.dat`.

```
$ nito-cli -named -interactive -rpcwallet="wallet-01" backupwallet destination=/home/node01/Backups/backup-01.dat
```

The guided command identifies the destination and requires explicit approval
because the resulting file contains private wallet authority. It does not
overwrite an existing backup silently.

In the GUI, the wallet is selected in the `Wallet` drop-down list in the upper right corner. If this list is not present, the wallet can be loaded in `File` ->`Open Wallet` if necessary. Then, the backup can be done in `File` -> `Backup Wallet…`.

This backup file can be stored on one or multiple offline devices, which must be reliable enough to work in an emergency and be malware free. Backup files can be regularly tested to avoid problems in the future.

If the computer has malware, it can compromise the wallet when recovering the backup file. One way to minimize this is to not connect the backup to an online device.

If the wallet file and all backups are lost, a recovery phrase can recover only
its covered deterministic keys and chain-derived history. Funds controlled by
imported keys or other authority absent from the phrase remain inaccessible.

### 1.5 Backup Frequency

HD wallets derive addresses from stored seeds, but a backup covers only the
seeds, descriptors and imported keys present when it was made. Back up again
after importing keys, adding Orchard, migrating a wallet, changing encryption
or adding important local metadata. Retain the original V3 backup after an
Orchard upgrade.

Non-HD keys added after a backup cannot be recreated from that backup. Chain
scanning also cannot recreate labels, comments or receive requests. Make and
verify regular wallet-file backups even when you hold a recovery phrase.

### 1.6 Restoring the Wallet From a Backup

To restore a wallet, the `restorewallet` RPC or the `Restore Wallet` GUI menu item (`File` -> `Restore Wallet…`) must be used.

```bash
nito-cli -named -interactive restorewallet wallet_name="restored-wallet" backup_file=/home/node01/Backups/backup-01.dat
```

The guided form requires approval before loading private backup material. The
same policy is available for `importwallet`, wallet version upgrades, keypool
replacement/refill, multisignature creation and legacy watch-only imports.
These operations can change what a valid wallet backup must contain; follow the
RPC warning and create a verified backup immediately afterward.

After that, `getwalletinfo` can be used to check if the wallet has been fully restored.

```
$ nito-cli -rpcwallet="restored-wallet" getwalletinfo
```

The restored wallet can also be loaded in the GUI via `File` ->`Open wallet`.

## Adding Orchard To A V3 Wallet

V3 wallet files open directly in V4 and continue to use their existing
transparent keys, addresses and labels. Adding Orchard is optional for
transparent-only use. If legacy-to-descriptor migration is desired, run
`migratewallet` before adding Orchard; migration is refused afterwards.

First make and verify a normal V3 wallet backup. If the wallet is encrypted,
unlock it through the hidden-input CLI prompt:

```bash
nito-cli -named -interactive -rpcwallet=legacy walletpassphrase timeout=300
```

An unencrypted wallet does not need that step. Use the guided command for a new
Orchard phrase, an optional BIP39 passphrase or restoration of a saved phrase:

```bash
nito-cli -named -interactive -rpcwallet=legacy upgradeorchardwallet
```

The wizard requests and confirms a supplied phrase, confirms an optional BIP39
passphrase, and asks for final approval before mutation. The result contains the
phrase, its `orchard_only` scope, the path of the automatic pre-upgrade
backup and a warning. Save the phrase and keep both the original V3 backup and
the automatic backup permanently: the Orchard phrase cannot restore
pre-existing transparent or imported keys.

Protected automation can instead provide optional `mnemonic=...` and
`bip39_passphrase=...` lines through `-named -stdin`, as described in
the [RPC reference](nito/rpc-reference.md#advanced-automation).

Relock a wallet that was unlocked for the operation:

```bash
nito-cli -rpcwallet=legacy walletlock
```

See the [RPC reference](nito/rpc-reference.md#add-orchard-to-an-existing-v3-wallet)
and [backup and restore](nito/wallet-backup-restore.md#recovery-sources).

## Migrating Legacy Wallets to Descriptor Wallets

Nito Core refuses `migratewallet` after an Orchard recovery root has been added
to a legacy wallet. Continue using that wallet directly to preserve its
transparent and Orchard keys. Migration is optional for supported V3 legacy
wallets and must take place before `upgradeorchardwallet` if you want both.

For a person at a terminal, run:

```bash
nito-cli -named -interactive -rpcwallet=legacy migratewallet
```

The wizard confirms migration, asks whether the wallet is encrypted and requests
the current password without echo only when required. It then sends one
`migratewallet` request. A cancellation, missing password or unavailable RPC
server causes no wallet mutation.

Legacy wallets (traditional non-descriptor wallets) can be migrated to become Descriptor wallets
through the use of the `migratewallet` RPC. Migrated wallets will have all of their addresses and private keys added to
a newly created Descriptor wallet that has the same name as the original wallet. Because Descriptor
wallets do not support having private keys and watch-only scripts, there may be up to two
additional wallets created after migration. In addition to a descriptor wallet of the same name,
there may also be a wallet named `<name>_watchonly` and `<name>_solvables`. `<name>_watchonly`
contains all of the watchonly scripts. `<name>_solvables` contains any scripts which the wallet
knows but is not watching the corresponding P2(W)SH scripts.

Migrated wallets will also generate new addresses differently. While the same BIP 32 seed will be
used, the BIP 44, 49, 84, and 86 standard derivation paths will be used. After migrating, a new
backup of the wallet(s) will need to be created.

Given that there is an extremely large number of possible configurations for the scripts that
Legacy wallets can know about, be watching for, and be able to sign for, `migratewallet` only
makes a best effort attempt to capture all of these things into Descriptor wallets. There may be
unforeseen configurations which result in some scripts being excluded. If a migration fails
unexpectedly or otherwise misses any scripts, please create an issue on GitHub. A backup of the
original wallet can be found in the wallet directory with the name `<name>-<timestamp>.legacy.bak`.

The backup can be restored using the methods discussed in the
[Restoring the Wallet From a Backup](#16-restoring-the-wallet-from-a-backup) section.
