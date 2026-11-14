# Offline Signing Tutorial

This tutorial shows how to keep private keys on an offline Nito Core wallet
while an online watch-only wallet tracks funds, creates PSBTs and broadcasts the
final transaction.

The workflow below covers transparent funds. Orchard private-note recovery and
private transaction behavior are documented separately in
[nito/bech32x-private-wallet.md](nito/bech32x-private-wallet.md) and
[nito/rpc-reference.md](nito/rpc-reference.md).

## Model

| Host | Role |
| --- | --- |
| Offline host | Holds the signing wallet and private keys. It does not need the blockchain. |
| Online host | Holds a watch-only wallet, scans the chain, creates unsigned PSBTs and broadcasts signed transactions. |

Use an encrypted wallet on the offline host and move PSBT files between hosts
with removable media or another controlled transfer method.

The commands use regtest for a local example and require Bash and `jq`.
Start separate regtest nodes on the two hosts. The offline node must have no
peer connections; it needs only the wallet and the PSBT supplied for signing.
Use `-fallbackfee=0.0002` on the online test node because a new regtest chain
has no fee-estimation history.

## Create The Offline Wallet

On the offline host:

```bash
./src/nito-cli -regtest -named -interactive createwallet \
  wallet_name="offline_wallet" \
  descriptors=true
```

Choose wallet-file encryption in the wizard and enter the passphrase twice
without echo. Choose BIP39 protection only if that separate recovery secret is
also required and will be backed up independently.

Export public descriptors. The exported file does not contain private keys, but
it reveals the wallet's public address set and should still be handled with
care.

```bash
./src/nito-cli -regtest -rpcwallet="offline_wallet" listdescriptors \
  | jq -r '.descriptors' > descriptors.json
```

Move `descriptors.json` to the online host.

## Create The Online Watch-Only Wallet

On the online host:

```bash
./src/nito-cli -regtest -named createwallet \
  wallet_name="watch_only_wallet" \
  disable_private_keys=true \
  blank=true \
  descriptors=true

./src/nito-cli -regtest -rpcwallet="watch_only_wallet" importdescriptors "$(cat descriptors.json)"
```

The watch-only wallet can generate matching receive addresses and monitor
balances, but it cannot sign spends.

## Fund The Watch-Only Wallet

Generate a receive address and fund it on regtest.

```bash
recv=$(./src/nito-cli -regtest -rpcwallet="watch_only_wallet" getnewaddress)
./src/nito-cli -regtest -named createwallet wallet_name="miner_wallet" descriptors=true
miner=$(./src/nito-cli -regtest -rpcwallet="miner_wallet" getnewaddress)

./src/nito-cli -regtest generatetoaddress 101 "$miner"
./src/nito-cli -regtest -rpcwallet="miner_wallet" sendtoaddress "$recv" 1.0
./src/nito-cli -regtest generatetoaddress 1 "$miner"
./src/nito-cli -regtest -rpcwallet="watch_only_wallet" listunspent
```

The payment spends a mature miner output. Mining a single coinbase directly
to the watch-only address would leave it immature and unavailable for the next
step. On a live network, replace the regtest mining commands with normal funding and
wait for the confirmations required by your policy.

## Create An Unsigned PSBT

On the online host:

```bash
dest=$(./src/nito-cli -regtest -rpcwallet="miner_wallet" getnewaddress)

./src/nito-cli -regtest -rpcwallet="watch_only_wallet" send \
  "{\"$dest\":0.5}" \
  | jq -r '.psbt' > unsigned.psbt

./src/nito-cli -regtest analyzepsbt "$(cat unsigned.psbt)"
```

Move `unsigned.psbt` to the offline host.

## Sign Offline

On the offline host:

Inspect the decoded transaction before signing. Confirm the destination,
amount, change and fee against the intended payment; the online host does not
authorize those choices on your behalf. The unlock command below requests the
wallet password without echo; do not place it in the command line.

```bash
./src/nito-cli -regtest decodepsbt "$(cat unsigned.psbt)"
./src/nito-cli -regtest -named -interactive -rpcwallet="offline_wallet" walletpassphrase timeout=60

./src/nito-cli -regtest -named -interactive -rpcwallet="offline_wallet" \
  walletprocesspsbt psbt="$(cat unsigned.psbt)" \
  | jq -r '.psbt' > signed.psbt
./src/nito-cli -regtest -rpcwallet="offline_wallet" walletlock
```

Move `signed.psbt` back to the online host.

## Finalize And Broadcast

On the online host:

```bash
hex=$(./src/nito-cli -regtest finalizepsbt "$(cat signed.psbt)" | jq -r '.hex')
./src/nito-cli -regtest sendrawtransaction "$hex"
./src/nito-cli -regtest generatetoaddress 1 "$miner"
```

The online watch-only wallet can then confirm the spend with:

```bash
./src/nito-cli -regtest -rpcwallet="watch_only_wallet" listtransactions
./src/nito-cli -regtest -rpcwallet="watch_only_wallet" getbalances
```

## Related Documentation

- [managing-wallets.md](managing-wallets.md)
- [psbt.md](psbt.md)
- [nito/wallet-backup-restore.md](nito/wallet-backup-restore.md)
