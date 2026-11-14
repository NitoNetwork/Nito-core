# Multisig Tutorial

This tutorial shows a transparent 2-of-3 descriptor multisig workflow with Nito
Core. It uses PSBTs because a multisig wallet cannot spend until enough
participants have signed the same transaction.

Private Orchard notes are not multisig outputs. This guide is for transparent
funds only.

## Requirements

- a running Nito Core node;
- Bash 4 or later and `jq` for extracting fields from JSON RPC output;
- three participant wallets that can sign;
- one watch-only multisig wallet that tracks funds and creates PSBTs.

The commands below use regtest so the tutorial is reproducible without an
external funding service.

```bash
./src/nitod -regtest -daemon -fallbackfee=0.0002
```

## Create Participant Wallets

Create three descriptor wallets. They hold private keys and should be used only
to sign multisig PSBTs.

```bash
for n in 1 2 3; do
  ./src/nito-cli -regtest -named createwallet wallet_name="participant_${n}" descriptors=true
done
```

Extract one external and one internal descriptor from each participant wallet.

```bash
declare -A xpubs

for n in 1 2 3; do
  xpubs["external_${n}"]=$(./src/nito-cli -regtest -rpcwallet="participant_${n}" listdescriptors \
    | jq -r '.descriptors[] | select(.desc | startswith("wpkh") and contains("/0/*")) | .desc' \
    | sed -E 's/^wpkh\((.*)\)#.*/\1/' | head -n 1)

  xpubs["internal_${n}"]=$(./src/nito-cli -regtest -rpcwallet="participant_${n}" listdescriptors \
    | jq -r '.descriptors[] | select(.desc | startswith("wpkh") and contains("/1/*")) | .desc' \
    | sed -E 's/^wpkh\((.*)\)#.*/\1/' | head -n 1)
done
```

## Build Multisig Descriptors

Create sorted 2-of-3 witness-script-hash descriptors and add checksums.

```bash
external_desc="wsh(sortedmulti(2,${xpubs["external_1"]},${xpubs["external_2"]},${xpubs["external_3"]}))"
internal_desc="wsh(sortedmulti(2,${xpubs["internal_1"]},${xpubs["internal_2"]},${xpubs["internal_3"]}))"

external_desc_sum=$(./src/nito-cli -regtest getdescriptorinfo "$external_desc" | jq -r '.descriptor')
internal_desc_sum=$(./src/nito-cli -regtest getdescriptorinfo "$internal_desc" | jq -r '.descriptor')
```

## Create The Watch-Only Multisig Wallet

The multisig wallet tracks addresses and creates PSBTs, but it has no private
keys.

```bash
./src/nito-cli -regtest -named createwallet \
  wallet_name="multisig_wallet" \
  disable_private_keys=true \
  blank=true \
  descriptors=true

import_payload=$(jq -nc \
  --arg ext "$external_desc_sum" \
  --arg int "$internal_desc_sum" \
  '[{"desc":$ext,"active":true,"internal":false,"timestamp":"now"},
    {"desc":$int,"active":true,"internal":true,"timestamp":"now"}]')

./src/nito-cli -regtest -rpcwallet="multisig_wallet" importdescriptors "$import_payload"
```

## Fund The Multisig Wallet

Generate a receiving address, mature the miner's coinbase outputs, then send
an ordinary payment to the multisig wallet and confirm it.

```bash
recv=$(./src/nito-cli -regtest -rpcwallet="multisig_wallet" getnewaddress)
miner=$(./src/nito-cli -regtest -rpcwallet="participant_1" getnewaddress)

./src/nito-cli -regtest generatetoaddress 101 "$miner"
./src/nito-cli -regtest -rpcwallet="participant_1" sendtoaddress "$recv" 1.0
./src/nito-cli -regtest generatetoaddress 1 "$miner"
./src/nito-cli -regtest -rpcwallet="multisig_wallet" getbalances
```

## Create A PSBT

Create a destination address and ask the watch-only wallet to build a funded
PSBT.

```bash
dest=$(./src/nito-cli -regtest -rpcwallet="participant_1" getnewaddress)

psbt=$(./src/nito-cli -regtest -rpcwallet="multisig_wallet" -named walletcreatefundedpsbt \
  inputs='[]' \
  outputs="{\"$dest\":0.5}" \
  | jq -r '.psbt')

./src/nito-cli -regtest analyzepsbt "$psbt"
```

## Sign, Combine And Broadcast

Two participant signatures are enough for a 2-of-3 spend.

```bash
psbt_1=$(./src/nito-cli -regtest -rpcwallet="participant_1" walletprocesspsbt "$psbt" | jq -r '.psbt')
psbt_2=$(./src/nito-cli -regtest -rpcwallet="participant_2" walletprocesspsbt "$psbt" | jq -r '.psbt')

combined=$(./src/nito-cli -regtest combinepsbt "[\"$psbt_1\",\"$psbt_2\"]")
hex=$(./src/nito-cli -regtest finalizepsbt "$combined" | jq -r '.hex')

./src/nito-cli -regtest sendrawtransaction "$hex"
```

After broadcasting, mine one block and check both wallets.

```bash
./src/nito-cli -regtest generatetoaddress 1 "$miner"
./src/nito-cli -regtest -rpcwallet="multisig_wallet" listtransactions
./src/nito-cli -regtest -rpcwallet="participant_1" listtransactions
```

## Related Documentation

- [descriptors.md](descriptors.md)
- [psbt.md](psbt.md)
- [nito/rpc-reference.md](nito/rpc-reference.md)
