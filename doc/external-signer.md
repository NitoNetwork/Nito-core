# External Signers

Nito Core can use an external command to enumerate signing devices, obtain
transparent descriptors, display addresses and sign transparent PSBTs. Select
the command with `-signer=<command>` in a build with external-signer support.

The signer must support Nito's network parameters, address encoding and
transaction rules. An implementation of this command interface alone does not
establish hardware-wallet compatibility. These examples do not provide Orchard
spending-key support or certify any device.

## Create And Use A Wallet

Start the node with your installed signer command:

```bash
nitod -signer=/path/to/nito-compatible-signer
nito-cli enumeratesigners
nito-cli -named createwallet wallet_name=hww disable_private_keys=true \
  blank=true descriptors=true external_signer=true
```

Nito Core imports the descriptors returned by the signer. Check that they cover
the intended network and key paths before accepting deposits. Back up the
signing device according to its recovery procedure and retain a backup of the
Nito wallet for its public descriptors and local metadata.

Generate an address, then compare it with the address shown on the device:

```bash
nito-cli -rpcwallet=hww getnewaddress
nito-cli -rpcwallet=hww walletdisplayaddress <address>
```

For a normal transparent payment:

```bash
nito-cli -rpcwallet=hww sendtoaddress <transparent-address> <amount>
```

Review the destination, amount and fee on the signing device. A successful
ordinary `sendtoaddress` call returns the transaction ID; an unavailable signer
or rejected signature produces an error.

## Command Interface

The current interface is implemented in
[`src/external_signer.cpp`](../src/external_signer.cpp). Commands return JSON on
standard output. For network-specific commands, Nito passes `--chain` with
`main`, `test`, `signet` or `regtest`.

### Enumerate

```text
<command> enumerate
```

Return an array, empty when there are no devices. Each entry must provide a
string `fingerprint`; an optional string `model` identifies the device:

```json
[{"fingerprint":"00000000","model":"Example signer"}]
```

The fingerprint identifies a master key, not an authenticated device identity.

### Get Descriptors

```text
<command> --fingerprint <fingerprint> --chain <chain> getdescriptors --account 0
```

Return an object with `receive` and `internal` arrays of descriptor strings.
Descriptors must contain the correct network's extended keys, derivation paths
and checksums. Public descriptors disclose the corresponding address set and
should be handled as sensitive viewing data.

### Display An Address

```text
<command> --fingerprint <fingerprint> --chain <chain> displayaddress --desc <descriptor>
```

Return an object with an `address` string, or an `error` string on failure.
The device must verify the descriptor against its keys and display the address
for the selected Nito network.

### Sign A Transaction

Nito starts the signer with:

```text
<command> --stdin --fingerprint <fingerprint> --chain <chain>
```

It supplies the following command through standard input:

```text
signtx "<base64-psbt>"
```

Return an object containing a base64 `psbt` string with the signatures added,
or an `error` string. Nito first requires the signer's fingerprint to match a
BIP32 or Taproot derivation in at least one input. The signer must independently
review the transaction and refuse a request the user rejects.

The returned PSBT must preserve the transaction the user reviewed. Normal
wallet processing attempts to finalize and broadcast it when all required
signatures are available.

## Related Guides

- [PSBT workflow](psbt.md)
- [Offline transparent signing](offline-signing-tutorial.md)
- [Descriptors](descriptors.md)
