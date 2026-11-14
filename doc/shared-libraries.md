Shared Libraries
================

## nitoconsensus
This library exposes transparent script verification to other applications,
such as language bindings. It does not validate a complete block or Orchard
proofs, nullifier uniqueness, anchors or value-pool transitions. Use a full
Nito Core node to validate the complete chain.

### API

The interface is defined in the C header `nitoconsensus.h` located in `src/script/nitoconsensus.h`.

#### Version

`nitoconsensus_version` returns an `unsigned int` with the API version *(currently `2`)*.

#### Script Validation

`nitoconsensus_verify_script`, `nitoconsensus_verify_script_with_amount` and `nitoconsensus_verify_script_with_spent_outputs` return an `int` with the status of the verification. It will be `1` if the input script correctly spends the previous output `scriptPubKey`.

##### Parameters
###### nitoconsensus_verify_script
- `const unsigned char *scriptPubKey` - The previous output script that encumbers spending.
- `unsigned int scriptPubKeyLen` - The number of bytes for the `scriptPubKey`.
- `const unsigned char *txTo` - The transaction with the input that is spending the previous output.
- `unsigned int txToLen` - The number of bytes for the `txTo`.
- `unsigned int nIn` - The index of the input in `txTo` that spends the `scriptPubKey`.
- `unsigned int flags` - The script validation flags *(see below)*.
- `nitoconsensus_error* err` - Will have the error/success code for the operation *(see below)*.

###### nitoconsensus_verify_script_with_amount
- `const unsigned char *scriptPubKey` - The previous output script that encumbers spending.
- `unsigned int scriptPubKeyLen` - The number of bytes for the `scriptPubKey`.
- `int64_t amount` - The amount spent in the input
- `const unsigned char *txTo` - The transaction with the input that is spending the previous output.
- `unsigned int txToLen` - The number of bytes for the `txTo`.
- `unsigned int nIn` - The index of the input in `txTo` that spends the `scriptPubKey`.
- `unsigned int flags` - The script validation flags *(see below)*.
- `nitoconsensus_error* err` - Will have the error/success code for the operation *(see below)*.

###### nitoconsensus_verify_script_with_spent_outputs
- `const unsigned char *scriptPubKey` - The previous output script that encumbers spending.
- `unsigned int scriptPubKeyLen` - The number of bytes for the `scriptPubKey`.
- `int64_t amount` - The amount spent in the input
- `const unsigned char *txTo` - The transaction with the input that is spending the previous output.
- `unsigned int txToLen` - The number of bytes for the `txTo`.
- `const UTXO *spentOutputs` - Previous outputs spent in the transaction. `UTXO` contains `const unsigned char *scriptPubKey`, `unsigned int scriptPubKeySize` (the script length in bytes) and `int64_t value` (the amount in Nitoshi).
- `unsigned int spentOutputsLen` - The number of entries in `spentOutputs`, matching the number of transaction inputs.
- `unsigned int nIn` - The index of the input in `txTo` that spends the `scriptPubKey`.
- `unsigned int flags` - The script validation flags *(see below)*.
- `nitoconsensus_error* err` - Will have the error/success code for the operation *(see below)*.

##### Script Flags
- `nitoconsensus_SCRIPT_FLAGS_VERIFY_NONE`
- `nitoconsensus_SCRIPT_FLAGS_VERIFY_P2SH` - Evaluate P2SH ([BIP16](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)) subscripts
- `nitoconsensus_SCRIPT_FLAGS_VERIFY_DERSIG` - Enforce strict DER ([BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)) compliance
- `nitoconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY` - Enforce NULLDUMMY ([BIP147](https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki))
- `nitoconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY` - Enable CHECKLOCKTIMEVERIFY ([BIP65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki))
- `nitoconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY` - Enable CHECKSEQUENCEVERIFY ([BIP112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki))
- `nitoconsensus_SCRIPT_FLAGS_VERIFY_WITNESS` - Enable WITNESS ([BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki))
- `nitoconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT` - Enable TAPROOT ([BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki), [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki), [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki))

##### Errors
- `nitoconsensus_ERR_OK` - No errors with input parameters *(see the return value of `nitoconsensus_verify_script` for the verification status)*
- `nitoconsensus_ERR_TX_INDEX` - An invalid index for `txTo`
- `nitoconsensus_ERR_TX_SIZE_MISMATCH` - `txToLen` did not match with the size of `txTo`
- `nitoconsensus_ERR_TX_DESERIALIZE` - An error deserializing `txTo`
- `nitoconsensus_ERR_AMOUNT_REQUIRED` - Input amount is required if WITNESS is used
- `nitoconsensus_ERR_INVALID_FLAGS` - Script verification `flags` are invalid (i.e. not part of the libconsensus interface)
- `nitoconsensus_ERR_SPENT_OUTPUTS_REQUIRED` - Spent outputs are required if TAPROOT is used
- `nitoconsensus_ERR_SPENT_OUTPUTS_MISMATCH` - Spent outputs size doesn't match tx inputs size

### Language Bindings

Build bindings against [the Nito C header](../src/script/nitoconsensus.h) and
the matching compiled library. A binding for another chain is not a compatible
Nito implementation merely because it provides similarly named functions.
