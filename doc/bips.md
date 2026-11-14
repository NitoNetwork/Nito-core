# Standards And Protocol References

Nito Core keeps standard transparent transaction and wallet behavior, then adds
the v4 Orchard/Bech32x private layer documented in
`doc/nito`.

This page is a reference map, not an upstream pull-request history.

## Transparent Compatibility

| Area | Standards used by Nito Core |
| --- | --- |
| P2SH and multisig | BIP 13, BIP 16, BIP 67 |
| HD wallets and account paths | BIP 32, BIP 39, BIP 43, BIP 44, BIP 49, BIP 84, BIP 86 |
| SegWit | BIP 141, BIP 143, BIP 144, BIP 173 |
| Taproot and Bech32m | BIP 340, BIP 341, BIP 342, BIP 350 |
| PSBT | BIP 174 and BIP 371 for transparent and Taproot records |
| Replace-by-fee | BIP 125 |
| Mining templates | BIP 22 and BIP 23 |
| P2P relay and compact blocks | BIP 152, BIP 155, BIP 157, BIP 158, BIP 339 |

## Nito V4 Extensions

| Area | Nito documentation |
| --- | --- |
| Bech32x Orchard receive addresses | [nito/bech32x-private-wallet.md](nito/bech32x-private-wallet.md) |
| Private activation rules | [nito/consensus-activation.md](nito/consensus-activation.md) |
| Private wallet behavior | [nito/bech32x-private-wallet.md](nito/bech32x-private-wallet.md) |
| Automatic complete seed and history recovery | [nito/wallet-backup-restore.md](nito/wallet-backup-restore.md) |
| Private wallet RPC and PSBT records | [nito/rpc-reference.md](nito/rpc-reference.md) |
| Value pools | [nito/security-privacy-model.md](nito/security-privacy-model.md) |

## Notes For Integrators

Transparent addresses, transparent transactions, PSBTs and mining templates keep
their standard shape unless a v4 private transaction is present.
Software that parses transactions must treat v4 private transaction hex as an
opaque complete transaction unless it is explicitly Nito-v4-aware. Pool guidance
is maintained in [nito/mining-pool-compatibility.md](nito/mining-pool-compatibility.md).
