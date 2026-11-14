# Nito Core v4 Documentation

Nito Core v4 preserves Nito's transparent chain and wallet behavior and adds
opt-in Bech32x private transactions backed by Orchard cryptography. Mainnet
activation is block `1,165,432`; testnet enables Orchard from genesis.

The current stable release is
[Nito Core 4.0.0](https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0).
See the [4.0.0 release notes](../release-notes.md) for the upgrade summary and
the tables below for detailed user and operator guidance.

## Wallet Users

| Need | Guide |
| --- | --- |
| Install, synchronize and create or open a wallet | [Quick start](quick-start.md) |
| Understand Bech32x addresses, private sends and pruning | [Bech32x private wallet](bech32x-private-wallet.md) |
| Back up, upgrade or restore a wallet | [Wallet backup and restore](wallet-backup-restore.md) |
| Understand security and privacy boundaries | [Security and privacy model](security-privacy-model.md) |
| Join the public test network | [Community testnet](community-testnet.md) |

## Node Operators And Integrators

| Need | Guide |
| --- | --- |
| Prepare for activation and peer enforcement | [Consensus activation](consensus-activation.md) |
| Use the v4 wallet and Orchard RPCs | [RPC reference](rpc-reference.md) |
| Integrate mining or pool software | [Mining and pool compatibility](mining-pool-compatibility.md) |
| Build desktop or headless binaries | [Source builds](source-builds.md) |
| Verify a source or release build | [Testing and validation](testing-validation.md) |
| Review licenses and cryptographic dependencies | [License and third-party code](license-and-third-party-code.md) |

## Compatibility And Recovery

- Existing v3 Berkeley DB and SQLite wallets open directly and keep their
  transparent keys, labels and address sequence.
- Bech32 remains the default receive type. Bech32x is an explicit choice.
- A native v4 `full_wallet` phrase covers deterministic transparent and Orchard
  authority. An `orchard_only` phrase added to a v3 wallet must be kept with
  the original v3 backup.
- Complete phrase recovery against an existing chain requires unpruned blocks,
  `transparenthistoryindex`, and `orchardindex` after activation.
- A pruned node can keep using synchronized Orchard funds when its Orchard
  index was built before the required blocks were deleted. Complete phrase
  recovery still requires an unpruned indexed node.

Nito Core does not implement Zcash unified addresses. Bech32x is Nito's direct
private receive family.
