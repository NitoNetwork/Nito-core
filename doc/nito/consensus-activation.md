# Consensus Activation

Nito Core v4 activates Orchard validation at the chain parameter
`privateTxActivationHeight`. Let `H` be that height. `H` is the first block that
may contain an Orchard bundle.

Mainnet uses `H = 1,165,432`. Orchard activation is independent of the
established subsidy schedule. The reward reduction from 256 NITO to 128 NITO
still occurs at block `1,042,400`. Nito Core v4 does not change that schedule,
SHA-256 proof of work, the block header or transparent coinbase construction.

Every release reports its configured height through `getorchardpools`. Node,
pool, explorer and indexer operators must install a compatible release before
block `1,165,432`.

The v4 community testnet uses `H = 0`: Orchard is active from the testnet
genesis block and all of its peers must satisfy the v4 network requirements.
Regtest activates at height `1` by default and accepts
`-privateactivationheight=<height>` for controlled boundary testing. Testnet
and regtest let wallets, nodes, miners and integrations validate Orchard
without changing or accelerating the mainnet schedule.

## Before Height H

Through block `H-1`:

- Orchard bundles are invalid in blocks below `H`;
- ordinary v3 peers remain eligible for transparent synchronization and relay;
- Qt and RPC keep unavailable Bech32x wallet functions hidden or rejected;
- transparent consensus, transactions, blocks and mining behavior are
  unchanged.

Mempool admission evaluates the next block's height. At tip `H-1`, an Orchard
transaction may be admitted for candidate block `H` if it passes all other
checks. Its P2P source and relay peers must satisfy the v4 requirements. Wallet
creation and spending controls use the active chain's activation state.

A v4 node whose active tip is below `H` may request and accept a transparent-only
block `H` from an ordinary v3 peer. This lets the node reach the activation
boundary when its current peers are still v3. An activation block containing
Orchard already requires a v4-capable source.

## At And After Height H

At height `H`, Nito Core begins validating:

- private transaction serialization and bundle version;
- Orchard proofs and RedPallas signatures;
- nullifier uniqueness;
- note commitment tree anchors;
- value balance and private-pool range safety;
- deterministic connection and disconnection state.

Transparent-only blocks remain valid. Activation enables Orchard; it does not
require every block to contain a private transaction or a new block marker.
Block headers, SHA-256 proof of work, transparent coinbase and transparent fee
collection retain their established format.

## Peer Requirements

A peer is v4-capable only when both conditions are true:

- protocol version is `70017` or later;
- services include `NITO_PRIVATE`.

Future protocol versions remain eligible when they advertise
`NITO_PRIVATE`. Compatibility is not restricted to one exact client version.

As soon as block `H` joins the active chain, every peer that fails either
requirement is disconnected. Block `H+1` and every later block require a
v4-capable peer. If no compatible peer is available, the node remains visibly
isolated instead of reconnecting to an incompatible source.

## One-Way Network Boundary

The node persists that v4 activation has been observed. A reorganization below
`H` or a restart after activation does not reopen v3 peer eligibility. This
one-way network boundary prevents an activated node from later accepting block
traffic from peers that cannot validate Orchard.

Consensus validation still follows the active-chain height: Orchard bundles
remain invalid in any block below `H`, including after a reorganization.

## Orchard Value Pool

Private transactions update the Orchard value pool:

```text
orchard_pool = prior_orchard_pool - private_bundle.value_balance
```

Positive `value_balance` moves value out of the private pool. Negative
`value_balance` moves value into it. Consensus rejects a block that would move
the pool outside the allowed money range. Undo data records the prior and
connected values so reorganization handling remains deterministic.
