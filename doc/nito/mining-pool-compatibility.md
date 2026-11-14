# Mining And Pool Compatibility

Nito Core v4 preserves SHA-256 mining, the block-header format, transparent
coinbase construction, subsidy and normal fee collection. Miners and pools must
upgrade the backing daemon before mainnet block `1,165,432`, but ASIC work
submission and header hashing do not change. Orchard activation is independent
of the established subsidy schedule; V4 does not change block rewards or
their reduction heights.

## Required Operator Upgrade

Once the activation block is active, a node accepts later block traffic only
from peers using protocol `70017` or later and advertising `NITO_PRIVATE`. A
v4 node may obtain a transparent-only activation block from a v3 peer while its active
tip is still below the boundary, but that peer is disconnected immediately
afterward. A pool connected to an older daemon can no longer follow the
activated network. Upgrade the daemon before the published height even when
the pool mines only transparent payouts.

## GetBlockTemplate Contract

Pool software must:

- request `getblocktemplate` from a v4 daemon;
- preserve each selected transaction's complete raw `data` bytes;
- honor the template `depends` relationships when removing or reordering
  transactions;
- use transaction `txid` values for the transaction Merkle root;
- use the template witness hash/wtxid semantics for the witness commitment;
- submit the complete block with `submitblock`.

Private transactions are ordinary complete template entries. Pools do not
construct Orchard proofs, encrypted outputs, nullifiers, value commitments or
private coinbase fields.

## Transaction And Witness Commitments

`txid` and witness hash are not interchangeable. The transaction Merkle root is
built from stripped transaction IDs. The witness commitment uses the coinbase
witness reserved value and the wtxid commitment tree defined by the template.

If a pool removes or reorders transactions, it must preserve dependency order
and recompute every affected commitment. Missing witness data, an invalid
reserved value or a malformed coinbase commitment must reject the job instead
of being logged and submitted optimistically.

## Orchard Transactions

Pool code treats Orchard transaction bytes as opaque. It must not strip,
normalize or reconstruct bundle fields. Core has already checked the proof,
signatures, nullifiers, anchor, value balance and fee policy before exposing the
transaction to a template.

Changing those bytes invalidates the transaction or block. It cannot spend a
user's funds outside consensus; it only prevents the attempted transaction from
confirming.

## Transparent Signatures On Orchard Transactions

Every transparent signature in a transaction carrying Orchard effects commits
to the canonical Orchard effects hash. Nito appends that commitment to the
legacy, SegWit v0 and Taproot signature messages, including every supported
`SIGHASH` mode. Orchard authorization bytes are excluded from the effects hash
to avoid a circular signature dependency, but recipients, amounts, nullifiers,
commitments, anchors and value balance cannot be changed after a transparent
signature is made.

For a transaction without an Orchard bundle, no extra commitment bytes are
added. Its transparent signature hash therefore remains bit-for-bit identical
to the v3 calculation. This mechanism changes neither transaction
serialization nor the `txid`/`wtxid` rules used by pools and indexers.

## Fees And Payouts

The transparent coinbase receives subsidy plus the fees reported by Core.
Orchard value balance records movement between transparent and private pools;
it is not a separate miner payout.

Pools may pay a `nito1x...` destination with a normal wallet payout, which
shields the recipient output. Pool accounting, payout records and transparent
coinbase ownership remain unchanged.
