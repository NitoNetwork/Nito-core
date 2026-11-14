# Security And Privacy Model

Nito Core v4 provides an opt-in private transaction path with Bech32x Orchard
addresses. Privacy protects wallet-specific note data; it does not hide every
fact about a transaction or network participant.

## Sensitive Wallet Data

Treat the following as secrets or sensitive viewing material:

- recovery phrases, optional BIP39 passphrases and spending keys;
- wallet private keys and encrypted wallet files;
- full viewing keys;
- decrypted notes, memos and wallet-specific note lists;
- private balances and wallet-linked transaction history.

Full viewing keys disclose incoming notes for their derivation branch and can
recover outputs encrypted to their outgoing viewing keys, including sends and
change. They cannot authorize a spend.
Opening an encrypted wallet in Qt requires its passphrase. After authentication,
Qt keeps an authorized viewing-only session so it can display balances and
history while the spending key is locked. Every address creation or send that
requires private keys asks for the passphrase again and relocks the spending
key when the operation finishes. Explicitly locking or closing the wallet ends
the viewing session and withholds private balances, decrypted notes, Bech32x
generation, viewing-key export and private history details. Public transaction
data and some local metadata can remain accessible; locking does not hide the
existence of wallet transactions.

Wallet encryption protects spending keys, Orchard note records and the local
recipient and amount information needed to rebuild a private transaction with
higher fees. The fee-bump records use authenticated encryption bound to the
transaction ID and require an unlocked wallet. Encrypting an existing wallet
also protects these records and rewrites the database to remove old plaintext
from free pages. It cannot change copies or backups made before encryption.

The entire wallet database is not encrypted. Labels, comments, receive requests
and other transaction metadata can remain readable in a copied wallet file.
Protect wallet files and backups with access controls and encrypted storage when
confidentiality against someone with file access is required.

## Phrase Scope

`dumpmnemonic` reports the authority covered by a phrase:

- `full_wallet`: deterministic transparent and Orchard authority for a native
  v4 wallet;
- `orchard_only`: Orchard authority added to an existing v3 wallet.

An `orchard_only` phrase cannot restore the wallet's earlier transparent or
imported keys. Keep the corresponding v3 `wallet.dat` backup for life for its
transparent keys. Wallet files also remain
necessary for labels, comments, address-book entries and other local metadata.

`getprivatekeymaninfo true` exports private Orchard descriptors and reports the
same scope distinction. For `full_wallet`, the exported private root has the
same full deterministic recovery authority as the recovery phrase, including
transparent and Orchard keys. For `orchard_only`, it restores Orchard only and
does not replace the original v3 wallet backup.

An optional BIP39 passphrase changes the wallet derived from a phrase. Omission
means an empty passphrase. Nito Core applies Unicode NFKD normalization; spaces
and case are significant. The limit is 1024 UTF-8 bytes before and after
normalization. A different valid passphrase, including a typing error, derives
another valid wallet rather than producing an incorrect-password error.

The BIP39 passphrase is distinct from the wallet encryption password and is
never stored, recoverable or resettable. Keep it separately if used: phrase
recovery requires both secrets. `dumpmnemonic` never returns the passphrase.
Wallet-file backups preserve the derived seed record, so `backupwallet` and
`restorewallet` retain the derived authority without storing the passphrase.
Such files still require protection; the BIP39 passphrase does not add a second
unlock password to a copied wallet file. See the
[backup guide](wallet-backup-restore.md#optional-bip39-passphrase).

## Public Chain Data

Blocks can reveal:

- transaction identifiers;
- transparent inputs and outputs;
- the presence and action count of an Orchard bundle;
- nullifiers, note commitments, encrypted outputs and anchors;
- aggregate value balance;
- proof and signature bytes.

Public data can show value entering or leaving the Orchard pool. A private
transfer does not publish its recipient address or note amount, but network
observers can still perform timing and traffic analysis. Use Tor or another
supported network privacy layer when hiding network origin matters.

## Consensus Safety

Consensus validates the fixed Orchard bundle/circuit version, proofs,
signatures, nullifiers, anchors, commitment tree, value balance, private-pool
range and undo state.

```text
orchard_pool = prior_orchard_pool - private_bundle.value_balance
```

A block that moves the private pool outside the allowed money range is invalid.
Changing validated Orchard bytes invalidates the transaction or block; it does
not bypass wallet authorization.

## Proof Verification Resource Policy

Orchard proof work is represented in policy virtual size as 5,000 units plus
1,000 units per action, with serialized size remaining the floor. Successful
proof verification uses a bounded cache; invalid proofs and verifier errors are
never cached. The existing maximum block weight also bounds the worst-case
Orchard verification cost without adding a new consensus rule.

Unsolicited P2P Orchard transactions additionally share a global verification
budget that refills at 55,000 units per second with a 110,000-unit burst. Cheap
structural, contextual and fee checks run before this budget is consumed and
before Halo2 verification. RPC submissions and block validation are not rate
limited by this P2P policy, so local operators and consensus processing remain
deterministic.

## Index And Pruning

Automatic complete recovery requires an unpruned node with
`transparenthistoryindex` and, after private activation, `orchardindex`
complete through the requested block hash. Nito Core refuses partial recovery
when an index or block history is incomplete.

A pruned node can retain and spend transparent wallet state it already knows,
provided the wallet does not need blocks older than the retained range.
With `orchardindex=1` (the default, also with pruning) built before deletion, Orchard discovery, private
history catch-up and Merkle paths survive block pruning. Complete phrase
recovery and missing transparent history still require archival blocks.
Consensus validation is unchanged; missing index data never authorizes stale
private spending or a partially complete recovery.
An explicit `orchardindex=0` is respected. If an older pruned node lacks blocks
needed by its index, startup stops with guidance rather than silently disabling
Orchard or starting a redownload. Recovery requires an explicit operator choice.

The index contains public compact Orchard data and complete public
Orchard-bearing transactions, not decrypted private notes. Its storage is
additional to the prune target. Wallet full viewing keys remain
wallet-side and are not required by public index servers.

## Operational Rules

- Verify release checksums before installing binaries.
- Upgrade every node, pool and indexer daemon before activation.
- Keep recovery phrases offline and separate from wallet-file backups.
- Encrypt wallets that hold spendable funds.
- Unlock only for the operation that requires secrets.
- Use an archival indexed node for recovery and history reconstruction.
- Never publish a spending key, recovery phrase or full viewing key.
