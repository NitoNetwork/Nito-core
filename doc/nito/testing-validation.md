# Testing And Validation

Use the checks that match how Nito Core will be installed and operated. A file
that compiles is not necessarily the same file distributed in a release, and a
node that starts is not necessarily synchronized or ready for wallet use.

## Verify Release Downloads

Download binaries, `SHA256SUMS` and the release manifest from the same release.
Verify every file you intend to install:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

On macOS, use `shasum -a 256 <file>`. On Windows, use:

```powershell
Get-FileHash .\<file> -Algorithm SHA256
```

Compare the complete hash with its line in `SHA256SUMS`. When Minisign files
are supplied, obtain the release public key through an independent official
channel before verifying them.

## Validate A Source Build

Build an exact release tag or commit using the profile in
[source-builds.md](source-builds.md). Record the revision and run the tests
enabled by that profile:

```bash
git rev-parse HEAD
make check
cargo fmt --manifest-path src/private/orchard_ffi/Cargo.toml --check
cargo test --manifest-path src/private/orchard_ffi/Cargo.toml --locked --release
```

A desktop build must also run its Qt tests. A headless wallet build must contain
the daemon, command tools and wallet RPCs but no Qt executable. A
`--disable-wallet` build intentionally omits wallet functionality and is not a
substitute for an exchange wallet build.

Cross-compiled binaries must be executed on the target platform or a suitable
emulated environment. Compilation alone does not validate runtime behavior.

## Check A Running Node

After installation, verify the selected network, synchronization and indexes:

```bash
nito-cli getnetworkinfo
nito-cli getblockchaininfo
nito-cli getorchardpools
nito-cli getindexinfo
```

Confirm that the chain is synchronized and that each index required by the
deployment reports ready. After mainnet activation, peers must support protocol
`70017` or later and advertise `NITO_PRIVATE`.

Testnet is the shared public test network. Regtest is appropriate for local,
repeatable wallet and activation scenarios. Signet requires an operator who can
satisfy the configured signing challenge and produce blocks.

## Validate Wallet Operation

Use a separate test wallet and valueless coins before enabling production
deposits or withdrawals. Verify the flows used by the deployment:

- transparent receive and send;
- transparent to Bech32x;
- Bech32x to transparent;
- Bech32x to Bech32x;
- encrypted-wallet opening and a new passphrase request for every send;
- backup and restore with the wallet backend in use;
- restart, synchronization and index catch-up.

For a v3 upgrade, retain an untouched v3 backup. Confirm that the wallet keeps
its transparent addresses, labels and spending behavior before calling
`upgradeorchardwallet`. After the upgrade, keep both the pre-upgrade backup and
the returned `orchard_only` phrase, then verify transparent and private spends.

Phrase recovery against existing history must use an unpruned node with
`transparenthistoryindex` and `orchardindex` ready. Do not accept a balance-only
result as a complete restore: transactions, current spendable funds and the
reported recovery state must all agree.

## Validate Mining And Pool Integration

Mining hardware and block headers remain SHA-256 compatible. Pool software
must nevertheless use a v4 daemon and pass complete Orchard transactions from
`getblocktemplate` without rewriting their bytes or order. Submit both a
transparent-only block and, after activation, a block containing an Orchard
transaction on a controlled network before enabling production mining.

See [mining-pool-compatibility.md](mining-pool-compatibility.md) for the complete
integration contract.

## Report A Problem

Record the Nito Core version, source commit or artifact checksum, operating
system, network, wallet backend and exact command or UI action. Remove recovery
phrases, private keys, wallet files, authentication cookies and other secrets
before sharing logs.
