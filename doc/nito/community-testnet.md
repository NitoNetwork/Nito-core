# Community Testnet

Nito Core v4 testnet is a separate public test chain for validating node,
wallet, Orchard, mining and integration behavior. Testnet coins have no value
and must never be represented as mainnet funds.

## Activation And Compatibility

Orchard is active from the testnet genesis block. `getorchardpools` therefore
reports:

- `privateTxActivationHeight` equal to `0`;
- `activated` equal to `true`.

Every connected testnet peer must use protocol version `70017` or later and
advertise `NITO_PRIVATE`. There is no legacy-v3 bridge on this V4-only test
network. Mainnet activation remains fixed at block `1,165,432`; testnet
activity cannot change or accelerate it.

## Start And Verify

Start an archival testnet node with the default wallet indexes:

```bash
nitod -testnet -daemon
nito-cli -testnet getblockchaininfo
nito-cli -testnet getnetworkinfo
nito-cli -testnet getorchardpools
nito-cli -testnet getindexinfo
nito-cli -testnet getconnectioncount
nito-cli -testnet getpeerinfo
```

Check that:

- `getblockchaininfo.chain` is `test`;
- `getnetworkinfo.protocolversion` is at least `70017`;
- `getnetworkinfo.localservicesnames` contains `NITO_PRIVATE`;
- `getorchardpools.activated` is `true`;
- `orchardindex` is enabled and synchronized before wallet recovery or private
  spending against an existing testnet history.

The default testnet P2P port is `8840` and its RPC port is `8845`. The testnet
Onion service target port is `8841`; it is not an RPC endpoint.

A node can initialize testnet and create addresses without any connected peers.
For shared testing, verify that peers are connected, blocks synchronize and new
blocks continue to arrive. If the node stays at genesis with no peers, use the
discovery checks below before attempting funded transactions.

## Testnet, Signet And Regtest

Use testnet for shared community testing with valueless coins and normal
permissionless SHA-256 block production. Nito Core includes BIP325-style
Signet support for operator-controlled test chains, but no official public
Nito Signet service is currently announced. A usable Signet requires an
operator able to satisfy the selected challenge, reachable peers and ongoing
block production; do not present `-signet` as a ready community network unless
those services have been announced.

Use regtest for local, deterministic scenarios. Regtest produces blocks on
demand, activates Orchard at height `1` by default and accepts
`-privateactivationheight=<height>` for controlled boundary testing. The
default ports for every network are listed in
[quick-start.md](quick-start.md#choose-a-network).

## Peer Discovery

Use a data directory belonging to the current testnet. Its message magic and
genesis identify the network; nodes using different parameters cannot connect
or synchronize blocks into it.

The binary queries these DNS seed names:

- `t1.testnet.nito.network`;
- `t2.testnet.nito.network`;
- `t3.testnet.nito.network`;
- `testnet-seed.nito.network`.

No fixed seed address is embedded until the new network has stable public
bootstrap nodes. A shared testnet can operate only while at least one reachable
V4 testnet node accepts connections. If automatic discovery has no reachable
peer, start with a current community endpoint:

```bash
nitod -testnet -addnode=<host>:8840 -daemon
```

Do not point a testnet node at a mainnet endpoint. Testnet has distinct message
magic, genesis block, address prefixes, ports and datadir.

An operator providing a public bootstrap node should enable listening, expose
TCP port `8840`, keep the node unpruned when it is used for wallet recovery,
and verify that `getnetworkinfo.localservicesnames` contains `NITO_PRIVATE`.
DNS seed records should contain only reachable V4 testnet nodes.

## Exercise Orchard

Create a disposable descriptor wallet and request both address families:

```bash
nito-cli -testnet -named createwallet wallet_name=test descriptors=true
nito-cli -testnet -rpcwallet=test getnewaddress "" bech32
nito-cli -testnet -rpcwallet=test getnewaddress "" bech32x
```

Testnet Bech32 and Bech32x addresses use the `tn` human-readable prefix.
Bech32 remains the default receive type; Bech32x remains an explicit choice.

After obtaining confirmed testnet funds, exercise each flow separately:

```bash
nito-cli -testnet -rpcwallet=test sendtoaddress <bech32x-address> <amount>
nito-cli -testnet -rpcwallet=test sendprivate <transparent-address> <amount>
nito-cli -testnet -rpcwallet=test sendprivate <bech32x-address> <amount>
```

Confirm transactions, restart the node and wallet, and verify balances and
history again. Mining and pool tests must preserve the normal SHA-256 header,
transparent coinbase and complete opaque transaction entries returned by
`getblocktemplate`.

## Safety

- Never reuse mainnet recovery phrases, private keys or wallet files.
- Never publish RPC credentials.
- Bech32x wallet functions require `orchardindex=1` (also the pruned-node default), built before block
  deletion if pruning. Complete phrase recovery requires an unpruned node
  with both `orchardindex=1` and `transparenthistoryindex=1`.
- Treat peer service bits as advertised capabilities, not authentication.
