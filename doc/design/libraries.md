# Libraries

| Name                     | Description |
|--------------------------|-------------|
| *libnito_cli*         | RPC client functionality used by *nito-cli* executable |
| *libnito_common*      | Home for common functionality shared by different executables and libraries. Similar to *libnito_util*, but higher-level (see [Dependencies](#dependencies)). |
| *libnito_consensus*   | Stable, backwards-compatible consensus functionality used by *libnito_node* and *libnito_wallet* and also exposed as a [shared library](../shared-libraries.md). |
| *libnitoconsensus*    | Shared library build of static *libnito_consensus* library |
| *libnito_kernel*      | Consensus engine and support library used for validation by *libnito_node* and also exposed as a [shared library](../shared-libraries.md). |
| *libnitoqt*           | GUI functionality used by *nito-qt* and *nito-gui* executables |
| *libnito_ipc*         | IPC functionality used by *nito-node*, *nito-wallet*, *nito-gui* executables to communicate when [`--enable-multiprocess`](multiprocess.md) is used. |
| *libnito_node*        | P2P and RPC server functionality used by *nitod* and *nito-qt* executables. |
| *libnito_util*        | Home for common functionality shared by different executables and libraries. Similar to *libnito_common*, but lower-level (see [Dependencies](#dependencies)). |
| *libnito_wallet*      | Wallet functionality used by *nitod* and *nito-wallet* executables. |
| *libnito_wallet_tool* | Lower-level wallet functionality used by *nito-wallet* executable. |
| *libnito_zmq*         | [ZeroMQ](../zmq.md) functionality used by *nitod* and *nito-qt* executables. |

## Conventions

- Most libraries are internal libraries and have APIs which are completely unstable! There are few or no restrictions on backwards compatibility or rules about external dependencies. Exceptions are *libnito_consensus* and *libnito_kernel* which have external interfaces documented at [../shared-libraries.md](../shared-libraries.md).

- Generally each library should have a corresponding source directory and namespace. Source code organization is a work in progress, so it is true that some namespaces are applied inconsistently, and if you look at [`libnito_*_SOURCES`](../../src/Makefile.am) lists you can see that many libraries pull in files from outside their source directory. But when working with libraries, it is good to follow a consistent pattern like:

  - *libnito_node* code lives in `src/node/` in the `node::` namespace
  - *libnito_wallet* code lives in `src/wallet/` in the `wallet::` namespace
  - *libnito_ipc* code lives in `src/ipc/` in the `ipc::` namespace
  - *libnito_util* code lives in `src/util/` in the `util::` namespace
  - *libnito_consensus* code lives in `src/consensus/` in the `Consensus::` namespace

## Dependencies

- Libraries should minimize what other libraries they depend on, and only reference symbols following the arrows shown in the dependency graph below:

<table><tr><td>

```mermaid

%%{ init : { "flowchart" : { "curve" : "basis" }}}%%

graph TD;

nito-cli[nito-cli]-->libnito_cli;

nitod[nitod]-->libnito_node;
nitod[nitod]-->libnito_wallet;

nito-qt[nito-qt]-->libnito_node;
nito-qt[nito-qt]-->libnitoqt;
nito-qt[nito-qt]-->libnito_wallet;

nito-wallet[nito-wallet]-->libnito_wallet;
nito-wallet[nito-wallet]-->libnito_wallet_tool;

libnito_cli-->libnito_util;
libnito_cli-->libnito_common;

libnito_common-->libnito_consensus;
libnito_common-->libnito_util;

libnito_kernel-->libnito_consensus;
libnito_kernel-->libnito_util;

libnito_node-->libnito_consensus;
libnito_node-->libnito_kernel;
libnito_node-->libnito_common;
libnito_node-->libnito_util;

libnitoqt-->libnito_common;
libnitoqt-->libnito_util;

libnito_wallet-->libnito_common;
libnito_wallet-->libnito_util;

libnito_wallet_tool-->libnito_wallet;
libnito_wallet_tool-->libnito_util;

classDef bold stroke-width:2px, font-weight:bold, font-size: smaller;
class nito-qt,nitod,nito-cli,nito-wallet bold
```
</td></tr><tr><td>

**Dependency graph**. Arrows show linker symbol dependencies. *Consensus* lib depends on nothing. *Util* lib is depended on by everything. *Kernel* lib depends only on consensus and util.

</td></tr></table>

- The graph shows what _linker symbols_ (functions and variables) from each library other libraries can call and reference directly, but it is not a call graph. For example, there is no arrow connecting *libnito_wallet* and *libnito_node* libraries, because these libraries are intended to be modular and not depend on each other's internal implementation details. But wallet code is still able to call node code indirectly through the `interfaces::Chain` abstract class in [`interfaces/chain.h`](../../src/interfaces/chain.h) and node code calls wallet code through the `interfaces::ChainClient` and `interfaces::Chain::Notifications` abstract classes in the same file. In general, defining abstract classes in [`src/interfaces/`](../../src/interfaces/) can be a convenient way of avoiding unwanted direct dependencies or circular dependencies between libraries.

- *libnito_consensus* should be a standalone dependency that any library can depend on, and it should not depend on any other libraries itself.

- *libnito_util* should also be a standalone dependency that any library can depend on, and it should not depend on other internal libraries.

- *libnito_common* should serve a similar function as *libnito_util* and be a place for miscellaneous code used by various daemon, GUI, and CLI applications and libraries to live. It should not depend on anything other than *libnito_util* and *libnito_consensus*. The boundary between _util_ and _common_ is a little fuzzy but historically _util_ has been used for more generic, lower-level things like parsing hex, and _common_ has been used for nito-specific, higher-level things like parsing base58. The difference between util and common is mostly important because *libnito_kernel* is not supposed to depend on *libnito_common*, only *libnito_util*. In general, if it is ever unclear whether it is better to add code to *util* or *common*, it is probably better to add it to *common* unless it is very generically useful or useful particularly to include in the kernel.


- *libnito_kernel* should only depend on *libnito_util* and *libnito_consensus*.

- The only thing that should depend on *libnito_kernel* internally should be *libnito_node*. GUI and wallet libraries *libnitoqt* and *libnito_wallet* in particular should not depend on *libnito_kernel* and the unneeded functionality it would pull in, like block validation. To the extent that GUI and wallet code need scripting and signing functionality, they should be get able it from *libnito_consensus*, *libnito_common*, and *libnito_util*, instead of *libnito_kernel*.

- GUI, node, and wallet code internal implementations should all be independent of each other, and the *libnitoqt*, *libnito_node*, *libnito_wallet* libraries should never reference each other's symbols. They should only call each other through [`src/interfaces/`](`../../src/interfaces/`) abstract interfaces.

## Work in progress

- Validation code is moving from *libnito_node* to *libnito_kernel* as part of [The libnitokernel Project #24303](https://github.com/nito/nito/issues/24303)
- Source code organization is discussed in general in [Library source code organization #15732](https://github.com/nito/nito/issues/15732)
