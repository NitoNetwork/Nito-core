UNIX BUILD NOTES
====================
Some notes on how to build Nito Core in Unix.

(For BSD specific instructions, see `build-*bsd.md` in this directory.)

To Build
---------------------

```bash
./autogen.sh
./configure
make # use "-j N" for N parallel jobs
make install # optional
```

Exchange, custody and release builds should follow the pinned
[`depends/` source-build profiles](nito/source-builds.md). The package-manager
instructions below are convenient for development, but they do not reproduce
the official dependency or legacy-wallet compatibility contract.

See below for instructions on how to [install the dependencies on popular Linux
distributions](#linux-distribution-specific-instructions), or the
[dependencies](#dependencies) section for a complete overview.

## Rust Toolchain

Nito Core v4 always builds its Orchard proof engine, including in headless and
wallet-disabled configurations. Install the pinned Rust toolchain before
running `make`:

```bash
rustup toolchain install 1.97.0 --profile minimal
rustup override set 1.97.0
rustc --version
cargo --version
```

Cross-builds require the matching Rust target and linker described in the
[source-build guide](nito/source-builds.md).

## Memory Requirements

C++ compilers are memory-hungry. It is recommended to have at least 1.5 GB of
memory available when compiling Nito Core. On systems with less, gcc can be
tuned to conserve memory with additional CXXFLAGS:


    ./configure CXXFLAGS="--param ggc-min-expand=1 --param ggc-min-heapsize=32768"

Alternatively, or in addition, debugging information can be skipped for compilation. The default compile flags are
`-g -O2`, and can be changed with:

    ./configure CXXFLAGS="-O2"

Finally, clang (often less resource hungry) can be used instead of gcc, which is used by default:

    ./configure CXX=clang++ CC=clang

## Linux Distribution Specific Instructions

### Ubuntu & Debian

#### Dependency Build Instructions

Build requirements:

    sudo apt-get install build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 bison cmake gperf ninja-build perl

Now, you can either build from self-compiled [depends](#dependencies) or install the required dependencies:

    sudo apt-get install libevent-dev libboost-dev

SQLite is required for the descriptor wallet:

    sudo apt install libsqlite3-dev

Berkeley DB is only required for the legacy wallet. Build the patched Berkeley DB
4.8 provided by [depends](#berkeley-db) to preserve wallet-file compatibility and
the page-clearing protection used by official releases. Distribution packages
such as `libdb-dev` and `libdb++-dev` may use a different version and omit this
patch. `--with-incompatible-bdb` only bypasses the version check; it does not
provide either guarantee.

To build Nito Core without wallet, see [*Disable-wallet mode*](#disable-wallet-mode)

Optional port mapping libraries (see: `--with-miniupnpc` and `--with-natpmp`):

    sudo apt install libminiupnpc-dev libnatpmp-dev

ZMQ dependencies (provides ZMQ API):

    sudo apt-get install libzmq3-dev

User-Space, Statically Defined Tracing (USDT) dependencies:

    sudo apt install systemtap-sdt-dev

GUI dependencies:

If you want to build nito-qt, make sure that the required packages for Qt development
are installed. Qt 6 is necessary to build the GUI.
To build without GUI pass `--with-gui=no`. This disables Qt only; wallet RPCs
remain enabled unless `--disable-wallet` is also specified.

To build with Qt 6 you need the following:

    sudo apt-get install qt6-base-dev qt6-tools-dev qt6-tools-dev-tools

Additionally, to support Wayland protocol for modern desktop environments:

    sudo apt install qt6-wayland

libqrencode (optional) can be installed with:

    sudo apt-get install libqrencode-dev

Once these are installed, they will be found by configure and a nito-qt executable will be
built by default.


### Fedora

#### Dependency Build Instructions

Build requirements:

    sudo dnf install gcc-c++ libtool make autoconf automake python3 bison cmake gperf ninja-build perl

Now, you can either build from self-compiled [depends](#dependencies) or install the required dependencies:

    sudo dnf install libevent-devel boost-devel

SQLite is required for the descriptor wallet:

    sudo dnf install sqlite-devel

Berkeley DB is only required for the legacy wallet. Use the patched Berkeley DB
4.8 from [depends](#berkeley-db). Fedora's `libdb-devel` and `libdb-cxx-devel`
packages may use a different version and omit the page-clearing protection used
by official releases. `--with-incompatible-bdb` only bypasses the version check.

To build Nito Core without wallet, see [*Disable-wallet mode*](#disable-wallet-mode)

Optional port mapping libraries (see: `--with-miniupnpc` and `--with-natpmp`):

    sudo dnf install miniupnpc-devel libnatpmp-devel

ZMQ dependencies (provides ZMQ API):

    sudo dnf install zeromq-devel

User-Space, Statically Defined Tracing (USDT) dependencies:

    sudo dnf install systemtap-sdt-devel

GUI dependencies:

If you want to build nito-qt, make sure that the required packages for Qt development
are installed. Qt 6 is necessary to build the GUI.
To build without GUI pass `--with-gui=no`. This disables Qt only; wallet RPCs
remain enabled unless `--disable-wallet` is also specified.

To build with Qt 6 you need the following:

    sudo dnf install qt6-qttools-devel qt6-qtbase-devel

Additionally, to support Wayland protocol for modern desktop environments:

    sudo dnf install qt6-qtwayland

libqrencode (optional) can be installed with:

    sudo dnf install qrencode-devel

Once these are installed, they will be found by configure and a nito-qt executable will be
built by default.

## Dependencies

See [dependencies.md](dependencies.md) for a complete overview, and
[depends](/depends/README.md) on how to compile them yourself, if you wish to
not use the packages of your Linux distribution.

### Berkeley DB

The legacy wallet uses Berkeley DB 4.8 with the repository's security patches.
These patches clear newly allocated cache pages so unused database space does
not disclose previous page contents. The native database tests check this
property. To build only Berkeley DB from depends, run:
```bash
make -C depends NO_BOOST=1 NO_LIBEVENT=1 NO_QT=1 NO_SQLITE=1 NO_NATPMP=1 NO_UPNP=1 NO_ZMQ=1 NO_USDT=1
...
to: /path/to/nito/depends/x86_64-pc-linux-gnu
```
and configure using the following:
```bash
export BDB_PREFIX="/path/to/nito/depends/x86_64-pc-linux-gnu"

./configure \
    BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" \
    BDB_CFLAGS="-I${BDB_PREFIX}/include"
```

**Note**: Make sure that `BDB_PREFIX` is an absolute path.

**Note**: You only need Berkeley DB if the legacy wallet is enabled (see [*Disable-wallet mode*](#disable-wallet-mode)).

Disable-wallet mode
--------------------
When the intention is to only run a P2P node, without a wallet, Nito Core can
be compiled in disable-wallet mode with:

    ./configure --disable-wallet

In this case there is no dependency on SQLite or Berkeley DB.

Mining is also possible in disable-wallet mode using the `getblocktemplate` RPC call.

Additional Configure Flags
--------------------------
A list of additional configure flags can be displayed with:

    ./configure --help


Setup and Build Example: Arch Linux
-----------------------------------
This development example assumes you already obtained an exact source revision
using the [source checkout instructions](nito/source-builds.md#supported-build-contract):

    pacman --sync --needed autoconf automake boost gcc git libevent libtool make pkgconf python rustup sqlite
    rustup toolchain install 1.97.0 --profile minimal
    rustup override set 1.97.0
    ./autogen.sh
    ./configure --with-gui=no --with-sqlite=yes
    make check
    ./src/nitod

If you intend to work with legacy Berkeley DB wallets, see [Berkeley DB](#berkeley-db) section.
