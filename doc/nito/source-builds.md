# Building Nito Core v4 From Source

This guide is for exchanges, custodians, node operators and users who compile
Nito Core instead of installing the official binaries.

## Supported Build Contract

The Nito Core V4 sources are on the
[`v4.0` branch](https://github.com/NitoNetwork/Nito-core/tree/v4.0).
V4 release binaries have not been published yet. V3.0.1 remains the latest
stable release.
Clone this branch explicitly and record the exact revision before building:

```bash
git clone --branch v4.0 --single-branch https://github.com/NitoNetwork/Nito-core.git
cd Nito-core
git status --short
git rev-parse HEAD
```

For a published binary release, use its exact announced tag or commit instead.

Use the repository's `depends/` system for release and exchange builds. It
compiles the pinned, SHA-256-verified dependency sources used by the official
release workflow. Distribution libraries are useful for development, but they
do not provide the same dependency or legacy-wallet compatibility contract.

Using `depends/` and the documented options provides the supported consensus,
network and RPC behavior. It does not imply that independently compiled files
will be byte-for-byte identical when compilers, SDKs or build environments
differ.

## Choose A Build Profile

| Profile | Depends options | Configure options | Result |
| --- | --- | --- | --- |
| Desktop wallet | default | `--with-gui=qt6 --with-sqlite=yes --with-bdb=yes` | Daemon, command tools, wallet RPCs and Qt. |
| Exchange headless wallet | `NO_QT=1` | `--with-gui=no --with-sqlite=yes --with-bdb=yes` | Same daemon consensus and wallet RPCs, without `nito-qt`. |
| Validation-only headless node | `NO_QT=1 NO_WALLET=1` | `--with-gui=no --disable-wallet` | Consensus, relay, mining and node RPCs without any wallet RPC. |

Qt is not part of consensus. Removing Qt does not remove Orchard validation,
the activation rules, P2P capability enforcement or standard mining RPCs.
`--disable-wallet` is different: it intentionally removes wallet functionality
and must not be used by an exchange that relies on Nito Core wallet RPCs.

Berkeley DB 4.8 remains required when the deployment must open legacy v3
wallet files. Do not substitute an ABI-incompatible system Berkeley DB.

## Common Linux Prerequisites

The supported release baseline uses Ubuntu 22.04 and Rust 1.97.0:

```bash
sudo apt update
sudo apt install automake bison bsdmainutils build-essential cmake cpio curl \
  file git gperf libtool ninja-build patch perl pkg-config python3 \
  python3-tomli unzip zip

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --no-modify-path
fi
. "$HOME/.cargo/env"
rustup toolchain install 1.97.0 --profile minimal
rustup override set 1.97.0
rustup component add rustfmt --toolchain 1.97.0
rustc --version
cargo --version
```

For a Qt build, also install the host tools used by the release workflow:

```bash
sudo apt install gettext qt6-base-dev-tools qt6-l10n-tools x11-xkb-utils \
  xutils-dev xvfb
```

## Linux Distribution Status

Ubuntu 22.04 x86_64 is the native Linux release-build baseline in
`.github/workflows/build-release.yml`. Linux aarch64 and Windows releases are
cross-compiled from the same Ubuntu baseline, with the target toolchains below.

Other Ubuntu releases, Debian and other distributions are development targets
unless the exact release revision has been qualified there. Check the compiler,
Python and Qt host-tool requirements before building. Distribution versions and
package availability alone do not establish compatibility.

Qualification requires the complete selected profile: warning-clean dependency
and Core builds, native and applicable Qt tests, all locked Orchard tests,
binary inspection, and wallet runtime checks. Preserve diagnostics and resolve
their cause rather than disabling translations or warning checks. A successful
build of an older revision does not certify a later source or dependency update.

## Linux x86_64

Run `./autogen.sh` on every fresh Git checkout because generated Autotools
files are not stored in the repository.

### Desktop Qt build

```bash
make -C depends HOST=x86_64-pc-linux-gnu -j"$(nproc)"
./autogen.sh
CONFIG_SITE="$PWD/depends/x86_64-pc-linux-gnu/share/config.site" \
  ./configure --prefix=/ --disable-shared --with-gui=qt6 --with-qrencode \
    --with-sqlite=yes --with-bdb=yes --enable-reduce-exports \
    --enable-tests --enable-bench --enable-werror
make -j"$(nproc)"
QT_QPA_PLATFORM=minimal make check -j"$(nproc)"
```

### Exchange headless wallet build

```bash
make -C depends HOST=x86_64-pc-linux-gnu NO_QT=1 -j"$(nproc)"
./autogen.sh
CONFIG_SITE="$PWD/depends/x86_64-pc-linux-gnu/share/config.site" \
  ./configure --prefix=/ --disable-shared --with-gui=no \
    --with-sqlite=yes --with-bdb=yes --enable-reduce-exports \
    --enable-tests --enable-bench --enable-werror
make -j"$(nproc)"
make check -j"$(nproc)"
```

### Validation-only headless build

```bash
make -C depends HOST=x86_64-pc-linux-gnu NO_QT=1 NO_WALLET=1 \
  -j"$(nproc)"
./autogen.sh
CONFIG_SITE="$PWD/depends/x86_64-pc-linux-gnu/share/config.site" \
  ./configure --prefix=/ --disable-shared --with-gui=no --disable-wallet \
    --enable-reduce-exports --enable-tests --enable-bench --enable-werror
make -j"$(nproc)"
make check -j"$(nproc)"
```

For every profile, validate the locked Orchard crate separately:

```bash
cargo fmt --manifest-path src/private/orchard_ffi/Cargo.toml --check
cargo test --manifest-path src/private/orchard_ffi/Cargo.toml --locked --release
```

The complete locked Orchard test suite must pass for the selected release
revision.

## Linux aarch64 Cross-Build

Install the cross compiler and matching Rust target:

```bash
sudo apt install binutils-aarch64-linux-gnu g++-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
```

Then use `HOST=aarch64-linux-gnu` with the selected profile. For example, the
headless wallet dependency command is:

```bash
make -C depends HOST=aarch64-linux-gnu NO_QT=1 -j"$(nproc)"
./autogen.sh
CONFIG_SITE="$PWD/depends/aarch64-linux-gnu/share/config.site" \
  ./configure --prefix=/ --disable-shared --with-gui=no \
    --with-sqlite=yes --with-bdb=yes --enable-reduce-exports --enable-werror
make -j"$(nproc)"
```

Cross-compiled binaries must be tested on a real or emulated aarch64 runtime;
successful compilation alone is not runtime verification.

## Windows win64 Cross-Build

Install the POSIX MinGW toolchain, then select it explicitly:

```bash
sudo apt install g++-mingw-w64-x86-64-posix nsis
sudo update-alternatives --set x86_64-w64-mingw32-gcc \
  /usr/bin/x86_64-w64-mingw32-gcc-posix
sudo update-alternatives --set x86_64-w64-mingw32-g++ \
  /usr/bin/x86_64-w64-mingw32-g++-posix
rustup target add x86_64-pc-windows-gnu
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
```

Use `HOST=x86_64-w64-mingw32` with the selected profile. For example, the
headless wallet build is:

```bash
make -C depends HOST=x86_64-w64-mingw32 NO_QT=1 -j"$(nproc)"
./autogen.sh
CONFIG_SITE="$PWD/depends/x86_64-w64-mingw32/share/config.site" \
  ./configure --prefix=/ --disable-shared --with-gui=no \
    --with-sqlite=yes --with-bdb=yes --enable-reduce-exports --enable-werror
make -j"$(nproc)"
```

See [Windows build notes](../build-windows.md) for WSL filesystem and
`binfmt_misc` precautions.

## macOS arm64

The complete Apple Silicon Qt procedure, including the pinned native Qt tools,
translations and Berkeley DB compiler, is in the
[macOS build guide](../build-osx.md).

For a headless wallet, keep the same bootstrap and Berkeley DB settings but
add `NO_QT=1` to the `depends` command and configure with:

```bash
./autogen.sh
CONFIG_SITE="$PWD/depends/arm64-apple-darwin/share/config.site" \
  ./configure --disable-shared --with-gui=no --with-sqlite=yes --with-bdb=yes \
    --with-miniupnpc --with-natpmp --enable-tests --enable-bench \
    --enable-werror
```

Qt host tools and translation-directory options are not required for that
headless profile.

## Exchange Runtime Requirements

An exchange using the built-in wallet should run an unpruned full node and
make the required indexes explicit in `nito.conf`:

```ini
prune=0
txindex=1
orchardindex=1
transparenthistoryindex=1
```

A pruned deployment may keep using transparent wallet state that is already
synchronized. With `orchardindex=1` (the default even with pruning) built before block deletion it can also
use Orchard wallet funds, but it cannot reconstruct deleted transparent
history or perform complete phrase recovery. Exchanges should retain the
unpruned indexed profile above for recovery and operational auditability.
The Orchard index is not included in the prune storage target; see
[pruned wallets](bech32x-private-wallet.md#pruned-wallets).

Before enabling deposits or withdrawals, verify synchronization and index
readiness:

```bash
nito-cli getnetworkinfo
nito-cli getblockchaininfo
nito-cli getorchardpools
nito-cli getindexinfo
```

Do not treat a successful build as operational readiness. The active chain and
every index required by the exchange must report synchronized, and the daemon
must enforce the published v4 protocol and service requirements.

## Release-Parity Validation

The authoritative release options and platform inspections live in
`.github/workflows/build-release.yml`. Source builders should compare their
selected profile with that workflow and run the applicable gates from
[testing-validation.md](testing-validation.md).

The official workflow currently validates the complete Qt artifact matrix.
Headless builds require their own `make check`, locked Orchard test and runtime
validation evidence; a Qt workflow result must not be presented as proof of an
independently compiled headless binary.
