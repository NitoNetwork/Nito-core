# macOS Build Guide

This guide builds Nito Core and the Qt application on Apple Silicon. Official
macOS releases use the same SHA-256-verified `depends/` library sources as the
Linux and Windows release targets. Homebrew supplies bootstrap tools only; its
libraries are not linked into release binaries.

Obtain the Nito Core V4 sources from `v4.0` using the
[source checkout instructions](nito/source-builds.md#supported-build-contract),
and record its exact commit with `git rev-parse HEAD` before building. For a
published release, use the revision named in its announcement.

## Prerequisites

Install the Xcode command-line tools:

```bash
xcode-select --install
```

Install [Homebrew](https://brew.sh), then install the minimal bootstrap set:

```bash
brew install automake bison cmake gperf libtool ninja pkg-config gettext gcc@14
```

These formulae provide build generators and host tools. Boost, Berkeley DB,
Qt libraries and Linguist tools, SQLite, libevent, ZeroMQ, QRencode, MiniUPnPc
and libnatpmp are built from the pinned `depends/` recipes instead of Homebrew
packages. The macOS recipe also compiles the matching QtBase translations from
the pinned Qt source archive.

Install `rustup`, then select the release toolchain:

```bash
rustup toolchain install 1.97.0 --profile minimal
rustup override set 1.97.0
rustup component add rustfmt --toolchain 1.97.0
```

## Build Pinned Dependencies

From the repository root:

```bash
export PATH="$(brew --prefix gettext)/bin:$(brew --prefix bison)/bin:$PATH"

legacy_bdb_cc="$(brew --prefix gcc@14)/bin/gcc-14"
legacy_bdb_cc_version="$($legacy_bdb_cc -dumpfullversion)"

make -C depends \
  HOST=arm64-apple-darwin \
  BUILD=arm64-apple-darwin \
  bdb_cc="$legacy_bdb_cc" \
  HOST_ID_SALT="nito-macos-bdb-gcc-${legacy_bdb_cc_version}" \
  NO_USDT=1 \
  JOBS="$(sysctl -n hw.ncpu)" \
  -j"$(sysctl -n hw.ncpu)"
```

Berkeley DB 4.8.30 remains part of the official build so Nito Core can open
supported v3 legacy wallets. Its C sources use GCC 14 for warning-clean
compatibility, while its C++ interface and the other libraries use Apple Clang
from Xcode. Every source archive is checked against the SHA-256 value in its
package recipe before it is built.

For a headless wallet build, use the same `depends` command with `NO_QT=1`.
This omits Qt and its host tools while retaining Berkeley DB, SQLite, the
wallet and the Orchard proof engine. Add `NO_WALLET=1` only for a
validation-only daemon.

## Configure And Compile

```bash
./autogen.sh

DEPENDS_PREFIX="$PWD/depends/arm64-apple-darwin"
QT_BINDIR=""
for dir in "$DEPENDS_PREFIX/bin" "$DEPENDS_PREFIX/libexec" "$DEPENDS_PREFIX/native/bin"; do
  if [ -x "$dir/moc" ]; then
    QT_BINDIR="$dir"
    break
  fi
done
test -n "$QT_BINDIR"
test -x "$DEPENDS_PREFIX/native/bin/lrelease"
export PATH="$QT_BINDIR:$DEPENDS_PREFIX/native/bin:$PATH"

CONFIG_SITE="$DEPENDS_PREFIX/share/config.site" \
  ./configure \
    --disable-shared \
    --with-gui=qt6 \
    --with-qrencode \
    --with-qt-bindir="$QT_BINDIR" \
    --with-qt-translationdir="$DEPENDS_PREFIX/translations" \
    --with-sqlite=yes \
    --with-bdb=yes \
    --with-miniupnpc \
    --with-natpmp \
    --enable-tests \
    --enable-bench \
    --enable-werror

make -j"$(sysctl -n hw.ncpu)"
make check -j"$(sysctl -n hw.ncpu)"
cargo fmt --manifest-path src/private/orchard_ffi/Cargo.toml --check
cargo test --manifest-path src/private/orchard_ffi/Cargo.toml --locked --release
```

The command-line binaries are created in `src/`, and the GUI binary is
`src/qt/nito-qt`.

### Headless configure

After building dependencies with `NO_QT=1`, run:

```bash
./autogen.sh
CONFIG_SITE="$PWD/depends/arm64-apple-darwin/share/config.site" \
  ./configure --disable-shared --with-gui=no --with-sqlite=yes \
    --with-bdb=yes --with-miniupnpc --with-natpmp --enable-tests \
    --enable-bench --enable-werror
make -j"$(sysctl -n hw.ncpu)"
make check -j"$(sysctl -n hw.ncpu)"
cargo test --manifest-path src/private/orchard_ffi/Cargo.toml --locked --release
```

This profile produces the command-line binaries but no application bundle or
DMG. Its daemon consensus and wallet RPC behavior remain the same as the Qt
profile.

## Build The Application Bundle

The `depends/` Qt build is static, including its macOS platform plugins. Build
the application without copying dynamic Qt plugins:

```bash
export QTDIR="$PWD/depends/arm64-apple-darwin"
make deploy OSX_DEPLOY_SCRIPT_ARGS=-no-plugins
```

The deploy target creates `dist/Nito-Qt.app` and a ZIP archive. Official
release automation additionally checks every Mach-O dependency with `otool`
and rejects Homebrew or temporary build-prefix paths before producing the DMG.

## Run Nito Core

```bash
./src/nitod -daemon
./src/nito-cli --help
./src/qt/nito-qt
```

The default data directory is:

```text
~/Library/Application Support/Nito/
```

Create a private configuration file when needed:

```bash
mkdir -p "$HOME/Library/Application Support/Nito"
touch "$HOME/Library/Application Support/Nito/nito.conf"
chmod 600 "$HOME/Library/Application Support/Nito/nito.conf"
```
