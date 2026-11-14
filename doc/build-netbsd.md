# NetBSD Build Guide

Updated for NetBSD [9.2](https://netbsd.org/releases/formal-9/NetBSD-9.2.html).

This guide describes how to build nitod, command-line utilities, and GUI on NetBSD.

## Preparation

### 1. Install Required Dependencies

Install the required dependencies the usual way you [install software on NetBSD](https://www.netbsd.org/docs/guide/en/chap-boot.html#chap-boot-pkgsrc).
The example commands below use `pkgin`.

```bash
pkgin install autoconf automake libtool pkg-config git gmake boost libevent

```

Install a compiler that meets the requirements in
[dependencies.md](dependencies.md), including C++20 support. If it is not the
default compiler, select its absolute executable paths with `CC` and `CXX`
when running `./configure`.

See [dependencies.md](dependencies.md) for a complete overview.

### 2. Obtain The Source And Rust Toolchain

NetBSD is a development/community target, not part of the official four-OS
release artifact matrix. Obtain an exact revision using the
[source checkout instructions](nito/source-builds.md#supported-build-contract),
then select the Orchard toolchain:

```bash
rustup toolchain install 1.97.0 --profile minimal
rustup override set 1.97.0
git rev-parse HEAD
```

### 3. Install Optional Dependencies

#### Wallet Dependencies

It is not necessary to build wallet functionality to run nitod or the GUI.

###### Descriptor Wallet Support

`sqlite3` is required to enable support for [descriptor wallets](descriptors.md).

```bash
pkgin install sqlite3
```

###### Legacy Wallet Support

`db4` is required to enable support for legacy wallets.

```bash
pkgin install db4
```

#### GUI Dependencies

Nito Core includes a GUI built with the cross-platform Qt Framework. To compile the GUI, install Qt 6.

```bash
pkgin install qt6-qtbase qt6-qttools
```

The GUI can encode addresses in a QR Code. To build in QR support for the GUI, install `qrencode`.

```bash
pkgin install qrencode
```

#### Test Suite Dependencies

There is an included test suite that is useful for testing code changes when developing.
To run the test suite, install Python 3.9 or later from the package collection
for your NetBSD release and make it available as `python3`.

### Building Nito Core

**Note**: Use `gmake` (the non-GNU `make` will exit with an error).


### 1. Configuration

There are many ways to configure Nito Core. Here is an example that
explicitly disables the wallet and GUI:

```bash
./autogen.sh
./configure --disable-wallet --with-gui=no \
    CPPFLAGS="-I/usr/pkg/include" \
    MAKE=gmake
```

For a full list of configuration options, see the output of `./configure --help`

### 2. Compile

Build and run the tests:

```bash
gmake # use "-j N" here for N parallel jobs
gmake check # Run tests if Python 3 is available
```
