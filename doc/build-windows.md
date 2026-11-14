WINDOWS BUILD NOTES
====================

Below are some notes on how to build Nito Core for Windows.

For release, exchange or custody deployments, start with the complete
[source-build profiles](nito/source-builds.md). They pin Rust, the MinGW target,
the dependency closure and the distinction between Qt, headless-wallet and
wallet-disabled builds.

The options known to work for building Nito Core on Windows are:

* On Linux, using the [Mingw-w64](https://www.mingw-w64.org/) cross compiler tool chain.
* On Windows, using [Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/windows/wsl/about) and Mingw-w64.
* On Windows, using [Microsoft Visual Studio](https://visualstudio.microsoft.com). See [README.md](/build_msvc/README.md).

Other options which may work, but which have not been extensively tested are (please contribute instructions):

* On Windows, using a POSIX compatibility layer application such as [cygwin](https://www.cygwin.com/) or [msys2](https://www.msys2.org/).

Installing Windows Subsystem for Linux
---------------------------------------

Follow the upstream installation instructions, available [here](https://learn.microsoft.com/en-us/windows/wsl/install).

Cross-compilation for Ubuntu and Windows Subsystem for Linux
------------------------------------------------------------

The steps below can be performed on Ubuntu or WSL. The depends system
will also work on other Linux distributions, however the commands for
installing the toolchain will be different.

First, install the general dependencies:

    sudo apt update
    sudo apt upgrade
    sudo apt install automake bison bsdmainutils build-essential cmake cpio curl file gettext git gperf libtool ninja-build nsis patch perl pkg-config python3 python3-tomli qt6-base-dev-tools qt6-l10n-tools unzip zip

A host toolchain (`build-essential`) is necessary because some dependency
packages need to build host utilities that are used in the build process.

See [dependencies.md](dependencies.md) for a complete overview.

If you want to build the windows installer with `make deploy` you need [NSIS](https://nsis.sourceforge.io/Main_Page):

    sudo apt install nsis

Obtain the Nito Core V4 sources from `v4.0` using the
[source checkout instructions](nito/source-builds.md#supported-build-contract),
and record its exact commit with `git rev-parse HEAD` before building. For a
published release, use the revision named in its announcement.

## Building for 64-bit Windows

The first step is to install the mingw-w64 cross-compilation tool chain:

```sh
sudo apt install g++-mingw-w64-x86-64-posix
sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
```

Install Rust 1.97.0 and its MinGW target:

```sh
rustup toolchain install 1.97.0 --profile minimal
rustup override set 1.97.0
rustup target add x86_64-pc-windows-gnu
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
```

Once the toolchain is installed the build steps are common:

Note that for WSL the Nito Core source path MUST be somewhere in the default mount file system, for
example /usr/src/nito, AND not under /mnt/d/. If this is not the case the dependency autoconf scripts will fail.
This means you cannot use a directory that is located directly on the host Windows file system to perform the build.

Additional WSL Note: WSL support for [launching Win32 applications](https://learn.microsoft.com/en-us/archive/blogs/wsl/windows-and-ubuntu-interoperability#launching-win32-applications-from-within-wsl)
results in `Autoconf` configure scripts being able to execute Windows Portable Executable files. This can cause
unexpected behaviour during the build, such as Win32 error dialogs for missing libraries. The recommended approach
is to temporarily disable WSL support for Win32 applications.

Build using:

    PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g') # strip out problematic Windows %PATH% imported var
    sudo bash -c "echo 0 > /proc/sys/fs/binfmt_misc/status" # Disable WSL support for Win32 applications.
    cd depends
    make HOST=x86_64-w64-mingw32
    cd ..
    ./autogen.sh
    CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/ --disable-shared --with-gui=qt6 --with-qrencode --with-sqlite=yes --with-bdb=yes --enable-reduce-exports --enable-werror
    make # use "-j N" for N parallel jobs
    sudo bash -c "echo 1 > /proc/sys/fs/binfmt_misc/status" # Enable WSL support for Win32 applications.

For a headless exchange wallet, build dependencies with
`make HOST=x86_64-w64-mingw32 NO_QT=1` and configure with
`--with-gui=no --with-sqlite=yes --with-bdb=yes`. Add `NO_WALLET=1` and
`--disable-wallet` only for a validation-only node that must not expose wallet
RPCs.

## Depends system

For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.

Installation
-------------

After building using the Windows subsystem it can be useful to copy the compiled
executables to a directory on the Windows drive in the same directory structure
as they appear in the release `.zip` archive. This can be done in the following
way. This will install to `c:\workspace\nito`, for example:

    make install DESTDIR=/mnt/c/workspace/nito

You can also create an installer using:

    make deploy
