Building Nito Core with Visual Studio
========================================

Introduction
---------------------
Visual Studio 2022 is minimum required to build Nito Core.

Solution and project files to build with `msbuild` or Visual Studio can be found in the `build_msvc` directory.

To build Nito Core from the command-line, it is sufficient to only install the [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) component.

The "Desktop development with C++" workload must be installed as well.

Building with Visual Studio is an alternative to the Linux based [cross-compiler build](../doc/build-windows.md).

The official Windows release and exchange-parity path uses the MinGW
`depends/` cross-build. MSVC is a supported developer build, but it does not
claim byte-for-byte or dependency-closure equivalence with the official
package.


Prerequisites
---------------------
Install the pinned Rust toolchain used to build the Orchard proof engine:

```cmd
rustup toolchain install 1.97.0 --profile minimal
rustup override set 1.97.0
rustc --version
cargo --version
```

To build [dependencies](../doc/dependencies.md) (except for [Qt](#qt)),
the default approach is to use the [vcpkg](https://vcpkg.io) package manager from Microsoft:

The included `vcpkg-configuration.json` selects a Berkeley DB overlay with the
same page-clearing security fix as the release `depends/` build. Keep this
overlay enabled when building support for legacy wallets. Its port files are
derived from Microsoft vcpkg at the manifest's pinned baseline; their MIT
license is included in `vcpkg-ports/berkeleydb/LICENSE.txt`. Berkeley DB retains
its own upstream license.

1. [Install](https://vcpkg.io/en/getting-started.html) vcpkg.

2. By default, vcpkg makes both `release` and `debug` builds for each package.
To save build time and disk space, one could skip `debug` builds (example uses PowerShell):
```powershell

Add-Content -Path "vcpkg\triplets\x64-windows-static.cmake" -Value "set(VCPKG_BUILD_TYPE release)"
```

Qt
---------------------
To build Nito Core with the GUI, a static Qt 6 build is required.

1. Download a single ZIP archive of Qt 6 source code from https://download.qt.io/archive/qt/ (for example, `qt-everywhere-opensource-src-6.8.4.zip`) and expand it into a dedicated folder. The following instructions assume that this folder is `C:\dev\qt-source`.

> Tip: Keep the Qt source and build paths short. Long default extraction paths can still exceed Windows command-line or object path limits.

Before configuring Qt 6.8.4, apply the shared fixes from the Nito checkout.
In PowerShell, replace `C:\dev\nito` with its actual location:

```powershell
$nitoSource = 'C:\dev\nito'
foreach ($name in @('md4c_reference_definition_init.patch', 'qhttpheaders_compare_views.patch', 'qmimemagicrule_compare_views.patch', 'CVE-2026-78253.patch', 'CVE-2026-76151.patch', 'CVE-2026-19248.patch')) {
    git -C C:\dev\qt-source\qtbase apply --unidiff-zero -p2 -- "$nitoSource\depends\patches\qt\$name"
    if ($LASTEXITCODE -ne 0) { throw "Qt patch failed: $name" }
}
```

Apply these patches once to a fresh source tree. They are required for the
security fixes described in the [dependency list](../doc/dependencies.md).

2. Open "x64 Native Tools Command Prompt for VS 2022", and input the following commands:
```cmd
cd C:\dev\qt-source
mkdir build
cd build
..\configure.bat -release -opensource -confirm-license -static -static-runtime -prefix C:\Qt6_static -nomake examples -nomake tests -no-openssl -no-dbus -no-opengl -no-feature-sql -no-feature-vulkan -submodules qtbase
cmake --build . --parallel
cmake --install .
```

One could speed up building with [`jom`](https://wiki.qt.io/Jom), a replacement for `nmake` which makes use of all CPU cores.

To build Nito Core without Qt, unload or disable the `nito-qt`, `libnito_qt` and `test_nito-qt` projects.
This removes only the GUI. The daemon, Orchard consensus code and wallet RPCs
remain available.

For a native Windows AddressSanitizer validation build, keep incremental
linking disabled and pass the opt-in property to MSBuild:

```cmd
msbuild build_msvc\nito.sln /m /t:test_nito-qt /p:Configuration=Release /p:Platform=x64 /p:NitoEnableAddressSanitizer=true
set NITO_QT_TEST_SUITE=AppTests
build_msvc\x64\Release\test_nito-qt.exe
set NITO_QT_TEST_SUITE=WalletTests
build_msvc\x64\Release\test_nito-qt.exe
```

MSVC supports AddressSanitizer for x64 but does not provide ThreadSanitizer.
The Linux x86_64 and ARM64 sanitizer jobs run both
AddressSanitizer/UndefinedBehaviorSanitizer and ThreadSanitizer. The macOS job
runs AddressSanitizer/UndefinedBehaviorSanitizer; it does not currently cover
ThreadSanitizer. The native Windows job runs AddressSanitizer. The Windows
profile disables the MSVC standard-library string/vector annotations so the
instrumented Nito objects remain ABI-compatible with the pinned, uninstrumented
static Qt and vcpkg libraries; AddressSanitizer instrumentation of Nito code
remains enabled and is verified on the final test executable.

Building
---------------------
1. Use Python to generate `*.vcxproj` for the Visual Studio 2022 toolchain from Makefile:

```cmd
python build_msvc\msvc-autogen.py
```

2. An optional step is to adjust the settings in the `build_msvc` directory and the `common.init.vcxproj` file. This project file contains settings that are common to all projects such as the runtime library version and target Windows SDK version. The Qt directories can also be set. To specify a non-default path to a static Qt package directory, use the `QTBASEDIR` environment variable.

3. To build from the command-line with the Visual Studio toolchain use:

```cmd
msbuild build_msvc\nito.sln -property:Configuration=Release -maxCpuCount -verbosity:minimal
```

Alternatively, open the `build_msvc/nito.sln` file in Visual Studio.

For a command-line-only build, select the non-Qt targets explicitly:

```cmd
msbuild build_msvc\nito.sln -target:nitod;nito-cli;nito-tx;nito-wallet;nito-util -property:Configuration=Release -maxCpuCount -verbosity:minimal
```

An exchange requiring official Windows dependency parity should use the
[MinGW headless-wallet profile](../doc/nito/source-builds.md#windows-win64-cross-build)
instead of treating this MSVC build as the release artifact.

Security
---------------------
[Base address randomization](https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization)
is part of the Windows executable hardening. Keep it enabled when distributing
or using Nito Core binaries.

To check if `nitod` has `RandomizedBaseAddress` enabled or disabled run

```
dumpbin /headers build_msvc\x64\Release\nitod.exe
```

If is it enabled then in the output `Dynamic base` will be listed in the `DLL characteristics` under `OPTIONAL HEADER VALUES` as shown below

```
            8160 DLL characteristics
                   High Entropy Virtual Addresses
                   Dynamic base
                   NX compatible
                   Terminal Server Aware
```
