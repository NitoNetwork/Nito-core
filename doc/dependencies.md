# Dependencies

These are the principal dependencies used to build Nito Core. Platform-specific
installation commands are documented in the matching `build-*.md` guide.

The `depends/` system pins release versions. Package recipes and
this summary must change together.

Release, exchange and custody builds should use `depends/` rather than system
libraries. This preserves the reviewed dependency set and Berkeley DB 4.8
compatibility. System-library builds remain useful for development, but they
are not release-parity builds.

Official Linux x86_64, Linux aarch64, Windows win64 and macOS arm64 builds use
the same `depends/` recipes and SHA-256-verified source archives for every
library shared by those targets. Platform-specific libraries are included only
where the operating system requires them. Native package managers provide
bootstrap tools, not libraries in the Nito link closure. On macOS, the Qt
Linguist host tool and matching QtBase translations come from the same pinned
Qt source as the target libraries. The release workflow rejects macOS binaries
that retain Homebrew or build-prefix library paths.

## Toolchain

| Dependency | Requirement or release selection |
| --- | --- |
| Autoconf | 2.69 |
| Automake | 1.13 |
| Clang | 14.0 |
| GCC | 10.1 |
| Python | 3.9 |
| Rust | 1.97.0, pinned by the release workflow |
| systemtap | Optional, for tracing |

Cross-builds also require the matching Rust target. Linux aarch64 uses
`aarch64-unknown-linux-gnu` with `aarch64-linux-gnu-gcc`; MinGW uses
`x86_64-pc-windows-gnu` with `x86_64-w64-mingw32-gcc`. See the
[source-build guide](nito/source-builds.md) for complete commands.

## Core Libraries

| Dependency | Release-build version | Minimum required | Runtime |
| --- | --- | --- | --- |
| Boost | 1.81.0 | 1.73.0 | No |
| libevent | 2.1.13-stable | 2.1.8 | No |
| glibc | Platform-provided | 2.27 | Yes |
| Linux kernel | Platform-provided | 3.17.0 | Yes |

## Wallet

| Dependency | Release-build version | Minimum required | Runtime |
| --- | --- | --- | --- |
| Berkeley DB | 4.8.30 | 4.8.x | No |
| SQLite | 3.38.5 | 3.7.17 | No |

Berkeley DB 4.8.30 is retained to open supported v3 legacy wallet files. Do not
replace it with an ABI-incompatible Berkeley DB release in official binaries.
The bundled patches also clear entire newly allocated database pages so reused
cache buffers cannot disclose previous page contents in unused file space.
Use the patched dependency, including for native MSVC builds via the supplied
vcpkg overlay; an unpatched system library does not provide this protection.

## Qt And Desktop

| Dependency | Release-build version | Minimum required | Runtime |
| --- | --- | --- | --- |
| Qt | 6.8.4 | 6.2.0 | No |
| Fontconfig | 2.18.2 | 2.6 | No |
| FreeType | 2.14.3 | 2.3.0 | No |
| Expat | 2.8.5 | Package default | No |
| libxcb | 1.17.0 | Package default | No |
| xcb-proto | 1.17.0 | Package default | No |
| libXau | 1.0.12 | Package default | No |
| libxkbcommon | 1.13.2 | Package default | No |
| qrencode | 4.1.1 | Package default | No |

Release Qt is static. The Linux recipe disables host ICU, GSSAPI and Xlib
autodetection while retaining XCB, xkbcommon-x11, qxcb, qminimal and qoffscreen.
This constrains the library dependency set and prevents accidental dependencies
on runner libraries. Fontconfig and FreeType are linked statically; Linux still
needs usable system fonts and Fontconfig configuration at runtime. Pinned
sources alone do not establish byte-for-byte build reproducibility.

The Qt 6.8.4 recipes include backports of the upstream fixes for
CVE-2026-78253 (XML stream recursion), CVE-2026-76151 (network header offsets)
and CVE-2026-19248 (DOM destruction recursion). Each patch records its upstream
commit; both target libraries and native Qt build tools receive these fixes.
An unpatched Qt 6.8.4 installation is not equivalent to the release dependency.

## Networking And Notifications

| Dependency | Release-build version | Minimum required | Runtime |
| --- | --- | --- | --- |
| libnatpmp | Commit pinned in `depends/packages/libnatpmp.mk` | Package default | No |
| MiniUPnPc | 2.2.2 | 2.1 | No |
| ZeroMQ | 4.3.5 | 4.0.0 | No |

## Orchard Rust Baseline

| Dependency | Release-build version |
| --- | --- |
| orchard | 0.15.0 |
| halo2_gadgets | 0.5.0 |
| zcash_note_encryption | 0.4.1 |
| incrementalmerkletree | 0.8.2 |

Cargo builds with `--locked`. Nito selects Orchard V2 and the fixed post-NU6.2
circuit explicitly; dependency defaults cannot change the consensus version.
