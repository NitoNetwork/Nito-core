# Release sources and third-party notices

Nito Core 4.0.0 binaries and their corresponding source bundle are published
on the [official release page](https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0).
The [source-build guide](nito/source-builds.md) covers building the exact tag or
a later V4 maintenance revision. The archive and redistribution instructions
below apply to the official packages.

Nito Core includes third-party software under its own licenses. The Nito Core
license in `COPYING` does not replace those licenses. Portable archives keep
`LICENSE.txt` and `THIRD_PARTY_LICENSES.txt` under their single top-level
`bin/` directory. The
matching source archive contains `source-manifest.json`, which identifies the
release commit, dependency versions and source archive checksums.
The detailed notice collection in the source archive also covers source-tree
tools and optional components. The consolidated binary notice is generated
from the dependency closure for its release platform.

The graphical application uses Qt, copyright The Qt Company Ltd. and other
contributors, under the GNU Lesser General Public License version 3. The
applicable Qt and embedded third-party notices are included in
`THIRD_PARTY_LICENSES.txt`.
Berkeley DB and the other bundled libraries retain their respective licenses.

## Obtain the matching source

Download `nito-4.0.0-sources.tar.gz` from the **same release** as your binaries:

https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0

Verify the archive against that release's `SHA256SUMS`. The source archive
contains:

- Nito Core source, build scripts and dependency patches from the release commit;
- checksum-verified dependency archives under `depends/sources/`, including Qt;
- the locked Rust dependencies under `src/private/orchard_ffi/vendor/`;
- license notices and a source manifest under `release-notices/`.

This archive accompanies the binaries without an additional charge. Keep it
available whenever redistributing the corresponding binaries. GitHub's
automatically generated source archives do not include the external dependency
archives or vendored Rust crates.

## Build with modified libraries

Extract the source archive and install the compiler and platform build tools
described in `doc/nito/source-builds.md` and the appropriate `doc/build-*.md`
guide. Platform SDKs and compiler toolchains are installed separately. Use the
Rust toolchain pinned in `.github/workflows/build-release.yml`.

Run builds from the extracted source tree so Cargo discovers the included
`.cargo/config.toml`. The vendor configuration supplies the locked Rust crate
sources without contacting the registry. The dependency source archives are
already in the location used by `depends/`.

To change a library such as Qt, add your change as a patch under
`depends/patches/qt/` and list it in `depends/packages/qt.mk`. Then build using
the platform instructions. Changes to the recipes or listed patches invalidate
the dependency cache. Rebuild Nito Core to link your modified library into the
application; replacing a shared library beside the official executable is not
sufficient because the release libraries are linked statically. The workflow
records the release configuration for Linux x86_64, Linux aarch64, Windows
MinGW and macOS arm64. The full application source is provided for rebuilding
and relinking; modification and reverse engineering to debug modifications to
the LGPL-covered library are permitted by its license.

Install a rebuilt application by extracting its portable archive to a new
directory and running the executable under `bin/`. On macOS, run the rebuilt
application bundle or command-line binaries; the release build scripts apply
ad-hoc signatures and require no publisher signing key. Stop the existing node
before using the same data directory. Test modifications with a separate
`-datadir` on regtest first, and preserve wallet backups before replacing a
wallet application. No Nito-controlled activation key or device restriction
is required to run a modified build.

## Redistributors

Preserve `bin/LICENSE.txt` and `bin/THIRD_PARTY_LICENSES.txt` with portable binaries. Keep
`SOURCE.md` and `source-manifest.json` in the matching source archive. The
Windows installer places the notices in its installation directory; the macOS
application includes them under `Contents/Resources/`. Publish the
matching source archive beside the binaries and include it in the release
checksums. Consult each dependency's license for its conditions; this document
does not relicense third-party code.
