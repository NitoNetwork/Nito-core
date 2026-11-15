# Release sources and third-party notices

Nito Core 4.0.0 binaries are published on the
[official release page](https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0).
The corresponding source revision is the annotated, signed `v4.0.0` tag, which
must display GitHub's **Verified** status. GitHub provides archives generated
from that tag. The [source-build guide](nito/source-builds.md) covers building
the exact tag or a later V4 maintenance revision.

Nito Core includes third-party software under its own licenses. The Nito Core
license in `COPYING` does not replace those licenses. Portable archives keep
`LICENSE.txt` and `THIRD_PARTY_LICENSES.txt` under their single top-level
`bin/` directory. The
release recipes record exact dependency versions, hashes, source locations and
patches. The release workflow can assemble a dependency-complete source bundle
with `source-manifest.json` and the detailed notice collection for source-tree
tools and optional components. The consolidated binary notice is generated from
the dependency closure for its release platform.

The graphical application uses Qt, copyright The Qt Company Ltd. and other
contributors, under the GNU Lesser General Public License version 3. The
applicable Qt and embedded third-party notices are included in
`THIRD_PARTY_LICENSES.txt`.
Berkeley DB and the other bundled libraries retain their respective licenses.

## Obtain the matching source

Clone the official repository and check out the signed tag, or download one of
GitHub's source archives from the **same release** as your binaries:

https://github.com/NitoNetwork/Nito-core/releases/tag/v4.0.0

Confirm that GitHub reports the tag as **Verified** and that it targets commit
`e3ff5e42b980c792ee5ab790610772a7d9ee8f8a`. The GitHub-generated archives
contain the tracked Nito Core source for that tag. They do not embed external
dependency archives or the complete Cargo registry.

For redistribution, use the release tooling described in
[release-process.md](release-process.md) to assemble the corresponding source
bundle. It contains:

- Nito Core source, build scripts and dependency patches from the release commit;
- checksum-verified dependency archives under `depends/sources/`, including Qt;
- the locked Rust dependencies under `src/private/orchard_ffi/vendor/`;
- license notices and a source manifest under `release-notices/`.

Keep that corresponding source available whenever redistributing the official
binaries. The source tooling downloads only the versions pinned by the signed
release source and verifies their recorded hashes.

## Build with modified libraries

Extract GitHub's source archive or check out the signed tag, then install the
compiler and platform build tools described in `doc/nito/source-builds.md` and
the appropriate `doc/build-*.md` guide. Platform SDKs and compiler toolchains
are installed separately. Use the Rust toolchain pinned in
`.github/workflows/build-release.yml`.

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
