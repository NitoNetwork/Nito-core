# Release sources and third-party notices

Nito Core includes third-party software under its own licenses. The Nito Core
license in `COPYING` does not replace those licenses. Portable archives keep
`LICENSE.txt` and `THIRD_PARTY_LICENSES.txt` under their single top-level
`bin/` directory. The release workflow also produces an internal
corresponding-source bundle with a `source-manifest.json` identifying the
release commit, dependency versions and source archive checksums. That detailed
bundle is retained as workflow evidence rather than attached to the public
GitHub Release. Its notice collection also covers source-tree tools and optional
components. The consolidated binary notice is generated from the dependency
closure for its release platform.

The graphical application uses Qt, copyright The Qt Company Ltd. and other
contributors, under the GNU Lesser General Public License version 3. The
applicable Qt and embedded third-party notices are included in
`THIRD_PARTY_LICENSES.txt`.
Berkeley DB and the other bundled libraries retain their respective licenses.

## Obtain the matching source

Use GitHub's source archive for the signed release tag:

https://github.com/NitoNetwork/Nito-core/releases

The tag must resolve to the verified signed release commit. The repository
contains the pinned dependency recipes, checksums, patches, Cargo lockfile and
source-bundle tooling. To assemble the more detailed corresponding-source
bundle used as workflow evidence, run the documented release-source steps from
that exact tag. The generated bundle contains:

- Nito Core source, build scripts and dependency patches from the release commit;
- checksum-verified dependency archives under `depends/sources/`, including Qt;
- the locked Rust dependencies under `src/private/orchard_ffi/vendor/`;
- license notices and a source manifest under `release-notices/`.

GitHub's automatically generated source archives do not include external
dependency archives or vendored Rust crates. The pinned recipes download and
verify those sources, and `contrib/release/source-bundle.py` packages them for
offline rebuilding and redistribution.

## Build with modified libraries

Check out the exact verified release tag and install the compiler and platform
build tools described in `doc/nito/source-builds.md` and the appropriate
`doc/build-*.md` guide. Platform SDKs and compiler toolchains are installed
separately. Use the Rust toolchain pinned in
`.github/workflows/build-release.yml`. The pinned Depends recipes and Cargo lock
file retrieve and verify the corresponding dependency sources. To prepare the
same offline corresponding-source bundle retained by the workflow, run the
commands documented in [release-process.md](release-process.md#release-build).

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

Preserve `bin/LICENSE.txt` and `bin/THIRD_PARTY_LICENSES.txt` with portable
binaries. Generate and keep `SOURCE.md` and `source-manifest.json` in the
matching corresponding-source bundle. The Windows installer places the notices
in its installation directory; the macOS application includes them under
`Contents/Resources/`. Publish the matching corresponding source through a
durable channel when redistributing the binaries. Do not add it to Nito Core's
official public Release asset list or `SHA256SUMS`; that list is reserved for
the six platform packages, `SHA256SUMS` and `SHA256SUMS.minisig`. Consult each
dependency's license for its conditions; this document does not relicense
third-party code.
