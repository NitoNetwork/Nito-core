# Release Process

This page describes the public Nito Core release process at a high level. The
platform build workflow is `.github/workflows/build-release.yml`.

## Before A Release Candidate

1. Freeze the intended release version in `configure.ac`.
2. Confirm the mainnet private activation height in
   `src/kernel/chainparams.cpp` and update the Nito v4 docs if it changes.
3. Update translations and regenerated man pages when user-facing strings or
   command help changed.
4. Regenerate `nito.conf` examples if configuration options changed.
5. Update [release-notes.md](release-notes.md) with user-facing changes,
   operator notes and any security or privacy information users must know.
6. Run the relevant unit, functional and workflow-equivalent checks for the
   surfaces changed by the release.

## Release Build

Nito Core release artifacts are built from the manual GitHub Actions workflow
`.github/workflows/build-release.yml`.

Before publishing artifacts:

- verify the workflow is running from the intended commit;
- create an annotated, cryptographically signed release tag targeting that
  exact commit and confirm that GitHub reports it as **Verified**;
- verify Linux x86_64, Linux aarch64, Windows and macOS artifacts;
- verify checksums and artifact names;
- verify Qt artifacts when the release includes GUI binaries;
- keep debug artifacts separate from end-user downloads;
- keep the corresponding source available as described in
  [release-sources.md](release-sources.md);
- verify the license notices in each portable archive, installer and app bundle.

Run the final wallet and network checks against executables extracted from the
archives being distributed. Record the archive checksums, source commit and
test results together. Include V3 wallet migration, both PSBT wallet formats,
Orchard sends and recovery, pruning, activation gating and Signet validation.
Reuse relevant tests already completed on the same code; changes limited to
documentation or notices require renewed package verification, rather than a
repeat of unrelated consensus tests.

Check the installer payload against the portable Windows executables. GNU
`strip` may produce different PE timestamps and checksums when the same
executable is packaged twice; executable code and other content must agree.
On macOS, verify and mount the final DMG and check the app, notices and Qt
translation catalogs. Distinguish native execution from emulated checks in
the validation record.

The workflow packages the pinned dependency sources and locked Rust crates with
the Nito source from the same commit. This common source archive and its checksum
are required by the release index. Portable binary archives have a single
top-level `bin/` directory; `bin/LICENSE.txt` and
`bin/THIRD_PARTY_LICENSES.txt` preserve the applicable notices. The source
manifest stays in the matching source archive. See
[release-sources.md](release-sources.md) for source access, rebuilding and
redistribution instructions. Do not replace this archive with GitHub's automatic
source download, which omits dependencies.

For manual release packaging on Linux, prepare the same inputs from a clean,
committed checkout before creating installers:

```bash
make -C depends HOST=x86_64-pc-linux-gnu download-one
cargo fetch --locked --manifest-path src/private/orchard_ffi/Cargo.toml
python3 contrib/release/source-bundle.py --version 4.0.1 --output source-release
mkdir -p release
mkdir -p release/bin
tar -xOf source-release/release-notices.tar.gz COPYING > release/bin/LICENSE.txt
tar -xOf source-release/release-notices.tar.gz \
  binary/linux/THIRD_PARTY_LICENSES.txt > release/bin/THIRD_PARTY_LICENSES.txt
```

Use the intended release version in the command. Package only `bin/` at the
archive root, with `LICENSE.txt` and `THIRD_PARTY_LICENSES.txt` directly inside
it. Keep `SOURCE.md` and `source-manifest.json` in the matching source archive.
The Windows installer and macOS application use the platform-specific
consolidated notice generated in `release-notices/binary/`.

The workflow uploads each final `.zip`, `.tar.gz`, installer and DMG as a raw
artifact. A download from the GitHub Actions artifact panel is therefore the
final file itself rather than an additional ZIP wrapper. Complete tagged builds
also attach these files directly to the draft GitHub Release.

The workflow release index contains `SHA256SUMS` and
`release-manifest.txt`. The public GitHub Release attaches the approved platform
packages and `SHA256SUMS`; workflow manifests and source-packaging artifacts are
kept as build evidence rather than duplicated as end-user downloads. GitHub
provides source archives generated from the signed tag.

To enable optional signing, configure both repository Actions secrets:

- `NITO_RELEASE_SIGNING_KEY`: the complete encrypted Minisign secret-key file;
- `NITO_RELEASE_SIGNING_PASSWORD`: the password for that key.

When both are present, the index job creates `SHA256SUMS.minisig` and
`release-manifest.txt.minisig`; publish the checksum signature with the release.
If either secret is absent, signing is skipped cleanly and `SHA256SUMS` remains
explicitly unsigned. The Minisign public key must be distributed through an
independent authenticated channel, such as the official website and a
separately controlled announcement; publishing it only in the same GitHub
Release does not establish authenticity.

The macOS packaging step signs the stripped executables with ad-hoc signatures
and launches the command-line tools extracted from the final archive. It also
re-signs `Nito-Qt.app` after the license notices are added, verifies its sealed
resources, and repeats that verification on the app mounted from the final DMG.
These signatures preserve executable integrity; they do not authenticate a
publisher through Apple Developer ID or provide notarization. Native macOS Qt
tests use the Cocoa platform so the application and wallet suites actually run.

## Release Notes

Release notes should be written for node operators and wallet users first.
They should include:

- the exact version and commit being released;
- activation-height changes, if any;
- wallet, RPC, Qt and mining compatibility changes;
- security or privacy limitations that users must understand;
- checksum and artifact verification instructions.

Historical Nito release notes are archived under
[release-notes/](release-notes/).

## Tagging And Publication

1. Build and qualify the reviewed release commit, recording its complete SHA.
   New release-preparation commits created by maintainers should themselves be
   signed and verified; historical commits are not rewritten just to add a
   signature.
2. Create an annotated tag signed with the dedicated release-signing key and
   targeting that exact SHA. New public releases must never use lightweight
   tags.
3. Push the new tag without force. Confirm through GitHub that the ref resolves
   to a tag object, its signature is valid and **Verified**, and its target is
   the qualified commit. The tag-object SHA is expected to differ from the
   target commit SHA.
4. Publish the approved platform packages and `SHA256SUMS`, plus the checksum's
   Minisign signature when signing is configured.
5. Publish release notes with the exact commit, workflow provenance, signed-tag
   status and a clear upgrade path.
6. Reinspect the published asset names, sizes and checksums, and keep the
   release branch and documentation aligned after any hotfix.

Replacing a published tag is an exceptional, destructive operation. It requires
explicit authorization and must preserve the qualified target commit unless a
new build and release qualification are performed. Reverify the tag signature,
release metadata and every attached asset afterward.

The private release-signing key and its passphrase must remain outside the
repository and GitHub Actions. A signed tag authenticates the source tag and its
target commit; it does not sign attached binaries. Users must still verify each
download against `SHA256SUMS`, and unsigned checksum indexes must remain clearly
identified as unsigned.
