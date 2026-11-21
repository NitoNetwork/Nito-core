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
- retain the matching `nito-VERSION-sources.tar.gz` and its manifest as workflow
  evidence rather than attaching them to the public GitHub Release, and keep
  public source access documented in [release-sources.md](release-sources.md);
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
are retained as internal workflow evidence. They are validated with the release
but are not entries in the public `SHA256SUMS` or public GitHub Release.
Portable binary archives have a single top-level `bin/` directory;
`bin/LICENSE.txt` and `bin/THIRD_PARTY_LICENSES.txt` preserve the applicable
notices. The source manifest stays in the matching source archive. See
[release-sources.md](release-sources.md) for source access, rebuilding and
redistribution instructions. Do not replace this archive with GitHub's automatic
source download, which omits dependencies.

For manual release packaging on Linux, prepare the same inputs from a clean,
committed checkout before creating installers:

```bash
make -C depends HOST=x86_64-pc-linux-gnu download-one
cargo fetch --locked --manifest-path src/private/orchard_ffi/Cargo.toml
python3 contrib/release/source-bundle.py --version X.Y.Z --output source-release
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

The release-index artifact contains the final public `SHA256SUMS` and the
internal `release-manifest.txt`. The public draft GitHub Release attaches only
the six approved platform packages and `SHA256SUMS`; the detailed source bundle
and manifest remain workflow evidence. GitHub provides source archives generated
from the signed tag.

The workflow never receives a Minisign private key or passphrase. After package,
checksum, signed-tag and provenance qualification, the maintainer signs the
unchanged `SHA256SUMS` locally. On Windows PowerShell:

```powershell
minisign -S `
  -s "$env:USERPROFILE\.nito-signing\minisign\nito-core-release.key" `
  -m SHA256SUMS `
  -x SHA256SUMS.minisig `
  -t "Nito Core vX.Y.Z SHA256SUMS"

minisign -Vm SHA256SUMS `
  -x SHA256SUMS.minisig `
  -p contrib\release\nito-core-release.pub
```

The expected public-key ID is `D060C20B3417848D`; the canonical repository
copy is [`contrib/release/nito-core-release.pub`](../contrib/release/nito-core-release.pub).
Only `SHA256SUMS.minisig` is uploaded to the draft after it verifies. Never put
the private key or passphrase in Git, GitHub Actions, command arguments,
environment variables, logs or messages. If any package or `SHA256SUMS` changes,
discard the detached signature and repeat qualification and signing.

The same public key and ID are independently published as the
[official Nito.network public key](https://nito.network/security/nito-core-release.pub).
Immediately before publication, require that URL to return HTTP `200` with the
`text/plain` media type (parameters such as `charset` are permitted) and that
its response bytes exactly match
`contrib/release/nito-core-release.pub`. Stop publication if the independent
copy is unavailable or differs. Publishing the key only in the repository or
the GitHub Release does not establish an independent authentication path.

For official tagged builds in `NitoNetwork/Nito-core`, the index job also
creates GitHub build provenance attestations, with no keys or secrets to
manage: one for every file listed in `SHA256SUMS`, and one each for
`SHA256SUMS` and `release-manifest.txt`. Each attestation is signed through
Sigstore and records the repository, workflow, commit, ref and run that built
the file. Constrain verification to the release workflow and signed tag:

```bash
gh attestation verify nito-X.Y.Z-x86_64-linux-gnu.tar.gz \
  --repo NitoNetwork/Nito-core \
  --signer-workflow NitoNetwork/Nito-core/.github/workflows/build-release.yml \
  --source-ref refs/tags/vX.Y.Z \
  --source-digest FULL_SIGNED_TAG_TARGET_SHA
```

Replace `X.Y.Z` with the release version. Changed bytes, or the absence of an
attestation matching the repository, workflow and tag, fail this check. Compare
the reported source commit with `FULL_SIGNED_TAG_TARGET_SHA`, obtained by
independently verifying and peeling the signed annotated tag.
Attestations prove provenance, not reproducibility or maintainer approval; they
do not replace the signed tag or the Minisign signature.

### Reproducible-build roadmap

The inherited `contrib/guix/` tooling is not yet a qualified Nito Core v4
release path. A separate reproducible-build phase must integrate the pinned
Rust/Orchard dependency closure and reproduce Nito's actual platform packaging,
including consolidated license notices, the Windows NSIS installer, and the
macOS application/archive/DMG outputs. Toolchains and build inputs must remain
pinned, and any unavoidable platform-signing transformation must be documented
outside the byte-for-byte comparison boundary.

Do not describe a release as reproducible until at least two independent
builders have produced byte-identical applicable release payloads and published
independently signed attestations that agree on those hashes. GitHub provenance,
the signed release tag and Minisign remain mandatory while this roadmap is
implemented; none of them alone establishes reproducibility.

Start the final release build from the signed release tag with GitHub CLI or the
GitHub API. The web interface's **Use workflow from** selector is for branches.
For GitHub CLI, use matching tag and version values:

```bash
gh workflow run build-release.yml \
  --repo NitoNetwork/Nito-core \
  --ref vX.Y.Z \
  -f version=X.Y.Z \
  -f targets=all \
  -f stages=all \
  -f build_scope=all
```

The preflight rejects a tagged build when the tag and version differ. A valid
tagged run records the tag in each attestation, and the
`publish-github-release` job attaches the six platform packages and the final
`SHA256SUMS` to an unpublished draft GitHub Release. The checksum file is then
downloaded, verified, signed locally and returned as `SHA256SUMS.minisig`; the
draft must not be published before that signature is independently verified and
attached.

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
   target commit SHA. The public workflow independently repeats these checks
   with `contrib/release/verify-release-tag.sh` and the pinned SSH identity in
   `contrib/release/nito-core-tag-signers`; it fails before building provenance
   for a lightweight, unsigned, unexpectedly signed or mistargeted tag.
4. Run the release workflow from the signed tag and review the draft GitHub
   Release it creates. Confirm that constrained attestation verification passes
   for every package and `SHA256SUMS` and reports the signed tag's target commit.
5. Freeze the verified `SHA256SUMS`, have the maintainer sign it locally, verify
   `SHA256SUMS.minisig` against key `D060C20B3417848D`, and attach the signature
   without replacing any existing package or checksum asset.
6. Recheck the signed tag and exact public asset allowlist, then publish only
   after explicit authorization. The public assets are the six platform
   packages, `SHA256SUMS` and `SHA256SUMS.minisig`.
7. Publish release notes with the exact commit, workflow provenance, signed-tag
   status and a clear upgrade path.
8. Reinspect the published asset names, sizes and checksums, and keep the
   release branch and documentation aligned after any hotfix.

Replacing a published tag is an exceptional, destructive operation. It requires
explicit authorization and must preserve the qualified target commit unless a
new build and release qualification are performed. Reverify the tag signature,
release metadata and every attached asset afterward.

Both private signing keys and their passphrases must remain outside the
repository and GitHub Actions. The SSH key signs commits and annotated tags;
the separate Minisign key signs only the final public `SHA256SUMS`. A signed tag
authenticates the source tag and target commit but not attached binaries. Every
future public release must therefore include the verified
`SHA256SUMS.minisig`; validation builds may remain explicitly unpublished and
unsigned.
