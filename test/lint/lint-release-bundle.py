# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Check deterministic selection and consolidation of binary license notices."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
OFFICIAL_MINISIGN_KEY_URL = (
    'https://nito.network/security/nito-core-release.pub')
SPEC = importlib.util.spec_from_file_location(
    'source_bundle', ROOT / 'contrib/release/source-bundle.py')
SOURCE_BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE_BUNDLE)


class ReleaseBundleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.licenses = self.root / 'licenses'

        files = {
            'depends/boost/boost/LICENSE_1_0.txt': 'Shared license text\n',
            'depends/boost/boost/LICENSE.xml': 'XML license notice\n',
            'depends/boost/boost/tools/licence_info.cpp': 'Source tool, not a notice\n',
            'depends/native_meson/meson/COPYING': 'Build tool only\n',
            'depends/qt/qt-src/LICENSES/LGPL-3.0-only.txt': 'Qt LGPL\n',
            'depends/qt/qt-src/qtbase/LICENSES/MIT.txt': 'QtBase notice\n',
            'depends/qt/qt-src/qtbase/src/qt_attribution.json':
                '[{"Name":"Bundled component","License":"MIT","LicenseFile":"LICENSE"}]\n',
            'depends/qt/qt-src/qttranslations/LICENSES/BSD.txt': 'Translation notice\n',
            'depends/qt/qt-src/qtwebengine/LICENSES/BSD.txt': 'WebEngine notice\n',
            'rust/example/LICENSE-MIT': 'Shared license text\n',
            'rust/example/Cargo.toml': 'license = "MIT"\n',
            'nito/COPYING': 'Project license is packaged separately\n',
            'nito/src/secp256k1/COPYING': 'Embedded source notice\n',
        }
        for name, content in files.items():
            path = self.licenses / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8')

    def tearDown(self):
        self.temporary.cleanup()

    def test_platform_notice_selection(self):
        linux = self.root / 'linux.txt'
        SOURCE_BUNDLE.write_binary_notices(
            self.licenses, {'boost', 'qt'}, 'linux', linux)
        text = linux.read_text(encoding='utf-8')

        self.assertIn('Qt LGPL', text)
        self.assertIn('QtBase notice', text)
        self.assertIn('XML license notice', text)
        self.assertIn('Bundled component', text)
        self.assertIn('Embedded source notice', text)
        self.assertNotIn('Build tool only', text)
        self.assertNotIn('Source tool, not a notice', text)
        self.assertNotIn('Translation notice', text)
        self.assertNotIn('WebEngine notice', text)
        self.assertNotIn('Project license is packaged separately', text)
        self.assertNotIn('license = "MIT"', text)
        self.assertEqual(text.count('Shared license text'), 1)

        repeated = self.root / 'linux-repeated.txt'
        SOURCE_BUNDLE.write_binary_notices(
            self.licenses, {'boost', 'qt'}, 'linux', repeated)
        self.assertEqual(linux.read_bytes(), repeated.read_bytes())

        macos = self.root / 'macos.txt'
        SOURCE_BUNDLE.write_binary_notices(
            self.licenses, {'boost', 'qt'}, 'macos', macos)
        self.assertIn('Translation notice', macos.read_text(encoding='utf-8'))

    def test_missing_component_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Missing'):
            SOURCE_BUNDLE.write_binary_notices(
                self.licenses, {'missing'}, 'linux', self.root / 'invalid.txt')


class ReleaseWorkflowContractTest(unittest.TestCase):
    def load_workflow(self):
        path = ROOT / '.github/workflows/build-release.yml'
        return path.read_text(encoding='utf-8')

    def test_binary_archive_contract(self):
        workflow = self.load_workflow()
        self.assertEqual(workflow.count('archive: false'), 8)
        self.assertEqual(workflow.count('skip-decompress: true'), 2)
        self.assertIn('for dmg_attempt in 1 2 3; do', workflow)
        self.assertIn('hdiutil create failed after 3 attempts.', workflow)
        self.assertNotIn('bin/licenses/index.json', workflow)
        self.assertNotIn('bin/COPYING', workflow)
        for platform in ('linux', 'windows', 'macos'):
            self.assertIn(
                'binary/' + platform + '/THIRD_PARTY_LICENSES.txt', workflow)

    def test_release_attestation_contract(self):
        workflow = self.load_workflow()
        attest_action = (
            'uses: actions/attest@'
            '1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2')
        official_attestation_condition = (
            "github.repository == 'NitoNetwork/Nito-core' && "
            "github.ref_type == 'tag' && "
            "needs.preflight.outputs.run_index == 'true' && "
            "needs.preflight.outputs.build_scope == 'all' && "
            "needs.preflight.outputs.target_linux_x86_64 == 'true' && "
            "needs.preflight.outputs.target_linux_aarch64 == 'true' && "
            "needs.preflight.outputs.target_windows == 'true' && "
            "needs.preflight.outputs.target_macos == 'true'")

        self.assertEqual(workflow.count(attest_action), 2)
        self.assertIn('id-token: write', workflow)
        self.assertIn('attestations: write', workflow)
        self.assertIn('artifact-metadata: write', workflow)
        self.assertIn(
            'ATTEST_PROVENANCE: ${{ ' +
            official_attestation_condition + ' }}', workflow)
        self.assertEqual(
            workflow.count(
                "if: env.RUN_INDEX == 'true' && "
                "env.ATTEST_PROVENANCE == 'true'"),
            2)
        self.assertIn(
            '--signer-workflow '
            '${GITHUB_REPOSITORY}/.github/workflows/build-release.yml',
            workflow)
        self.assertIn('--source-ref ${GITHUB_REF}', workflow)
        self.assertIn('validate_version "$VERSION"', workflow)
        self.assertIn('[ "${GITHUB_REF_TYPE}" = "tag" ]', workflow)
        self.assertIn('[ "${GITHUB_REF_NAME}" != "v${VERSION}" ]', workflow)
        self.assertIn('contrib/release/verify-release-tag.sh', workflow)
        self.assertIn('release_tag_object:', workflow)
        self.assertIn('release_tag_commit:', workflow)
        self.assertIn('Tag object: ${VERIFIED_TAG_OBJECT', workflow)
        self.assertIn('Tag target commit: ${VERIFIED_TAG_COMMIT', workflow)

        for relative_path in ('README.md', 'doc/release-process.md'):
            text = (ROOT / relative_path).read_text(encoding='utf-8')
            self.assertIn(
                '--signer-workflow '
                'NitoNetwork/Nito-core/.github/workflows/build-release.yml',
                text)
            self.assertIn('--source-ref refs/tags/vX.Y.Z', text)
            self.assertIn('--source-digest', text)

    def test_offline_minisign_contract(self):
        workflow = self.load_workflow()
        public_key = (
            ROOT / 'contrib/release/nito-core-release.pub').read_text(
                encoding='utf-8')
        allowed_signers = (
            ROOT / 'contrib/release/nito-core-tag-signers').read_text(
                encoding='utf-8')
        expected_key = (
            'untrusted comment: minisign public key D060C20B3417848D\n'
            'RWSNhBc0C8Jg0H6yw7+V3qiCv/k/7NZox9P9oIGV/veXmCUrI6Bmn9oJ\n')
        expected_signer = (
            'biigbang0001@users.noreply.github.com '
            'ssh-ed25519 '
            'AAAAC3NzaC1lZDI1NTE5AAAAIPVbUAqLwyYdK5fEdaz+J49ODGwXCEh04CiMg3nnwhkp\n')

        self.assertEqual(public_key, expected_key)
        self.assertEqual(allowed_signers, expected_signer)
        self.assertNotIn('NITO_RELEASE_SIGNING_KEY', workflow)
        self.assertNotIn('NITO_RELEASE_SIGNING_PASSWORD', workflow)
        self.assertNotIn('minisign -S', workflow)
        self.assertNotIn('release-artifacts/*.minisig', workflow)
        self.assertIn(
            'Minisign policy: SHA256SUMS.minisig is generated offline and '
            'is required before publication', workflow)

        for relative_path in (
                'README.md', 'doc/release-process.md',
                'doc/nito/testing-validation.md'):
            text = (ROOT / relative_path).read_text(encoding='utf-8')
            self.assertIn('D060C20B3417848D', text)
            self.assertIn('minisign -Vm', text)
            self.assertIn('Nito Core vX.Y.Z SHA256SUMS', text)
            self.assertIn(OFFICIAL_MINISIGN_KEY_URL, text)

    def test_public_release_asset_contract(self):
        workflow = self.load_workflow()
        publish_job = workflow.split('  publish-github-release:', 1)[1]
        official_publish_condition = (
            "github.repository == 'NitoNetwork/Nito-core' && "
            "github.ref_type == 'tag' && "
            "needs.preflight.outputs.run_index == 'true' && "
            "needs.preflight.outputs.build_scope == 'all' && "
            "needs.preflight.outputs.target_linux_x86_64 == 'true' && "
            "needs.preflight.outputs.target_linux_aarch64 == 'true' && "
            "needs.preflight.outputs.target_windows == 'true' && "
            "needs.preflight.outputs.target_macos == 'true' && "
            "needs.release-index.result == 'success'")

        self.assertIn('      - preflight', publish_job)
        self.assertIn(
            'if: ${{ ' + official_publish_condition + ' }}', publish_job)
        self.assertIn(
            'sha256sum $(cat public-artifacts.txt) > SHA256SUMS', workflow)
        self.assertIn(
            'nito-${VERSION}-sources.tar.gz" >> validated-artifacts.txt',
            workflow)
        self.assertIn('overwrite_files: false', workflow)
        self.assertIn('fail_on_unmatched_files: true', workflow)

        draft_files = workflow.split(
            '- name: Create unsigned draft release', 1)[1].split(
                'body_path:', 1)[0]
        expected_assets = (
            'x86_64-linux-gnu.tar.gz',
            'aarch64-linux-gnu.tar.gz',
            'win64.zip',
            'win64-setup.exe',
            'arm64-apple-darwin.tar.gz',
            'arm64-apple-darwin.dmg',
            'SHA256SUMS',
        )
        for asset in expected_assets:
            self.assertIn(asset, draft_files)
        for forbidden in (
                'sources.tar.gz', 'release-manifest.txt', '*.minisig',
                'diagnostics'):
            self.assertNotIn(forbidden, draft_files)


if __name__ == '__main__':
    unittest.main()
