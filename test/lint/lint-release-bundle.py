# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Check deterministic selection and consolidation of binary license notices."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
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
        official_tag_condition = (
            "github.repository == 'NitoNetwork/Nito-core' && "
            "github.ref_type == 'tag'")

        self.assertEqual(workflow.count(attest_action), 2)
        self.assertIn('id-token: write', workflow)
        self.assertIn('attestations: write', workflow)
        self.assertIn('artifact-metadata: write', workflow)
        self.assertIn(
            'ATTEST_PROVENANCE: ${{ ' + official_tag_condition + ' }}',
            workflow)
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

        for relative_path in ('README.md', 'doc/release-process.md'):
            text = (ROOT / relative_path).read_text(encoding='utf-8')
            self.assertIn(
                '--signer-workflow '
                'NitoNetwork/Nito-core/.github/workflows/build-release.yml',
                text)
            self.assertIn('--source-ref refs/tags/vX.Y.Z', text)


if __name__ == '__main__':
    unittest.main()
