# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Exercise the fail-closed signed release-tag verifier."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / 'contrib/release/verify-release-tag.sh'


class ReleaseTagVerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for command in ('git', 'ssh-keygen'):
            if shutil.which(command) is None:
                raise unittest.SkipTest(f'{command} is required')
        if os.name == 'nt':
            git_path = Path(shutil.which('git')).resolve()
            bash_path = git_path.parents[1] / 'bin' / 'bash.exe'
            if not bash_path.is_file():
                raise unittest.SkipTest('Git Bash is required')
            cls.bash = str(bash_path)
        else:
            cls.bash = shutil.which('bash')
            if cls.bash is None:
                raise unittest.SkipTest('bash is required')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.signer = self.repo / 'release_signer'
        self.other_signer = self.repo / 'other_signer'
        self.allowed_signers = self.repo / 'allowed_signers'

        self.run_command('git', 'init', '--quiet')
        self.run_command('git', 'config', 'user.name', 'Nito Release Test')
        self.run_command('git', 'config', 'user.email', 'release-test@example.invalid')
        self.run_command('git', 'config', 'commit.gpgsign', 'false')
        (self.repo / 'payload.txt').write_text('first\n', encoding='utf-8')
        self.run_command('git', 'add', 'payload.txt')
        self.run_command('git', 'commit', '--quiet', '-m', 'Initial release payload')

        self.generate_key(self.signer)
        self.generate_key(self.other_signer)
        public_key = self.signer.with_suffix('.pub').read_text(
            encoding='utf-8').strip()
        self.allowed_signers.write_text(
            f'release-test@example.invalid {public_key}\n', encoding='utf-8')
        self.run_command('git', 'config', 'gpg.format', 'ssh')
        self.run_command('git', 'config', 'user.signingkey', str(self.signer))

    def tearDown(self):
        self.temporary.cleanup()

    def run_command(self, *command, check=True, env=None):
        return subprocess.run(
            command,
            cwd=self.repo,
            env=env,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def generate_key(self, path):
        self.run_command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path))

    def verify(self, tag, version, expected_commit='HEAD', allowed_signers=None,
               check=True, env=None):
        return self.run_command(
            self.bash, VERIFIER.as_posix(), tag, version, expected_commit,
            Path(allowed_signers or self.allowed_signers).as_posix(),
            check=check, env=env)

    def test_valid_signed_annotated_tag(self):
        self.run_command('git', 'tag', '-s', 'v1.2.3', '-m', 'Nito Core v1.2.3')
        github_output = self.repo / 'github-output.txt'
        environment = os.environ.copy()
        environment['GITHUB_OUTPUT'] = github_output.as_posix()

        result = self.verify('v1.2.3', '1.2.3', env=environment)

        self.assertIn('Verified annotated release tag v1.2.3', result.stdout)
        outputs = github_output.read_text(encoding='utf-8')
        self.assertRegex(outputs, r'(?m)^tag_object=[0-9a-f]{40,64}$')
        self.assertRegex(outputs, r'(?m)^tag_commit=[0-9a-f]{40,64}$')

    def test_lightweight_tag_is_rejected(self):
        self.run_command('git', 'tag', 'v1.2.3')
        result = self.verify('v1.2.3', '1.2.3', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must be an annotated tag object', result.stdout)

    def test_unsigned_annotated_tag_is_rejected(self):
        self.run_command('git', 'tag', '-a', 'v1.2.3', '-m', 'Unsigned tag')
        result = self.verify('v1.2.3', '1.2.3', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unsigned or was signed by an unexpected key', result.stdout)

    def test_unexpected_signer_is_rejected(self):
        self.run_command('git', 'config', 'user.signingkey', str(self.other_signer))
        self.run_command('git', 'tag', '-s', 'v1.2.3', '-m', 'Wrong signer')
        result = self.verify('v1.2.3', '1.2.3', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unexpected key', result.stdout)

    def test_version_mismatch_is_rejected(self):
        self.run_command('git', 'tag', '-s', 'v1.2.3', '-m', 'Nito Core v1.2.3')
        result = self.verify('v1.2.3', '1.2.4', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('does not match version', result.stdout)

    def test_wrong_target_is_rejected(self):
        self.run_command('git', 'tag', '-s', 'v1.2.3', '-m', 'Nito Core v1.2.3')
        (self.repo / 'payload.txt').write_text('second\n', encoding='utf-8')
        self.run_command('git', 'add', 'payload.txt')
        self.run_command('git', 'commit', '--quiet', '-m', 'Later payload')

        result = self.verify('v1.2.3', '1.2.3', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('targets', result.stdout)
        self.assertIn('expected', result.stdout)


if __name__ == '__main__':
    unittest.main()
