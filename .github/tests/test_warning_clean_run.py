#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the warning gate, including an actual failure to write its log."""

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest

if os.name == "posix":
    import resource


@unittest.skipUnless(os.name == "posix", "The Bash warning gate runs on POSIX hosts")
class WarningCleanRunTest(unittest.TestCase):
    def run_gate(self, command, *, limit_log=False):
        wrapper = Path(__file__).resolve().parents[1] / "scripts/warning-clean-run.sh"

        def limit_child_log():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))
            signal.signal(signal.SIGXFSZ, signal.SIG_DFL)

        with tempfile.TemporaryDirectory(prefix="nito-warning-gate-") as directory:
            log = Path(directory) / "build.log"
            child = subprocess.run(
                ["bash", str(wrapper), "bash", "-c", command],
                env={**os.environ, "WARNING_CLEAN_LOG": str(log)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=limit_child_log if limit_log else None,
                timeout=15,
            )
            return child, log.read_bytes()

    def test_clean_output_passes(self):
        child, log = self.run_gate("printf 'build complete\\n'")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(log, b"build complete\n")

    def test_warning_fails(self):
        child, log = self.run_gate("printf '\\033[33mwarning:\\033[0m diagnostic\\n'")
        self.assertNotEqual(child.returncode, 0)
        self.assertIn(b"diagnostic", log)

    def test_command_failure_is_preserved(self):
        child, _ = self.run_gate("printf 'failed\\n'; exit 7")
        self.assertEqual(child.returncode, 7)

    def test_truncated_log_fails(self):
        # A single write fits in the pipe but exceeds the log file limit. The
        # command succeeds while tee loses the diagnostic at the end.
        child, log = self.run_gate(
            "printf '%02000d\\nwarning: truncated diagnostic\\n' 0", limit_log=True
        )
        self.assertEqual(len(log), 1024)
        self.assertNotIn(b"warning:", log)
        self.assertNotEqual(child.returncode, 0, child.stderr)
        self.assertIn(b"Incomplete build log", child.stderr)

    def test_command_failure_takes_priority_over_log_failure(self):
        child, log = self.run_gate("printf '%02000d\\n' 0; exit 7", limit_log=True)
        self.assertEqual(len(log), 1024)
        self.assertEqual(child.returncode, 7, child.stderr)


if __name__ == "__main__":
    unittest.main()
