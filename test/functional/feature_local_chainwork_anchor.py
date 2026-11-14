#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the local chainwork anti-rollback anchor.

The release-time nMinimumChainWork/defaultAssumeValid values are intentionally
static, but each datadir also records the strongest chainwork it has already
seen. A later restart must not silently accept a weaker local chainstate.
"""

import os
import signal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


class LocalChainworkAnchorTest(NitoTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-localchainworkanchor=1"]]

    def run_test(self):
        node = self.nodes[0]
        anchor_path = node.chain_path / "local-chainwork-anchor"

        self.log.info("Generate blocks, flush cleanly, and verify the durable anchor")
        self.generate(node, 3)
        info = node.getblockchaininfo()
        self.restart_node(0, self.extra_args[0])
        node = self.nodes[0]
        assert anchor_path.exists()

        best_header = node.getblockheader(info["bestblockhash"])
        assert_equal(best_header["chainwork"], info["chainwork"])

        self.log.info("Crash after advancing the in-memory tip; the anchor must not outrun durable chainstate")
        self.generate(node, 2)
        node.process.kill()
        expected_ret_code = 1 if os.name == "nt" else -signal.SIGKILL
        self.wait_until(
            lambda: node.is_node_stopped(expected_ret_code=expected_ret_code),
            timeout=30,
        )
        self.start_node(0, self.extra_args[0])
        node = self.nodes[0]
        assert node.getblockcount() >= info["blocks"]

        info = node.getblockchaininfo()
        best_header = node.getblockheader(info["bestblockhash"])

        self.log.info("Forge a stronger local anchor and verify restart is refused")
        self.stop_node(0)
        stronger_work = int(info["chainwork"], 16) + 1
        anchor_path.write_text(
            "# Nito local anti-rollback chainwork anchor v1\n"
            "# Test-forged anchor that is stronger than the local chain tip.\n"
            f"height={info['blocks'] + 1}\n"
            f"blockhash={info['bestblockhash']}\n"
            f"chainwork={stronger_work:064x}\n"
            f"time={best_header['time']}\n",
            encoding="utf-8",
        )

        node.assert_start_raises_init_error(extra_args=self.extra_args[0])
        debug_log = node.debug_log_path.read_text(encoding="utf-8", errors="replace")
        assert "Local anti-rollback anchor refuses chain tip" in debug_log

        self.log.info("Delete the local anchor explicitly and verify restart is allowed")
        anchor_path.unlink()
        self.start_node(0, self.extra_args[0])
        assert anchor_path.exists()
        assert_equal(node.getblockcount(), info["blocks"])


if __name__ == "__main__":
    LocalChainworkAnchorTest().main()
