#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Nito default indexes for full and pruned nodes."""

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


class IndexDefaultsTest(NitoTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            [],
            ["-prune=550"],
            ["-txindex=0", "-coinstatsindex=0", "-orchardindex=0", "-transparenthistoryindex=0"],
        ]

    def assert_synced_index(self, node, index_name):
        self.wait_until(lambda: node.getindexinfo().get(index_name, {}).get("synced") is True)

    def assert_indexes_absent(self, node, index_names):
        index_info = node.getindexinfo()
        for index_name in index_names:
            assert index_name not in index_info

    def run_test(self):
        self.log.info("Full nodes enable txindex, orchardindex and transparenthistoryindex by default")
        full_node = self.nodes[0]
        for index_name in ("txindex", "orchardindex", "transparenthistoryindex"):
            self.assert_synced_index(full_node, index_name)

        full_indexes = full_node.getindexinfo()
        assert_equal(full_indexes["txindex"]["synced"], True)
        assert_equal(full_indexes["orchardindex"]["synced"], True)
        assert_equal(full_indexes["transparenthistoryindex"]["synced"], True)
        assert "coinstatsindex" not in full_indexes

        index_dir = full_node.chain_path / "indexes"
        assert (index_dir / "orchardindex").is_dir()
        assert (index_dir / "transparenthistoryindex").is_dir()
        assert not (index_dir / "orchardindex-v3-1110000").exists()
        assert not (index_dir / "transparenthistoryindex-v2").exists()

        self.log.info("Pruned nodes enable Orchard while excluding incompatible indexes")
        self.assert_synced_index(self.nodes[1], "orchardindex")
        self.assert_indexes_absent(self.nodes[1], ("txindex", "coinstatsindex", "transparenthistoryindex"))

        self.log.info("Explicit full-node opt-out still disables the default indexes")
        self.assert_indexes_absent(self.nodes[2], ("txindex", "coinstatsindex", "orchardindex", "transparenthistoryindex"))

        self.log.info("Prune mode still rejects an explicit txindex request")
        self.stop_node(1)
        self.nodes[1].assert_start_raises_init_error(
            expected_msg="Error: Prune mode is incompatible with -txindex.",
            extra_args=["-prune=550", "-txindex=1"],
        )
        self.nodes[1].assert_start_raises_init_error(
            expected_msg="Error: Prune mode is incompatible with -transparenthistoryindex. Disable pruning or start with -transparenthistoryindex=0.",
            extra_args=["-prune=550", "-transparenthistoryindex=1"],
        )
        self.start_node(1, extra_args=self.extra_args[1])
        self.assert_synced_index(self.nodes[1], "orchardindex")
        self.assert_indexes_absent(self.nodes[1], ("txindex", "coinstatsindex", "transparenthistoryindex"))

        self.log.info("Pruned nodes respect an explicit Orchard opt-out")
        self.restart_node(1, extra_args=["-prune=550", "-orchardindex=0"])
        self.assert_indexes_absent(self.nodes[1], ("txindex", "coinstatsindex", "orchardindex", "transparenthistoryindex"))
        self.restart_node(1, extra_args=self.extra_args[1])
        self.assert_synced_index(self.nodes[1], "orchardindex")

        self.log.info("Enabling indexes over an existing chain does not emit a false commit error")
        index_node = self.nodes[2]
        self.generate(index_node, 1, sync_fun=self.no_op)
        self.restart_node(2, extra_args=["-txindex=1", "-orchardindex=1", "-transparenthistoryindex=1"])
        for index_name in ("txindex", "orchardindex", "transparenthistoryindex"):
            self.assert_synced_index(index_node, index_name)

        startup_log = index_node.debug_log_path.read_text(encoding="utf-8", errors="replace")
        for index_name in ("txindex", "orchardindex", "transparenthistoryindex"):
            assert f"Failed to commit latest {index_name} state" not in startup_log


if __name__ == "__main__":
    IndexDefaultsTest().main()
