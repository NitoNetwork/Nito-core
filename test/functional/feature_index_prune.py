#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test indices in conjunction with prune."""
import os
import struct
from test_framework.blocktools import MIN_BLOCKS_TO_KEEP
from test_framework.messages import hash256
from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class FeatureIndexPruneTest(NitoTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [
            ["-fastprune", "-prune=1", "-blockfilterindex=1", "-orchardindex=0"],
            ["-fastprune", "-prune=1", "-blockfilterindex=0", "-coinstatsindex=1", "-orchardindex=0"],
            ["-fastprune", "-prune=1", "-blockfilterindex=1", "-coinstatsindex=1", "-orchardindex=0"],
            ["-blockfilterindex=0", "-orchardindex=0"],
        ]

    def sync_index(self, height):
        expected_filter = {'synced': True, 'best_block_height': height}
        expected_stats = {'synced': True, 'best_block_height': height}

        self.wait_until(lambda: self.nodes[0].getindexinfo().get('basic block filter index') == expected_filter)
        self.wait_until(lambda: self.nodes[1].getindexinfo().get('coinstatsindex') == expected_stats)
        self.wait_until(lambda: self.nodes[2].getindexinfo().get('basic block filter index') == expected_filter)
        self.wait_until(lambda: self.nodes[2].getindexinfo().get('coinstatsindex') == expected_stats)

    def reconnect_nodes(self):
        self.connect_nodes(0,1)
        self.connect_nodes(0,2)
        self.connect_nodes(0,3)

    def mine_batches(self, blocks):
        n = blocks // 250
        for _ in range(n):
            self.generate(self.nodes[0], 250)
        self.generate(self.nodes[0], blocks % 250)
        self.sync_blocks()

    def restart_without_indices(self):
        for i in range(3):
            self.restart_node(i, extra_args=["-fastprune", "-prune=1", "-blockfilterindex=0", "-orchardindex=0"])
        self.reconnect_nodes()

    def expected_prune_boundary(self, node, requested_height):
        """Read actual closed-file boundaries instead of assuming block sizes."""
        limit = min(requested_height, node.getblockcount() - MIN_BLOCKS_TO_KEEP)
        boundaries = []
        files = sorted(node.blocks_path.glob('blk*.dat'))
        for path in files[:-1]:
            last_header = None
            with path.open('rb') as stream:
                while True:
                    prefix = stream.read(8)
                    if len(prefix) < 8 or prefix == bytes(8):
                        break
                    size = struct.unpack('<I', prefix[4:])[0]
                    assert size >= 80
                    last_header = stream.read(80)
                    stream.seek(size - 80, 1)
            if last_header:
                block_hash = hash256(last_header)[::-1].hex()
                height = node.getblockheader(block_hash)['height']
                if height <= limit:
                    boundaries.append(height)
        assert boundaries, 'No complete block file is eligible for pruning'
        return max(boundaries)

    def run_test(self):
        filter_nodes = [self.nodes[0], self.nodes[2]]
        stats_nodes = [self.nodes[1], self.nodes[2]]

        self.log.info("check if we can access blockfilters and coinstats when pruning is enabled but no blocks are actually pruned")
        self.sync_index(height=200)
        tip = self.nodes[0].getbestblockhash()
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(tip)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=tip)['muhash']

        self.mine_batches(500)
        self.sync_index(height=700)

        self.log.info("prune some blocks")
        for node in self.nodes[:2]:
            expected_boundary = self.expected_prune_boundary(node, 400)
            with node.assert_debug_log(['limited pruning to height 689']):
                pruneheight_new = node.pruneblockchain(400)
                assert_equal(pruneheight_new, expected_boundary)
                assert_raises_rpc_error(-1, 'Block not available (pruned data)',
                                        node.getblock, node.getblockhash(pruneheight_new))
                assert node.getblock(node.getblockhash(pruneheight_new + 1))

        self.log.info("check if we can access the tips blockfilter and coinstats when we have pruned some blocks")
        tip = self.nodes[0].getbestblockhash()
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(tip)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=tip)['muhash']

        self.log.info("check if we can access the blockfilter and coinstats of a pruned block")
        height_hash = self.nodes[0].getblockhash(2)
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(height_hash)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=height_hash)['muhash']

        # Sync the indexes to the first block in the next physical file. Later
        # pruning removes the preceding file while retaining this checkpoint.
        previous_file = max(self.nodes[0].blocks_path.glob('blk*.dat'))
        while max(self.nodes[0].blocks_path.glob('blk*.dat')) == previous_file:
            self.generate(self.nodes[0], 1)
        checkpoint = self.nodes[0].getblockcount()
        self.sync_index(height=checkpoint)

        self.restart_without_indices()

        self.log.info("make sure trying to access the indices throws errors")
        for node in filter_nodes:
            msg = "Index is not enabled for filtertype basic"
            assert_raises_rpc_error(-1, msg, node.getblockfilter, height_hash)
        for node in stats_nodes:
            msg = "Querying specific block heights requires coinstatsindex"
            assert_raises_rpc_error(-8, msg, node.gettxoutsetinfo, "muhash", height_hash)

        self.mine_batches(1500 - checkpoint)

        self.log.info("prune exactly up to the indices best blocks while the indices are disabled")
        for i in range(3):
            pruneheight_2 = self.nodes[i].pruneblockchain(1000)
            assert_equal(pruneheight_2, checkpoint - 1)
            # Restart the nodes again with the indices activated
            self.restart_node(i, extra_args=self.extra_args[i])

        self.log.info("make sure that we can continue with the partially synced indices after having pruned up to the index height")
        self.sync_index(height=1500)

        self.log.info("prune further than the indices best blocks while the indices are disabled")
        self.restart_without_indices()
        self.mine_batches(1000)

        for i in range(3):
            pruneheight_3 = self.nodes[i].pruneblockchain(2000)
            assert_greater_than(pruneheight_3, pruneheight_2)
            self.stop_node(i)

        self.log.info("make sure we get an init error when starting the nodes again with the indices")
        filter_msg = "Error: basic block filter index best block of the index goes beyond pruned data. Please disable the index or reindex (which will download the whole blockchain again)"
        stats_msg = "Error: coinstatsindex best block of the index goes beyond pruned data. Please disable the index or reindex (which will download the whole blockchain again)"
        end_msg = f"{os.linesep}Error: Failed to start indexes, shutting down.."
        for i, msg in enumerate([filter_msg, stats_msg, filter_msg]):
            self.nodes[i].assert_start_raises_init_error(extra_args=self.extra_args[i], expected_msg=msg+end_msg)

        self.log.info("make sure the nodes start again with the indices and an additional -reindex arg")
        for i in range(3):
            restart_args = self.extra_args[i]+["-reindex"]
            self.restart_node(i, extra_args=restart_args)
            # The nodes need to be reconnected to the non-pruning node upon restart, otherwise they will be stuck
            self.connect_nodes(i, 3)

        self.sync_blocks(timeout=300)
        self.sync_index(height=2500)

        for node in self.nodes[:2]:
            expected_boundary = self.expected_prune_boundary(node, 2500)
            with node.assert_debug_log(['limited pruning to height 2489']):
                pruneheight_new = node.pruneblockchain(2500)
                assert_equal(pruneheight_new, expected_boundary)

        self.log.info("ensure that prune locks don't prevent indices from failing in a reorg scenario")
        with self.nodes[0].assert_debug_log(['basic block filter index prune lock moved back to 2480']):
            self.nodes[3].invalidateblock(self.nodes[0].getblockhash(2480))
            self.generate(self.nodes[3], 30)
            self.sync_blocks()


if __name__ == '__main__':
    FeatureIndexPruneTest().main()
