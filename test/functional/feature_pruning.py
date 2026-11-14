#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Nito pruning behavior.

Exercise manual pruning, a 288-block reorganization and automatic disk limits
with valid Nito blocks. Padding stays below Nito's 800,000 block weight limit;
small block files keep the manual-pruning and reorganization checks compact.
"""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.blockfilter import bip158_relevant_scriptpubkeys
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

BLOCK_SUBSIDY = 512


class PruneTest(NitoTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.supports_cli = False
        self.extra_args = [
            ["-fastprune"],
            ["-fastprune", "-prune=1", "-blockfilterindex=1"],
        ]

    def mine_blocks(self, n, *, script_pubkey=None, sync=True):
        node = self.nodes[0]
        best_block = node.getblock(node.getbestblockhash())
        height = int(best_block["height"]) + 1
        self.nTime = max(self.nTime, int(best_block["time"])) + 600
        previousblockhash = int(best_block["hash"], 16)

        for running_node in self.nodes:
            if running_node.running:
                running_node.setmocktime(self.nTime + 600 * n)

        for _ in range(n):
            block = create_block(
                hashprev=previousblockhash,
                ntime=self.nTime,
                coinbase=create_coinbase(height, nValue=BLOCK_SUBSIDY, script_pubkey=script_pubkey),
            )
            block.solve()
            assert_equal(node.submitblock(block.serialize().hex()), None)

            previousblockhash = block.sha256
            height += 1
            self.nTime += 600

        if sync:
            self.sync_all()

    def test_invalid_command_line_options(self):
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Prune cannot be configured with a negative value.',
            extra_args=['-prune=-1'],
        )
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Prune configured below the minimum of 550 MiB.  Please use a higher number.',
            extra_args=['-prune=549'],
        )
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Prune mode is incompatible with -txindex.',
            extra_args=['-prune=550', '-txindex'],
        )
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Prune mode is incompatible with -reindex-chainstate. Use full -reindex instead.',
            extra_args=['-prune=550', '-reindex-chainstate'],
        )

    def run_test(self):
        self.nTime = 0
        pruned_node = self.nodes[1]

        self.log.info("Mine valid Nito regtest blocks across several fastprune files")
        self.mine_blocks(750)
        self.wait_until(lambda: pruned_node.getindexinfo().get('basic block filter index') == {
            'synced': True,
            'best_block_height': 750,
        })

        old_block_hash = pruned_node.getblockhash(1)
        tip_hash = pruned_node.getbestblockhash()
        genesis_blockhash = pruned_node.getblockhash(0)
        genesis_spks = bip158_relevant_scriptpubkeys(pruned_node, genesis_blockhash)
        assert_equal(len(genesis_spks), 1)
        genesis_spk = list(genesis_spks)[0]

        assert genesis_blockhash in pruned_node.scanblocks(
            "start", [{"desc": f"raw({genesis_spk.hex()})"}], 0, 0)['relevant_blocks']
        assert_raises_rpc_error(
            -1,
            "Cannot prune blocks because node is not in prune mode",
            self.nodes[0].pruneblockchain,
            450,
        )

        self.log.info("Prune old block files while keeping recent reorg safety")
        pruneheight_new = pruned_node.pruneblockchain(450)
        assert_greater_than(pruneheight_new, 0)
        assert_equal(pruneheight_new + 1, pruned_node.getblockchaininfo()['pruneheight'])

        assert_raises_rpc_error(-1, "Block not available (pruned data)", pruned_node.getblock, old_block_hash)
        assert_equal(pruned_node.getblockheader(old_block_hash)["height"], 1)
        assert_equal(pruned_node.getblock(tip_hash)["hash"], tip_hash)

        assert_raises_rpc_error(
            -1,
            "Block not available (pruned data)",
            pruned_node.scanblocks,
            "start",
            [{"desc": f"raw({genesis_spk.hex()})"}],
            0,
            0,
            "basic",
            {"filter_false_positives": True},
        )

        self.log.info("Reorganize 288 retained blocks after old files were deleted")
        fork_height = 750 - 288
        assert_greater_than(fork_height, pruneheight_new)
        fork_hash = pruned_node.getblockhash(fork_height)
        self.disconnect_nodes(0, 1)
        self.nodes[0].invalidateblock(self.nodes[0].getblockhash(fork_height + 1))
        self.mine_blocks(289, sync=False)
        replacement_tip = self.nodes[0].getbestblockhash()
        assert replacement_tip != tip_hash
        self.connect_nodes(0, 1)
        self.sync_all()
        assert_equal(pruned_node.getbestblockhash(), replacement_tip)
        assert_equal(pruned_node.getblockhash(fork_height), fork_hash)
        self.wait_until(lambda: pruned_node.getindexinfo()['basic block filter index']['best_block_height'] == 751)
        self.restart_node(1)
        assert_equal(pruned_node.getbestblockhash(), replacement_tip)
        assert_raises_rpc_error(-1, "pruned data", pruned_node.getblock, old_block_hash)

        self.log.info("Exceed the automatic prune target using consensus-valid padding")
        self.restart_node(1, ["-prune=550", "-blockfilterindex=1"])
        self.connect_nodes(0, 1)
        self.mine_blocks(3200, script_pubkey=CScript([OP_RETURN, bytes(190_000)]))
        self.wait_until(lambda: pruned_node.getindexinfo()['basic block filter index']['best_block_height'] == 3951)
        info = pruned_node.getblockchaininfo()
        assert_equal(info['automatic_pruning'], True)
        assert_equal(info['prune_target_size'], 550 * 1024 * 1024)
        assert_greater_than(info['pruneheight'], 751)
        assert info['size_on_disk'] < info['prune_target_size']
        assert_raises_rpc_error(-1, "pruned data", pruned_node.getblock, replacement_tip)
        automatic_tip = pruned_node.getbestblockhash()
        assert_equal(pruned_node.getblock(automatic_tip)['hash'], automatic_tip)
        self.restart_node(1, ["-prune=550", "-blockfilterindex=1"])
        assert_equal(pruned_node.getbestblockhash(), automatic_tip)
        assert_equal(pruned_node.getblockchaininfo()['pruned'], True)

        self.log.info("Test invalid pruning command line options")
        self.test_invalid_command_line_options()


if __name__ == '__main__':
    PruneTest().main()
