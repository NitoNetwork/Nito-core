#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test wallet import on pruned node."""

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_block,
    create_coinbase,
)
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.test_framework import NitoTestFramework

BLOCK_SUBSIDY = 512
MNEMONIC_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

class WalletPruningTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.wallet_names = []
        self.extra_args = [
            ['-fastprune'], # node dedicated to mining
            [
                '-fastprune',
                '-prune=1',
                '-privateactivationheight=1',
                '-orchardindex=0',
                '-transparenthistoryindex=0',
            ], # node dedicated to testing manual pruning
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_bdb()

    def test_wallet_import_pruned(self, wallet_name):
        self.log.info("Make sure we can import wallet when pruned and required blocks are still available")

        wallet_file = wallet_name + ".dat"
        wallet_birthheight = self.get_birthheight(wallet_file)

        # Verify that the block at wallet's birthheight is available at the pruned node
        self.nodes[1].getblock(self.nodes[1].getblockhash(wallet_birthheight))

        # Import wallet into pruned node
        self.nodes[1].createwallet(wallet_name="wallet_pruned", descriptors=False, load_on_startup=True)
        self.nodes[1].importwallet(self.nodes[0].datadir_path / wallet_file)

        # Make sure that prune node's wallet correctly accounts for balances
        assert_equal(self.nodes[1].getbalance(), self.nodes[0].getbalance())

        self.log.info("- Done")

    def test_wallet_import_pruned_with_missing_blocks(self, wallet_name):
        self.log.info("Make sure we cannot import wallet when pruned and required blocks are not available")

        wallet_file = wallet_name + ".dat"
        wallet_birthheight = self.get_birthheight(wallet_file)

        # Verify that the block at wallet's birthheight is not available at the pruned node
        assert_raises_rpc_error(-1, "Block not available (pruned data)", self.nodes[1].getblock, self.nodes[1].getblockhash(wallet_birthheight))

        # Make sure wallet cannot be imported because of missing blocks
        # This will try to rescan blocks `TIMESTAMP_WINDOW` (2h) before the wallet birthheight.
        # There are 6 blocks an hour, so 11 blocks (excluding birthheight).
        assert_raises_rpc_error(-4, f"Pruned blocks from height {wallet_birthheight - 11} required to import keys. Use RPC call getblockchaininfo to determine your pruned height.", self.nodes[1].importwallet, self.nodes[0].datadir_path / wallet_file)
        self.log.info("- Done")

    def get_birthheight(self, wallet_file):
        """Gets birthheight of a wallet on node0"""
        with open(self.nodes[0].datadir_path / wallet_file, 'r', encoding="utf8") as f:
            for line in f:
                if line.startswith('# * Best block at time of backup'):
                    wallet_birthheight = int(line.split(' ')[9])
                    return wallet_birthheight

    def create_wallet(self, wallet_name, *, unload=False):
        """Creates and dumps a wallet on the non-pruned node0 to be later import by the pruned node"""
        self.nodes[0].createwallet(wallet_name=wallet_name, descriptors=False, load_on_startup=True)
        self.nodes[0].dumpwallet(self.nodes[0].datadir_path / f"{wallet_name}.dat")
        if (unload):
            self.nodes[0].unloadwallet(wallet_name)

    def mine_blocks(self, node, n, *, script_pubkey=None):
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
                coinbase=create_coinbase(height, script_pubkey=script_pubkey, nValue=BLOCK_SUBSIDY),
            )
            block.solve()
            assert_equal(node.submitblock(block.serialize().hex()), None)

            previousblockhash = block.sha256
            height += 1
            self.nTime += 600

        self.sync_all()

    def run_test(self):
        self.nTime = 0
        self.log.info("Generating a fastprune chain with two wallet birth heights...")

        # Use -fastprune's small block files instead of oversized Bitcoin-style
        # padding blocks. Nito's 800,000 block weight limit makes those inherited
        # 950k coinbase scripts invalid, while small block files still exercise
        # the importwallet/pruned-data behavior this test cares about.
        self.mine_blocks(self.nodes[0], 150)

        # Create a wallet whose birth block will be pruned.
        wallet_birthheight_1 = "wallet_birthheight_1"
        self.create_wallet(wallet_birthheight_1, unload=True)

        # Move far enough forward that manual pruning can delete early block
        # files while still keeping the second wallet's birth block available.
        self.mine_blocks(self.nodes[0], 300)

        # Create a wallet with birth height > wallet_birthheight_1
        wallet_birthheight_2 = "wallet_birthheight_2"
        self.create_wallet(wallet_birthheight_2)

        # Fund wallet to later verify that importwallet correctly accounts for balances
        self.mine_blocks(self.nodes[0], 1, script_pubkey=address_to_scriptpubkey(self.nodes[0].getnewaddress()))
        self.mine_blocks(self.nodes[0], COINBASE_MATURITY)
        self.mine_blocks(self.nodes[0], 200)

        wallet_file_1 = wallet_birthheight_1 + ".dat"
        wallet_file_2 = wallet_birthheight_2 + ".dat"
        birthheight_1 = self.get_birthheight(wallet_file_1)
        birthheight_2 = self.get_birthheight(wallet_file_2)

        self.nodes[1].pruneblockchain(birthheight_1 + 300)
        assert_raises_rpc_error(-1, "Block not available (pruned data)", self.nodes[1].getblock, self.nodes[1].getblockhash(birthheight_1))
        self.nodes[1].getblock(self.nodes[1].getblockhash(birthheight_2))

        self.test_wallet_import_pruned(wallet_birthheight_2)
        self.test_wallet_import_pruned_with_missing_blocks(wallet_birthheight_1)

        self.log.info("Make automatic seed-history restore fail explicitly when archival blocks were pruned")
        self.nodes[1].createwallet(wallet_name="pruned_seed_restore", blank=True, descriptors=True)
        pruned_seed_wallet = self.nodes[1].get_wallet_rpc("pruned_seed_restore")
        assert_raises_rpc_error(
            -1,
            "Some blocks required for complete wallet recovery have been pruned.",
            pruned_seed_wallet.sethdseed,
            True,
            MNEMONIC_12,
        )

if __name__ == '__main__':
    WalletPruningTest().main()
