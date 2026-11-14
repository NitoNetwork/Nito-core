#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Keep Orchard notes, history and spend witnesses after actual block pruning."""

import os
from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

ARGS = ["-privateactivationheight=1", "-prune=1", "-fastprune"]
PASSPHRASE = "local pruning regression only"
RECOVERY_ERROR = "Some blocks required for complete wallet recovery have been pruned. To reconstruct your wallet and its complete history, use a non-pruned node or perform a full resynchronization. This requires downloading data, time and disk space. No resynchronization has been started."
INDEX_ERROR = "The Orchard index cannot catch up because required blocks have been pruned."


class PrivatePruningTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument("--missing-index", action="store_true", help="Start without an Orchard index and prune its source blocks")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [ARGS]
        if self.options.missing_index:
            self.extra_args = [ARGS + ["-orchardindex=0"]]
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def sync_index(self):
        node = self.nodes[0]
        node.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: node.getindexinfo().get("orchardindex", {}).get("best_block_height") == node.getblockcount())

    def run_test(self):
        node = self.nodes[0]
        if self.options.missing_index:
            self.log.info("An old pruned node without an index needs explicit operator recovery")
            assert "orchardindex" not in node.getindexinfo()
            self.generate(node, 800)
            tip = node.getbestblockhash()
            assert_greater_than(node.pruneblockchain(500), 1)
            self.stop_node(0)
            node.assert_start_raises_init_error(extra_args=ARGS, expected_msg=INDEX_ERROR, match=ErrorMatch.PARTIAL_REGEX)
            self.start_node(0, ARGS + ["-orchardindex=0"])
            assert_equal(node.getbestblockhash(), tip)
            assert "orchardindex" not in node.getindexinfo()
            return

        self.log.info("New pruned nodes enable Orchard by default and respect an explicit opt-out")
        assert "orchardindex" in node.getindexinfo()
        self.restart_node(0, ARGS + ["-orchardindex=0"])
        assert "orchardindex" not in node.getindexinfo()
        # No blocks have been deleted yet, so this transition needs no reindex.
        self.restart_node(0, ARGS + ["-prune=0"])
        assert not node.getblockchaininfo()["pruned"]
        assert "orchardindex" in node.getindexinfo()
        node.unloadwallet(self.default_wallet_name)
        node.loadwallet(self.default_wallet_name, load_on_startup=True)
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 110)
        node.createwallet("private_pruned", descriptors=True, passphrase=PASSPHRASE, load_on_startup=True)
        wallet = node.get_wallet_rpc("private_pruned")
        wallet.walletpassphrase(PASSPHRASE, 600)
        address = wallet.getnewaddress("", "bech32x")
        initial_tx = miner.sendtoaddress(address, 5)
        self.generate(node, 1)
        self.sync_index()
        old_block = node.getbestblockhash()
        assert_equal(wallet.getprivatebalance()["trusted"], 5)
        backup = os.path.join(self.options.tmpdir, "old-wallet.dat")
        wallet.backupwallet(backup)
        wallet.walletlock()

        self.log.info("Switch an indexed archival node to pruning without disabling or rebuilding Orchard")
        self.restart_node(0, ARGS)
        wallet = node.get_wallet_rpc("private_pruned")
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.sync_index()
        assert node.getblockchaininfo()["pruned"]
        assert_equal(node.getindexinfo()["orchardindex"]["best_block_height"], 111)

        self.log.info("A locked wallet receives Orchard funds before its block is pruned")
        locked_tx = miner.sendtoaddress(address, 3)
        self.generate(node, 1)
        locked_block = node.getbestblockhash()
        self.generate(node, 800)
        self.sync_index()
        assert_equal(wallet.getwalletinfo()["seed_history"]["locked_live"]["status"], "pending")
        assert_greater_than(node.pruneblockchain(node.getblockcount() - 300), 112)
        assert_raises_rpc_error(-1, "pruned data", node.getblock, old_block)
        assert_raises_rpc_error(-1, "pruned data", node.getblock, locked_block)
        assert_raises_rpc_error(-13, "passphrase", wallet.getprivatebalance)

        self.log.info("Restart locked, then recover full Orchard history without deleted blocks")
        self.restart_node(0, ARGS)
        wallet = node.get_wallet_rpc("private_pruned")
        self.sync_index()
        wallet.walletpassphrase(PASSPHRASE, 600)
        assert_equal(wallet.getwalletinfo()["seed_history"]["locked_live"]["status"], "complete")
        assert_equal(wallet.getprivatebalance()["trusted"], 8)
        assert_greater_than(wallet.gettransaction(initial_tx)["confirmations"], 0)
        assert_greater_than(wallet.gettransaction(locked_tx)["confirmations"], 0)
        assert_equal(node.decoderawtransaction(wallet.gettransaction(locked_tx)["hex"])["txid"], locked_tx)

        self.log.info("Spend a note from a deleted block and reorg its spend")
        spent = wallet.sendprivate(wallet.getnewaddress(), Decimal("1"), fee_rate=1)
        self.generate(node, 1)
        self.sync_index()
        spend_block = node.getbestblockhash()
        balance = wallet.getprivatebalance()["trusted"]
        assert 0 < balance < 7
        assert_greater_than(wallet.gettransaction(spent)["confirmations"], 0)
        node.invalidateblock(spend_block)
        node.reconsiderblock(spend_block)
        self.sync_index()
        assert_equal(wallet.getprivatebalance()["trusted"], balance)
        self.restart_node(0, ARGS)
        wallet = node.get_wallet_rpc("private_pruned")
        self.sync_index()
        wallet.walletpassphrase(PASSPHRASE, 600)
        assert_equal(wallet.getprivatebalance()["trusted"], balance)
        wallet.sendprivate(wallet.getnewaddress("", "bech32x"), Decimal("0.1"), fee_rate=1)
        self.generate(node, 1)
        self.sync_index()

        self.log.info("Missing transparent history must not be presented as a complete restore")
        tip = node.getbestblockhash()
        assert_raises_rpc_error(-4, RECOVERY_ERROR, node.restorewallet, "old_backup", backup)
        node.createwallet("phrase_restore", descriptors=True, blank=True)
        assert_raises_rpc_error(-1, RECOVERY_ERROR, node.get_wallet_rpc("phrase_restore").sethdseed, True,
                               "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        assert_equal(node.getbestblockhash(), tip)
        assert not node.get_wallet_rpc("phrase_restore").listdescriptors()["descriptors"]

        self.log.info("An index disabled beyond deleted blocks cannot silently reinitialize")
        self.restart_node(0, ARGS + ["-orchardindex=0"])
        self.generate(node, 800)
        node.pruneblockchain(node.getblockcount() - 300)
        self.stop_node(0)
        node.assert_start_raises_init_error(extra_args=ARGS,
            expected_msg=INDEX_ERROR, match=ErrorMatch.PARTIAL_REGEX)


if __name__ == "__main__":
    PrivatePruningTest().main()
