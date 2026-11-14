#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test private wallet state across reorg, crash replay, and reindex."""

import os
import signal
from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
)


MAX_MINING_TRIES = 10_000_000
BASE_ARGS = ["-privateactivationheight=1", "-orchardindex=1", "-persistmempool=0"]


class WalletPrivateReorgReindexTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [BASE_ARGS]
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_height(self, node, wallet, height):
        blocks = []
        while node.getblockcount() < height:
            blocks.extend(self.generatetoaddress(
                node,
                height - node.getblockcount(),
                wallet.getnewaddress(),
                MAX_MINING_TRIES,
            ))
        assert_equal(node.getblockcount(), height)
        return blocks

    def mine_one(self, node, wallet):
        blocks = self.generatetoaddress(node, 1, wallet.getnewaddress(), MAX_MINING_TRIES)
        assert_equal(len(blocks), 1)
        return blocks[0]

    def assert_orchard_index(self, node):
        height = node.getblockcount()

        def index_synced_at_tip():
            info = node.getindexinfo("orchardindex").get("orchardindex")
            return info is not None and info["synced"] is True and info["best_block_height"] == height

        self.wait_until(index_synced_at_tip, timeout=180)

    def private_pool_delta_from_block(self, block):
        delta = Decimal("0")
        for tx in block["tx"]:
            bundle = tx.get("private_bundle")
            if bundle is not None:
                delta -= bundle["value_balance"]
        return delta

    def assert_private_confirmed(self, node, wallet, txid, min_confirmations=1):
        node.syncwithvalidationinterfacequeue()
        self.wait_until(
            lambda: wallet.gettransaction(txid)["confirmations"] >= min_confirmations,
            timeout=240,
        )
        tx = wallet.gettransaction(txid, verbose=True)
        assert_equal(tx["decoded"]["has_private_bundle"], True)
        assert_greater_than_or_equal(tx["confirmations"], min_confirmations)
        self.assert_orchard_index(node)
        return tx

    def reload_wallet_rpcs(self):
        node = self.nodes[0]
        return (
            node,
            node.get_wallet_rpc("miner"),
            node.get_wallet_rpc("private_replay"),
        )

    def restart_and_check(self, extra_args, shield_txid, unshield_txid, expected_pool):
        self.restart_node(0, extra_args)
        node, miner, wallet = self.reload_wallet_rpcs()
        self.assert_orchard_index(node)
        self.assert_private_confirmed(node, wallet, shield_txid)
        self.assert_private_confirmed(node, wallet, unshield_txid)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)
        pool = node.getorchardpools()["orchard"]
        assert_equal(pool["monitored"], True)
        assert_equal(pool["chainValue"], expected_pool)
        assert_equal(node.getrawmempool(), [])
        return node, miner, wallet

    def crash_node(self):
        node = self.nodes[0]
        node.process.kill()
        expected_ret_code = 1 if os.name == "nt" else -signal.SIGKILL
        self.wait_until(
            lambda: node.is_node_stopped(expected_ret_code=expected_ret_code),
            timeout=30,
        )

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mine spendable transparent funds and enable startup-loaded wallets")
        node.createwallet(wallet_name="miner", descriptors=True, load_on_startup=True)
        miner = node.get_wallet_rpc("miner")
        self.mine_to_height(node, miner, 101)
        self.assert_orchard_index(node)

        node.createwallet(wallet_name="private_replay", descriptors=True, load_on_startup=True)
        wallet = node.get_wallet_rpc("private_replay")

        self.log.info("Confirm a shielded note and record the Orchard pool")
        shield_txid = miner.sendtoaddress(wallet.getnewaddress("", "bech32x"), Decimal("1.00"))
        shield_block_hash = self.mine_one(node, miner)
        self.assert_private_confirmed(node, wallet, shield_txid)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)
        shield_block = node.getblock(shield_block_hash, 2)
        expected_pool = self.private_pool_delta_from_block(shield_block)
        assert_equal(expected_pool, Decimal("1.00"))
        assert_equal(node.getorchardpools()["orchard"]["chainValue"], expected_pool)

        self.log.info("Confirm an Orchard-to-transparent spend")
        unshield_txid = wallet.sendprivate(miner.getnewaddress(), Decimal("0.25"))
        unshield_block_hash = self.mine_one(node, miner)
        unshield_block = node.getblock(unshield_block_hash, 2)
        expected_pool += self.private_pool_delta_from_block(unshield_block)
        assert Decimal("0") < expected_pool < Decimal("1.00")
        self.assert_private_confirmed(node, wallet, unshield_txid)
        assert_equal(node.getorchardpools()["orchard"]["chainValue"], expected_pool)

        self.log.info("Disconnect and reconnect the private spend block")
        node.invalidateblock(unshield_block_hash)
        self.assert_orchard_index(node)
        self.wait_until(lambda: unshield_txid in node.getrawmempool(), timeout=120)
        assert_equal(node.getorchardpools()["orchard"]["chainValue"], Decimal("1.00"))

        node.reconsiderblock(unshield_block_hash)
        self.assert_private_confirmed(node, wallet, unshield_txid)
        assert_equal(node.getrawmempool(), [])
        assert_equal(node.getorchardpools()["orchard"]["chainValue"], expected_pool)

        self.log.info("Kill the node and verify private state is replayed on restart")
        self.crash_node()
        self.start_node(0, BASE_ARGS)
        node, miner, wallet = self.reload_wallet_rpcs()
        self.assert_orchard_index(node)
        self.assert_private_confirmed(node, wallet, shield_txid)
        self.assert_private_confirmed(node, wallet, unshield_txid)
        assert_equal(node.getorchardpools()["orchard"]["chainValue"], expected_pool)

        self.log.info("Rebuild indexes from block files")
        node, miner, wallet = self.restart_and_check(
            [*BASE_ARGS, "-reindex=1"],
            shield_txid,
            unshield_txid,
            expected_pool,
        )

        self.log.info("Rebuild chainstate while keeping the private index current")
        self.restart_and_check(
            [*BASE_ARGS, "-reindex-chainstate=1"],
            shield_txid,
            unshield_txid,
            expected_pool,
        )


if __name__ == "__main__":
    WalletPrivateReorgReindexTest().main()
