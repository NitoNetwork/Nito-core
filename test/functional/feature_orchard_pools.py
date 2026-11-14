#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getorchardpools reporting."""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import getnewdestination

MAX_MINING_TRIES = 10_000_000


class OrchardPoolsTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False, legacy=True)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-privateactivationheight=1", "-coinstatsindex=1"]]
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_height(self, height):
        node = self.nodes[0]
        while node.getblockcount() < height:
            self.generatetoaddress(
                node,
                height - node.getblockcount(),
                node.getnewaddress(),
                MAX_MINING_TRIES,
            )
        assert_equal(node.getblockcount(), height)

    def assert_lightweight_blockchain_info(self, expected_activated):
        blockchain_info = self.nodes[0].getblockchaininfo()
        assert_equal(blockchain_info["privateTxActivationHeight"], 1)
        assert_equal(blockchain_info["activated"], expected_activated)
        assert "valuePools" not in blockchain_info
        assert "value_pools" not in blockchain_info
        assert "orchard" not in blockchain_info

    def assert_pool_entry(self, pool, expected_value):
        assert_equal(pool["monitored"], True)
        assert_equal(pool["chainValue"], expected_value)
        assert_equal(pool["chainValueNitoshi"], int(expected_value * COIN))

    def assert_value_pools(self, expected_orchard_value):
        node = self.nodes[0]
        pool_info = node.getorchardpools()
        transparent_value = node.gettxoutsetinfo()["total_amount"]
        stats = node.gettxoutsetinfo("none")
        assert_equal(stats["block_info"]["unspendables"]["unclaimed_rewards"], 0)
        assert_equal(stats["total_unspendable_amount"], Decimal("512"))
        self.assert_pool_entry(pool_info["orchard"], expected_orchard_value)
        self.assert_pool_entry(pool_info["transparent"], transparent_value)
        self.assert_pool_entry(pool_info["total"], transparent_value + expected_orchard_value)
        assert_equal(pool_info["total"]["chainValue"], Decimal("512") * node.getblockcount())
        return pool_info

    def assert_orchard_pool(self, expected_value):
        self.assert_value_pools(expected_value)

    def private_pool_delta_from_block(self, block):
        delta = Decimal("0")
        for tx in block["tx"]:
            bundle = tx.get("private_bundle")
            if bundle is not None:
                delta -= bundle["value_balance"]
        return delta

    def mine_and_apply_private_pool_delta(self, expected_pool, expected_txid):
        node = self.nodes[0]
        initial_height = node.getblockcount()
        block_hashes = []
        while node.getblockcount() == initial_height:
            block_hashes = self.generatetoaddress(
                node,
                1,
                getnewdestination()[2],
                MAX_MINING_TRIES,
            )
        assert_equal(len(block_hashes), 1)
        block = node.getblock(block_hashes[0], 2)
        assert_equal(block["height"], initial_height + 1)
        assert expected_txid in {tx["txid"] for tx in block["tx"]}
        expected_pool += self.private_pool_delta_from_block(block)
        self.assert_orchard_pool(expected_pool)
        return expected_pool, block

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Before private transactions, the Orchard pool is monitored and empty")
        pool_info = node.getorchardpools()
        assert_equal(pool_info["chain"], "regtest")
        assert_equal(pool_info["blocks"], 0)
        assert_equal(pool_info["privateTxActivationHeight"], 1)
        assert_equal(pool_info["activated"], False)
        self.assert_pool_entry(pool_info["orchard"], Decimal("0"))
        self.assert_pool_entry(pool_info["transparent"], Decimal("0"))
        self.assert_pool_entry(pool_info["total"], Decimal("0"))
        self.assert_lightweight_blockchain_info(False)

        self.log.info("Transparent-only blocks do not add value-pool data to getblockchaininfo")
        self.mine_to_height(101)
        pool_info = node.getorchardpools()
        assert_equal(pool_info["blocks"], 101)
        assert_equal(pool_info["activated"], True)
        self.assert_value_pools(Decimal("0"))
        self.assert_lightweight_blockchain_info(True)

        utxo_stats = node.gettxoutsetinfo()
        assert "total_amount" in utxo_stats
        assert "orchard" not in utxo_stats
        assert "valuePools" not in utxo_stats

        expected_pool = Decimal("0")

        self.log.info("Transparent-to-Orchard shielding increases the audited Orchard pool")
        shield_txid = node.sendtoaddress(node.getnewaddress("", "bech32x"), Decimal("1.25"))
        expected_pool, shield_block = self.mine_and_apply_private_pool_delta(expected_pool, shield_txid)
        assert expected_pool > Decimal("0")

        self.wait_until(lambda: node.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("Orchard-to-transparent spending decreases the audited Orchard pool")
        unshield_txid = node.sendprivate(node.getnewaddress("", "bech32"), Decimal("0.50"))
        before_unshield_pool = expected_pool
        expected_pool, unshield_block = self.mine_and_apply_private_pool_delta(expected_pool, unshield_txid)
        assert Decimal("0") <= expected_pool < before_unshield_pool

        self.wait_until(lambda: node.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("Private-to-private spending updates only public cross-pool accounting")
        private_txid = node.sendprivate(node.getnewaddress("", "bech32x"), Decimal("0.10"))
        expected_pool, private_block = self.mine_and_apply_private_pool_delta(expected_pool, private_txid)
        assert expected_pool >= Decimal("0")

        self.log.info("Reorgs restore the exact audited Orchard pool")
        private_delta = self.private_pool_delta_from_block(private_block)
        node.invalidateblock(private_block["hash"])
        expected_pool -= private_delta
        self.assert_orchard_pool(expected_pool)
        self.assert_lightweight_blockchain_info(True)

        node.reconsiderblock(private_block["hash"])
        expected_pool += private_delta
        self.assert_orchard_pool(expected_pool)
        self.assert_lightweight_blockchain_info(True)

        self.log.info("Restart preserves Orchard accounting and unclaimed reward totals")
        self.restart_node(0)
        self.assert_orchard_pool(expected_pool)

        self.log.info("Reindex reconstructs the same supply accounting")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-reindex"])
        self.wait_until(lambda: node.getblockcount() == private_block["height"])
        self.assert_orchard_pool(expected_pool)


if __name__ == '__main__':
    OrchardPoolsTest().main()
