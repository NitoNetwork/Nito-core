#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that receive-only Orchard wallet scans do not retry sender change."""

from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal

MAX_MINING_TRIES = 10_000_000


class WalletPrivateReceiveScanTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-privateactivationheight=1"]]
        self.rpc_timeout = 120

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

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mine spendable transparent funds")
        node.createwallet(wallet_name="miner", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        self.mine_to_height(node, miner, 101)

        self.log.info("Create an external private source wallet and a private receiver wallet")
        node.createwallet(wallet_name="private_source", descriptors=True)
        source = node.get_wallet_rpc("private_source")
        node.createwallet(wallet_name="private_receiver", descriptors=True)
        receiver = node.get_wallet_rpc("private_receiver")

        self.log.info("Fund the source wallet with one confirmed private note")
        fund_txid = miner.sendtoaddress(source.getnewaddress("", "bech32x"), Decimal("0.06"))
        self.mine_to_height(node, miner, node.getblockcount() + 1)
        node.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: source.gettransaction(fund_txid)["confirmations"] >= 1, timeout=240)
        self.wait_until(lambda: source.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("Unload the sender before confirming a private-to-private receive")
        receiver_addr = receiver.getnewaddress("", "bech32x")
        receive_only_txid = source.sendprivate(receiver_addr, Decimal("0.02"))
        assert receive_only_txid in node.getrawmempool()
        node.syncwithvalidationinterfacequeue()
        node.unloadwallet("private_source")

        self.log.info("Confirming the receiver-only transaction must not scan sender change")
        with node.assert_debug_log(
            [],
            unexpected_msgs=[f"Retrying matched transaction {receive_only_txid}"],
            timeout=10,
        ):
            self.mine_to_height(node, miner, node.getblockcount() + 1)
            node.syncwithvalidationinterfacequeue()
            self.wait_until(
                lambda: receiver.getprivatebalance()["total_unspent"] >= Decimal("0.02"),
                timeout=240,
            )

        assert receive_only_txid not in node.getrawmempool()


if __name__ == "__main__":
    WalletPrivateReceiveScanTest().main()
