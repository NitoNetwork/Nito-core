#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Rescan private spends without owned outputs when using block filters."""

from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


class PrivateRescanSpendsTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-blockfilterindex=1", "-orchardindex=1", "-transparenthistoryindex=1", "-keypool=20"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 101)
        node.createwallet("source", descriptors=True)
        source = node.get_wallet_rpc("source")
        node.createwallet("offline", descriptors=True, blank=True)
        offline = node.get_wallet_rpc("offline")
        offline.sethdseed(True, source.dumpmnemonic()["mnemonic"])
        node.unloadwallet("offline")

        self.log.info("Receive and completely spend a private note while the copy is unloaded")
        deposit = miner.sendtoaddress(source.getnewaddress("", "bech32x"), Decimal("2"))
        self.generate(node, 1)
        spend = source.sendprivate(miner.getnewaddress(), Decimal("2"), subtractfeefromamount=True)
        self.generate(node, 1)
        assert_equal(source.getprivatebalance()["trusted"], Decimal("0"))
        self.wait_until(lambda: all(index["synced"] and index["best_block_height"] == node.getblockcount()
                                    for index in node.getindexinfo().values()))

        self.log.info("Loading the copy must recover both receipt and spend, with no remaining balance")
        node.loadwallet("offline")
        offline = node.get_wallet_rpc("offline")
        assert_equal(offline.gettransaction(deposit)["confirmations"], 2)
        assert_equal(offline.getprivatebalance()["trusted"], Decimal("0"))
        assert_equal(offline.gettransaction(spend)["confirmations"], 1)
        assert_equal(offline.gettransaction(spend)["details"], source.gettransaction(spend)["details"])
        offline.rescanblockchain(101)
        assert_equal(offline.getprivatebalance()["trusted"], Decimal("0"))
        assert_equal(offline.gettransaction(spend)["confirmations"], 1)


if __name__ == "__main__":
    PrivateRescanSpendsTest().main()
