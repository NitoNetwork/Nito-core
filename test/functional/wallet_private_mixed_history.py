#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Keep both transparent and private payments in mixed-output history."""

from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


class PrivateMixedHistoryTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-orchardindex=1", "-transparenthistoryindex=1", "-keypool=20"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 101)
        node.createwallet("source", descriptors=True, load_on_startup=True)
        source = node.get_wallet_rpc("source")
        phrase = source.dumpmnemonic()["mnemonic"]
        miner.sendtoaddress(source.getnewaddress("", "bech32x"), Decimal("4"))
        self.generate(node, 1)
        cases = []
        for own_transparent in [False, True]:
            transparent = (source if own_transparent else miner).getnewaddress()
            private = miner.getnewaddress("", "bech32x")
            txid = source.sendmany("", {transparent: Decimal("0.25"), private: Decimal("0.50")}, **{"private": True})
            self.generate(node, 1)
            expected = [("send", Decimal("-0.50")), ("send", Decimal("-0.25"))]
            if own_transparent:
                expected.append(("receive", Decimal("0.25")))
            cases.append((txid, sorted(expected), Decimal("-0.50") if own_transparent else Decimal("-0.75")))

        def check(rpc):
            for txid, expected, amount in cases:
                tx = rpc.gettransaction(txid)
                assert_equal(sorted((r["category"], r["amount"]) for r in tx["details"]), expected)
                rows = [r for r in rpc.listtransactions("*", 1000) if r["txid"] == txid]
                assert_equal(sorted((r["category"], r["amount"]) for r in rows), expected)
                assert_equal(tx["amount"], amount)

        check(source)
        self.restart_node(0)
        check(node.get_wallet_rpc("source"))
        node.createwallet("restored", descriptors=True, blank=True)
        restored = node.get_wallet_rpc("restored")
        restored.sethdseed(True, phrase)
        check(restored)


if __name__ == "__main__":
    PrivateMixedHistoryTest().main()
