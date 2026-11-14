#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Private selection with fragmented funds and consensus-bounded consolidation."""

from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


class PrivateSelectionTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-privateactivationheight=1"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 110)
        outputs = {wallet.getnewaddress("", "bech32x"): Decimal("0.01") for _ in range(50)}
        wallet.send(outputs=outputs, options={"fee_rate": 1})
        wallet.shieldtoaddress(wallet.getnewaddress("", "bech32x"), 10, fee_rate=1)
        self.generate(node, 1)
        assert_equal(wallet.getprivatebalance()["trusted"], Decimal("10.50"))

        self.log.info("Select the large note despite fifty smaller confirmed notes")
        result = wallet.send(
            outputs={wallet.getnewaddress(): Decimal("10")},
            options={"private": True, "subtract_fee_from_outputs": [0], "fee_rate": 1},
        )
        assert_equal(result["complete"], True)
        self.generate(node, 1)
        assert_equal(wallet.getprivatebalance()["trusted"], Decimal("0.50"))

        self.log.info("Consolidate fifty notes into one private self-payment")
        result = wallet.send(
            outputs={wallet.getnewaddress("", "bech32x"): Decimal("0.50")},
            options={"private": True, "subtract_fee_from_outputs": [0], "fee_rate": 1},
        )
        decoded = node.decoderawtransaction(node.getrawtransaction(result["txid"]))
        assert_equal(decoded["private_bundle"]["actions"], 50)
        assert decoded["weight"] <= 400000
        self.generate(node, 1)
        assert_equal(wallet.getprivatebalance()["spendable_notes"], 1)
        # A confirmed batch output can fund the next consolidation/payment.
        wallet.sendprivate(wallet.getnewaddress("", "bech32x"), Decimal("0.01"), fee_rate=1)
        self.generate(node, 1)


if __name__ == "__main__":
    PrivateSelectionTest().main()
