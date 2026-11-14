#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Keep explicit self-payments visible when their address also funded the inputs."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import COIN, CTxOut, tx_from_hex
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


class ReusedAddressHistoryTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-transparenthistoryindex=1", "-orchardindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        address = wallet.getnewaddress("reused receive", "bech32")
        target = COINBASE_MATURITY + 1
        while node.getblockcount() < target:
            self.generatetoaddress(node, target - node.getblockcount(), address, 10_000_000)
        coin = wallet.listunspent()[0]
        amounts = (Decimal("0.25"), Decimal("0.50"))
        raw = node.createrawtransaction(
            [{"txid": coin["txid"], "vout": coin["vout"]}],
            {address: sum(amounts)},
        )
        funded = wallet.fundrawtransaction(raw, {"fee_rate": 2, "add_inputs": False})
        tx = tx_from_hex(funded["hex"])
        recipient = 1 - funded["changepos"]
        script = tx.vout[recipient].scriptPubKey
        # Raw construction permits two outputs to the same address; the funding
        # RPC intentionally rejects duplicate keys in its address interface.
        tx.vout[recipient:recipient + 1] = [CTxOut(int(value * COIN), script) for value in amounts]
        signed = wallet.signrawtransactionwithwallet(tx.serialize().hex())
        txid = node.sendrawtransaction(signed["hex"])

        def check_history(rpc):
            details = rpc.gettransaction(txid)["details"]
            expected = sorted((category, value if category == "receive" else -value)
                              for category in ("send", "receive") for value in amounts)
            actual = sorted((row["category"], row["amount"]) for row in details)
            assert_equal(actual, expected)
            assert_equal(len({row["vout"] for row in details}), 2)
            assert all(row["address"] == address for row in details)
            rows = [row for row in rpc.listtransactions("*", 1000) if row["txid"] == txid]
            assert_equal(sorted((row["category"], row["amount"]) for row in rows), expected)
            assert_equal(rpc.gettransaction(txid)["amount"], Decimal("0"))
            assert_equal(rpc.gettransaction(txid)["fee"], -funded["fee"])

        self.log.info("Both explicit outputs remain visible, with internal change excluded")
        check_history(wallet)
        self.generatetoaddress(node, 1, address, 10_000_000)
        check_history(wallet)
        self.restart_node(0)
        wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        check_history(wallet)

        if self.options.descriptors:
            self.log.info("Complete phrase restore preserves the same self-payment rows")
            mnemonic = wallet.dumpmnemonic()["mnemonic"]
            node = self.nodes[0]
            node.createwallet(wallet_name="restored", blank=True, descriptors=True)
            restored = node.get_wallet_rpc("restored")
            restored.sethdseed(True, mnemonic)
            check_history(restored)


if __name__ == "__main__":
    ReusedAddressHistoryTest().main()
