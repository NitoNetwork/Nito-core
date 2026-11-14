#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Recover explicit private self-payments separately from change to the same address."""

from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

PASSPHRASE = "private history regression"
ARGS = ["-orchardindex=1", "-transparenthistoryindex=1", "-keypool=20", "-fastprune"]


class PrivateReusedHistoryTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [ARGS]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 101)
        node.createwallet("source", descriptors=True, passphrase=PASSPHRASE, load_on_startup=True)
        source = node.get_wallet_rpc("source")
        source.walletpassphrase(PASSPHRASE, 600)
        phrase = source.dumpmnemonic()["mnemonic"]
        address = source.getnewaddress("", "bech32x")
        miner.sendtoaddress(address, Decimal("2"))
        self.generate(node, 1)

        node.createwallet("locked_copy", descriptors=True, blank=True, passphrase=PASSPHRASE, load_on_startup=True)
        locked = node.get_wallet_rpc("locked_copy")
        locked.walletpassphrase(PASSPHRASE, 600)
        locked.sethdseed(True, phrase)
        assert_equal(locked.getprivatebalance()["trusted"], Decimal("2"))
        locked.walletlock()

        self.log.info("A private payment and its change return to the same funded receiver")
        txid = source.sendprivate(address, Decimal("0.75"))
        self.generate(node, 1)
        self_block = node.getbestblockhash()
        expected = [("receive", Decimal("0.75")), ("send", Decimal("-0.75"))]

        def check_self(rpc):
            tx = rpc.gettransaction(txid)
            assert_equal(sorted((r["category"], r["amount"]) for r in tx["details"]), expected)
            rows = [r for r in rpc.listtransactions("*", 1000) if r["txid"] == txid]
            assert_equal(sorted((r["category"], r["amount"]) for r in rows), expected)
            assert_equal(tx["private_external_credit"], Decimal("0.75"))
            assert_equal(tx["private_internal_credit"], tx["private_debit"] - Decimal("0.75") + tx["fee"])
            assert_equal(tx["amount"], Decimal("0"))

        check_self(source)
        self.log.info("A payment to another wallet excludes only the sender's real change")
        other_address = miner.getnewaddress("", "bech32x")
        external = source.sendprivate(other_address, Decimal("0.25"))
        self.generate(node, 1)

        def check_external(rpc):
            tx = rpc.gettransaction(external)
            assert_equal([(r["category"], r["amount"]) for r in tx["details"]], [("send", Decimal("-0.25"))])
            assert_equal(tx["private_external_credit"], Decimal("0"))

        check_external(source)
        received = miner.gettransaction(external)
        assert_equal(received["private_external_credit"], Decimal("0.25"))
        assert_equal(received["private_internal_credit"], Decimal("0"))
        balance = source.getprivatebalance()["trusted"]
        node.invalidateblock(self_block)
        node.reconsiderblock(self_block)
        check_self(source)
        check_external(source)
        assert_equal(source.getprivatebalance()["trusted"], balance)

        self.log.info("Restart and complete phrase restoration reconstruct the same classification")
        self.restart_node(0)
        source = node.get_wallet_rpc("source")
        assert_raises_rpc_error(-13, "passphrase", source.getprivatebalance)
        source.walletpassphrase(PASSPHRASE, 600)
        check_self(source)
        check_external(source)
        node.createwallet("restored", descriptors=True, blank=True)
        restored = node.get_wallet_rpc("restored")
        restored.sethdseed(True, phrase)
        check_self(restored)
        check_external(restored)
        assert_equal(restored.getprivatebalance()["trusted"], balance)

        self.log.info("Locked history catches up through the index after its blocks are pruned")
        self.restart_node(0, ARGS + ["-prune=1", "-transparenthistoryindex=0"])
        self.generate(node, 800)
        self.wait_until(lambda: node.getindexinfo()["orchardindex"]["best_block_height"] == node.getblockcount())
        assert_greater_than(node.pruneblockchain(node.getblockcount() - 300), 104)
        assert_raises_rpc_error(-1, "pruned data", node.getblock, self_block)
        self.restart_node(0, ARGS + ["-prune=1", "-transparenthistoryindex=0"])
        locked = node.get_wallet_rpc("locked_copy")
        assert_equal(locked.getwalletinfo()["seed_history"]["locked_live"]["status"], "pending")
        locked.walletpassphrase(PASSPHRASE, 600)
        assert_equal(locked.getwalletinfo()["seed_history"]["locked_live"]["status"], "complete")
        check_self(locked)
        check_external(locked)
        assert_equal(locked.getprivatebalance()["trusted"], balance)
        locked.walletlock()
        locked.walletpassphrase(PASSPHRASE, 600)
        check_self(locked)


if __name__ == "__main__":
    PrivateReusedHistoryTest().main()
