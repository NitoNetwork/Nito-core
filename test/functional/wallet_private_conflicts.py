#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test private-note spend availability errors and Orchard nullifier conflicts."""

from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)


MAX_MINING_TRIES = 10_000_000
MNEMONIC_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
MNEMONIC_12_ALT = "legal winner thank year wave sausage worth useful legal winner thank yellow"
MNEMONIC_12_NOBROADCAST = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"


class WalletPrivateConflictsTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-privateactivationheight=1", "-orchardindex=1"],
            ["-privateactivationheight=1", "-orchardindex=1"],
        ]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_height(self, node, wallet, height, sync_fun=None):
        blocks = []
        while node.getblockcount() < height:
            blocks.extend(self.generatetoaddress(
                node,
                height - node.getblockcount(),
                wallet.getnewaddress(),
                MAX_MINING_TRIES,
                sync_fun=sync_fun or self.sync_all,
            ))
        assert_equal(node.getblockcount(), height)
        return blocks

    def run_test(self):
        node_a, node_b = self.nodes

        self.log.info("Mine spendable transparent funds")
        node_a.createwallet(wallet_name="miner", descriptors=True)
        miner = node_a.get_wallet_rpc("miner")
        self.mine_to_height(node_a, miner, 101)

        self.log.info("A pending-only private note tells the user to wait for a block")
        node_a.createwallet(wallet_name="empty_private", blank=True, descriptors=True)
        empty_wallet = node_a.get_wallet_rpc("empty_private")
        empty_wallet.sethdseed(True, MNEMONIC_12)
        assert_raises_rpc_error(
            -6,
            "No spendable private notes are available.",
            empty_wallet.sendprivate,
            empty_wallet.getnewaddress(),
            Decimal("0.01"),
        )

        node_a.createwallet(wallet_name="pending_private", blank=True, descriptors=True)
        pending_wallet = node_a.get_wallet_rpc("pending_private")
        pending_wallet.sethdseed(True, MNEMONIC_12)
        pending_txid = miner.sendtoaddress(pending_wallet.getnewaddress("", "bech32x"), Decimal("0.03"))
        assert pending_txid in node_a.getrawmempool()
        node_a.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: pending_wallet.getprivatebalance()["untrusted_pending"] >= Decimal("0.03"), timeout=240)
        assert_raises_rpc_error(
            -6,
            "Private funds are waiting for confirmation. Wait for the next block before spending private notes.",
            pending_wallet.sendprivate,
            pending_wallet.getnewaddress(),
            Decimal("0.01"),
        )

        self.log.info("A private transaction that cannot be broadcast is abandoned and releases its note")
        node_a.createwallet(wallet_name="nobroadcast_private", blank=True, descriptors=True)
        nobroadcast_wallet = node_a.get_wallet_rpc("nobroadcast_private")
        nobroadcast_wallet.sethdseed(True, MNEMONIC_12_NOBROADCAST)
        nobroadcast_funding_txid = miner.sendtoaddress(nobroadcast_wallet.getnewaddress("", "bech32x"), Decimal("0.05"))
        self.mine_to_height(node_a, miner, node_a.getblockcount() + 1)
        node_a.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: nobroadcast_wallet.gettransaction(nobroadcast_funding_txid)["confirmations"] >= 1, timeout=240)
        self.wait_until(lambda: nobroadcast_wallet.getprivatebalance()["spendable_notes"] == 1, timeout=240)

        self.restart_node(0, self.extra_args[0] + ["-walletbroadcast=0"])
        node_a = self.nodes[0]
        for wallet_name in ("miner", "nobroadcast_private"):
            if wallet_name not in node_a.listwallets():
                node_a.loadwallet(wallet_name)
        miner = node_a.get_wallet_rpc("miner")
        nobroadcast_wallet = node_a.get_wallet_rpc("nobroadcast_private")
        assert_raises_rpc_error(
            -4,
            "Nito.network private transactions must be broadcast immediately so private notes are not locked locally without relay.",
            nobroadcast_wallet.sendprivate,
            miner.getnewaddress(),
            Decimal("0.01"),
        )
        node_a.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: nobroadcast_wallet.getprivatebalance()["spendable_notes"] == 1, timeout=240)

        self.restart_node(0, self.extra_args[0])
        node_a = self.nodes[0]
        if "miner" not in node_a.listwallets():
            node_a.loadwallet("miner")
        miner = node_a.get_wallet_rpc("miner")
        self.connect_nodes(0, 1)
        self.sync_blocks([node_a, node_b], timeout=180)

        self.log.info("A network mempool private spend marks the observed note unavailable before confirmation")
        node_a.createwallet(wallet_name="mempool_observer_a", blank=True, descriptors=True)
        observer_a = node_a.get_wallet_rpc("mempool_observer_a")
        observer_a.sethdseed(True, MNEMONIC_12_ALT)

        node_b.createwallet(wallet_name="mempool_observer_b", blank=True, descriptors=True)
        observer_b = node_b.get_wallet_rpc("mempool_observer_b")
        observer_b.sethdseed(True, MNEMONIC_12_ALT)

        observed_funding_txid = miner.sendtoaddress(observer_a.getnewaddress("", "bech32x"), Decimal("0.04"))
        self.mine_to_height(node_a, miner, node_a.getblockcount() + 1)
        self.sync_blocks([node_a, node_b], timeout=180)
        node_a.syncwithvalidationinterfacequeue()
        node_b.syncwithvalidationinterfacequeue()

        for wallet in (observer_a, observer_b):
            self.wait_until(lambda w=wallet: w.gettransaction(observed_funding_txid)["confirmations"] >= 1, timeout=240)
            self.wait_until(lambda w=wallet: w.getprivatebalance()["spendable_notes"] == 1, timeout=240)

        observed_spend_txid = observer_b.sendprivate(miner.getnewaddress(), Decimal("0.01"))
        self.sync_mempools([node_a, node_b], timeout=180)
        node_a.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: observed_spend_txid in node_a.getrawmempool(), timeout=180)
        self.wait_until(lambda: observer_a.getprivatebalance()["spendable_notes"] == 0, timeout=240)
        assert_raises_rpc_error(
            -6,
            "Private funds are waiting for confirmation. Wait for the next block before spending private notes.",
            observer_a.sendprivate,
            observer_a.getnewaddress(),
            Decimal("0.01"),
        )

        self.log.info("Create the same deterministic private wallet on two connected nodes")
        node_a.createwallet(wallet_name="conflict_a", blank=True, descriptors=True)
        wallet_a = node_a.get_wallet_rpc("conflict_a")
        wallet_a.sethdseed(True, MNEMONIC_12)

        node_b.createwallet(wallet_name="conflict_b", blank=True, descriptors=True)
        wallet_b = node_b.get_wallet_rpc("conflict_b")
        wallet_b.sethdseed(True, MNEMONIC_12)

        self.log.info("Confirm one private note visible to both same-seed wallets")
        funding_txid = miner.sendtoaddress(wallet_a.getnewaddress("", "bech32x"), Decimal("0.10"))
        self.mine_to_height(node_a, miner, node_a.getblockcount() + 1)
        self.sync_blocks([node_a, node_b], timeout=180)
        node_a.syncwithvalidationinterfacequeue()
        node_b.syncwithvalidationinterfacequeue()

        for wallet in (wallet_a, wallet_b):
            self.wait_until(lambda w=wallet: w.gettransaction(funding_txid)["confirmations"] >= 1, timeout=240)
            self.wait_until(lambda w=wallet: w.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("Spend the same private note independently on two disconnected nodes")
        self.disconnect_nodes(0, 1)
        tx_a = wallet_a.sendprivate(wallet_a.getnewaddress(), Decimal("0.01"))
        tx_b = wallet_b.sendprivate(wallet_b.getnewaddress(), Decimal("0.02"))
        assert tx_a in node_a.getrawmempool()
        assert tx_b in node_b.getrawmempool()

        self.log.info("Mine the second spend, reconnect, and ensure the losing tx is marked conflicted")
        self.mine_to_height(node_b, wallet_b, node_b.getblockcount() + 1, sync_fun=self.no_op)
        self.wait_until(lambda: wallet_b.gettransaction(tx_b)["confirmations"] >= 1, timeout=240)
        self.connect_nodes(0, 1)
        self.sync_blocks([node_a, node_b], timeout=180)
        node_a.syncwithvalidationinterfacequeue()

        self.wait_until(lambda: wallet_a.gettransaction(tx_a)["confirmations"] < 0, timeout=240)
        losing = wallet_a.gettransaction(tx_a)
        winning = wallet_a.gettransaction(tx_b)
        assert_greater_than_or_equal(winning["confirmations"], 1)
        assert_equal(-losing["confirmations"], winning["confirmations"])
        assert tx_a not in node_a.getrawmempool()


if __name__ == "__main__":
    WalletPrivateConflictsTest().main()
