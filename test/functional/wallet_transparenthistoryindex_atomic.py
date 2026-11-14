#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Prove transparent history events and the index locator commit atomically."""

import os
import signal
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


BASE_ARGS = [
    "-privateactivationheight=1",
    "-orchardindex=1",
    "-transparenthistoryindex=1",
    "-persistmempool=0",
]
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


class TransparentHistoryIndexAtomicTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [BASE_ARGS, BASE_ARGS]
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def wait_for_index(self, node):
        tip_height = node.getblockcount()

        def index_at_tip():
            info = node.getindexinfo("transparenthistoryindex").get("transparenthistoryindex")
            return (
                info is not None
                and info["synced"] is True
                and info["best_block_height"] == tip_height
            )

        self.wait_until(index_at_tip, timeout=180)

    def crash_node(self, node):
        node.process.kill()
        expected_ret_code = 1 if os.name == "nt" else -signal.SIGKILL
        self.wait_until(
            lambda: node.is_node_stopped(expected_ret_code=expected_ret_code),
            timeout=30,
        )

    def signed_conflict(self, node, utxo, destination, destination_amount):
        fee = Decimal("0.00100000")
        change_amount = utxo["amount"] - destination_amount - fee
        assert change_amount > 0
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            {
                destination: destination_amount,
                node.getrawchangeaddress("bech32"): change_amount,
            },
        )
        signed = node.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        decoded = node.decoderawtransaction(signed["hex"])
        return signed["hex"], decoded["txid"]

    def run_test(self):
        node0, node1 = self.nodes

        self.log.info("Build a common chain and a deterministic recovery destination")
        node0.createwallet(wallet_name="source", descriptors=True, load_on_startup=True)
        node1.createwallet(wallet_name="alternate_miner", descriptors=True, load_on_startup=True)
        source = node0.get_wallet_rpc("source")
        alternate_miner = node1.get_wallet_rpc("alternate_miner")
        self.generatetoaddress(node0, COINBASE_MATURITY + 1, source.getnewaddress())
        self.wait_for_index(node0)
        self.wait_for_index(node1)

        node0.createwallet(wallet_name="atomic_reference", blank=True, descriptors=True)
        reference = node0.get_wallet_rpc("atomic_reference")
        reference.sethdseed(True, MNEMONIC)
        destination = reference.getnewaddress("", "bech32")

        utxo = next(coin for coin in source.listunspent() if coin["amount"] > Decimal("3"))
        old_hex, old_txid = self.signed_conflict(source, utxo, destination, Decimal("1.00000000"))
        alternate_hex, alternate_txid = self.signed_conflict(source, utxo, destination, Decimal("2.00000000"))
        assert old_txid != alternate_txid

        self.log.info("Prepare a longer alternate branch without exposing it to node 0")
        self.disconnect_nodes(0, 1)
        assert_equal(node1.sendrawtransaction(alternate_hex), alternate_txid)
        self.generatetoaddress(node1, 2, alternate_miner.getnewaddress(), sync_fun=self.no_op)
        alternate_tip = node1.getbestblockhash()

        self.log.info("Crash after the old-branch event is staged but before its locator commit")
        committed_height = node0.getblockcount()
        delayed_args = [*BASE_ARGS, "-transparenthistoryindexcommitdelay=60000"]
        self.restart_node(0, delayed_args)
        node0 = self.nodes[0]
        source = node0.get_wallet_rpc("source")
        assert_equal(node0.sendrawtransaction(old_hex), old_txid)
        with node0.assert_debug_log(
            ["transparenthistoryindex: delaying atomic append commit"],
            timeout=30,
        ):
            self.generatetoaddress(node0, 1, source.getnewaddress(), sync_fun=self.no_op)

        # A reader must not see staged events as indexed before their commit.
        advertised_height = node0.getindexinfo("transparenthistoryindex")["transparenthistoryindex"]["best_block_height"]
        self.connect_nodes(0, 1)
        self.wait_until(lambda: node0.getbestblockhash() == alternate_tip, timeout=60)
        # Force the alternate active chain to disk while the index callback is
        # still paused in the pre-commit window.
        node0.gettxoutsetinfo("none")
        assert_equal(node0.getbestblockhash(), alternate_tip)
        self.crash_node(node0)
        assert_equal(advertised_height, committed_height)

        self.log.info("Restart on the alternate branch and rebuild a fresh wallet")
        self.start_node(0, BASE_ARGS)
        node0 = self.nodes[0]
        assert_equal(node0.getbestblockhash(), alternate_tip)
        self.wait_for_index(node0)

        node0.createwallet(wallet_name="atomic_restore", blank=True, descriptors=True)
        restored = node0.get_wallet_rpc("atomic_restore")
        restored.sethdseed(True, MNEMONIC)
        assert_equal(restored.getbalances()["mine"]["trusted"], Decimal("2.00000000"))
        assert_equal(len(restored.listunspent()), 1)
        assert_equal(restored.listunspent()[0]["txid"], alternate_txid)
        restored_txids = {entry["txid"] for entry in restored.listtransactions("*", 1000)}
        assert alternate_txid in restored_txids
        assert old_txid not in restored_txids


if __name__ == "__main__":
    TransparentHistoryIndexAtomicTest().main()
