#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Remove private mempool entries when a reorg disables their next block."""

from decimal import Decimal

from test_framework.blocktools import NORMAL_GBT_REQUEST_PARAMS
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal

ACTIVATION_HEIGHT = 110
MAX_MINING_TRIES = 10_000_000


class PrivateMempoolActivationReorgTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False, legacy=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-privateactivationheight={ACTIVATION_HEIGHT}", "-persistmempool=0"]]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_height(self, height):
        node = self.nodes[0]
        while node.getblockcount() < height:
            self.generatetoaddress(node, height - node.getblockcount(), node.getnewaddress(), MAX_MINING_TRIES)
        assert_equal(node.getblockcount(), height)

    def spend_transparent(self, txid, vout, value):
        node = self.nodes[0]
        raw = node.createrawtransaction(
            [{"txid": txid, "vout": vout}],
            {node.getnewaddress(): value - Decimal("0.001")},
            0,
            True,
        )
        signed = node.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        return node.sendrawtransaction(signed["hex"]), signed["hex"]

    def template_txids(self, height):
        template = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_equal(template["height"], height)
        return {entry["txid"] for entry in template["transactions"]}

    def run_test(self):
        node = self.nodes[0]
        self.mine_to_height(ACTIVATION_HEIGHT)
        first_active_block = node.getbestblockhash()
        previous_block = node.getblockhash(ACTIVATION_HEIGHT - 1)

        # Both coinbases remain mature even after the rewind to H-2. Otherwise
        # the existing maturity filter could hide the missing activation check.
        available = sorted(node.listunspent(), key=lambda entry: entry["confirmations"], reverse=True)
        shield_input, independent_input = available[:2]
        assert shield_input["confirmations"] >= 103
        assert independent_input["confirmations"] >= 103
        node.lockunspent(False, [
            {"txid": entry["txid"], "vout": entry["vout"]}
            for entry in available
            if entry != shield_input
        ])
        shield_result = node.send(
            outputs={node.getnewaddress("", "bech32x"): Decimal("1")},
            options={"locktime": 0, "private": False, "fee_rate": 1, "add_to_wallet": False},
        )
        shield_raw = shield_result["hex"]
        shield = node.sendrawtransaction(shield_raw)
        decoded = node.decoderawtransaction(shield_raw)
        assert_equal(decoded["locktime"], 0)
        assert_equal(decoded["vin"][0]["txid"], shield_input["txid"])
        change = next(output for output in decoded["vout"] if output["value"] > 0)
        child, child_raw = self.spend_transparent(shield, change["n"], change["value"])
        independent, _ = self.spend_transparent(
            independent_input["txid"], independent_input["vout"], independent_input["amount"]
        )
        expected = {shield, child, independent}
        assert_equal(set(node.getrawmempool()), expected)

        self.log.info("At H-1, private entries and their transparent children remain eligible for block H")
        node.invalidateblock(first_active_block)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert_equal(set(node.getrawmempool()), expected)
        assert_equal(self.template_txids(ACTIVATION_HEIGHT), expected)
        self.mine_to_height(ACTIVATION_HEIGHT)
        assert expected.issubset(set(node.getblock(node.getbestblockhash())["tx"]))
        assert_equal(node.getrawmempool(), [])

        self.log.info("Disconnect H and H-1 together: resurrect at H-1, then remove private entries at H-2")
        node.invalidateblock(previous_block)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 2)
        assert_equal(set(node.getrawmempool()), {independent})
        rejected = node.testmempoolaccept([shield_raw])[0]
        assert_equal(rejected["allowed"], False)
        assert_equal(rejected["reject-reason"], "bad-private-before-activation")
        assert_equal(self.template_txids(ACTIVATION_HEIGHT - 1), {independent})

        self.log.info("Transparent mining advances to H-1, where the same private package is valid again")
        self.mine_to_height(ACTIVATION_HEIGHT - 1)
        assert_equal(node.testmempoolaccept([shield_raw])[0]["allowed"], True)
        assert_equal(node.sendrawtransaction(shield_raw), shield)
        assert_equal(node.sendrawtransaction(child_raw), child)
        assert_equal(self.template_txids(ACTIVATION_HEIGHT), {shield, child})
        self.mine_to_height(ACTIVATION_HEIGHT)
        assert {shield, child}.issubset(set(node.getblock(node.getbestblockhash())["tx"]))
        assert_equal(node.getrawmempool(), [])
        assert_equal(node.getblockchaininfo()["activated"], True)


if __name__ == "__main__":
    PrivateMempoolActivationReorgTest().main()
