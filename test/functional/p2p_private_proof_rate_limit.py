#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the Orchard P2P proof-verification budget through real ATMP paths."""

import time
from decimal import Decimal

from test_framework.messages import (
    NODE_NETWORK,
    NODE_NITO_PRIVATE,
    NODE_WITNESS,
    tx_from_hex,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


PRIVATE_SERVICES = NODE_NETWORK | NODE_WITNESS | NODE_NITO_PRIVATE
MAX_PRIVATE_ACTIONS = 50


class PrivateProofRateLimitTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Each 50-action Halo2 proof takes about 25 seconds on a single worker;
        # parallel functional tests can compete for the same CPU. TestNode uses
        # half this value for each RPC call. This does not change the proof budget.
        self.rpc_timeout = 180
        self.extra_args = [
            ["-privateactivationheight=1"],
            ["-privateactivationheight=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def make_shield_transaction(self, wallet, action_count, *, inputs=None):
        outputs = {
            wallet.getnewaddress("", "bech32x"): Decimal("0.001")
            for _ in range(action_count)
        }
        options = {
            "add_to_wallet": False,
            "fee_rate": 1,
            "lock_unspents": True,
        }
        if inputs is not None:
            options.update({"add_inputs": False, "inputs": inputs})
        start = time.monotonic()
        result = wallet.send(outputs=outputs, options=options)
        self.log.info("Created %d-action proof in %.2f seconds", action_count, time.monotonic() - start)
        assert_equal(result["complete"], True)
        tx = tx_from_hex(result["hex"])
        tx.rehash()
        decoded = self.nodes[0].decoderawtransaction(result["hex"])
        assert_equal(decoded["has_private_bundle"], True)
        assert_equal(decoded["private_bundle"]["actions"], action_count)
        return tx

    def run_test(self):
        source, target = self.nodes
        wallet = source.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Fund the source wallet and give both nodes the same activated chain")
        # Keep several distinct mature coinbases available because each
        # unbroadcast proof transaction deliberately locks its selected input.
        self.generate(source, 110)
        self.sync_blocks()
        self.disconnect_nodes(0, 1)

        # Put the target's monotonic validation clock safely ahead of startup
        # time, then advance it deterministically for exact bucket refills.
        target.setmocktime(int(time.time()) + 3600)
        peer = target.add_p2p_connection(P2PDataStore(), services=PRIVATE_SERVICES)

        self.log.info("Two maximum-action transactions consume the full P2P verification burst")
        first = self.make_shield_transaction(wallet, MAX_PRIVATE_ACTIONS)
        second = self.make_shield_transaction(wallet, MAX_PRIVATE_ACTIONS)
        peer.send_txs_and_test([first, second], target, success=True)

        self.log.info("A third valid transaction is deferred without entering recent_rejects")
        retry = self.make_shield_transaction(wallet, MAX_PRIVATE_ACTIONS)
        peer.send_txs_and_test(
            [retry],
            target,
            success=False,
            reject_reason="private-proof-rate-limited",
        )
        target.bumpmocktime(1)
        peer.send_txs_and_test([retry], target, success=True)

        self.log.info("A limited orphan is removed and can be relayed again after refill")
        parent_address = wallet.getnewaddress()
        parent_result = wallet.send(
            outputs={parent_address: Decimal("1")},
            options={"fee_rate": 1},
        )
        parent_hex = source.getrawtransaction(parent_result["txid"])
        parent = tx_from_hex(parent_hex)
        parent.rehash()
        parent_decoded = source.decoderawtransaction(parent_hex)
        parent_vout = next(
            output["n"]
            for output in parent_decoded["vout"]
            if output["scriptPubKey"].get("address") == parent_address
        )
        orphan = self.make_shield_transaction(
            wallet,
            MAX_PRIVATE_ACTIONS,
            inputs=[{"txid": parent_result["txid"], "vout": parent_vout}],
        )

        peer.send_txs_and_test([orphan], target, success=False)
        with target.assert_debug_log(["deferred orphan Orchard proof verification"]):
            peer.send_txs_and_test([parent], target, success=True)
        assert orphan.hash not in target.getrawmempool()

        target.bumpmocktime(1)
        peer.send_txs_and_test([orphan], target, success=True)
        assert orphan.hash in target.getrawmempool()


if __name__ == "__main__":
    PrivateProofRateLimitTest().main()
