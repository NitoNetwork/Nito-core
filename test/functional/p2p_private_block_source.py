#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that an Orchard activation block is accepted only from a capable source."""

from decimal import Decimal

from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    NODE_NETWORK,
    NODE_NITO_PRIVATE,
    NODE_WITNESS,
    msg_block,
    tx_from_hex,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


ACTIVATION_HEIGHT = 102
LEGACY_SERVICES = NODE_NETWORK | NODE_WITNESS
PRIVATE_SERVICES = LEGACY_SERVICES | NODE_NITO_PRIVATE
MAX_MINING_TRIES = 10_000_000


class PrivateBlockSourceTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False, legacy=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            [f"-privateactivationheight={ACTIVATION_HEIGHT}"],
            ["-privateactivationheight=0"],
        ]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        target, builder = self.nodes
        builder.createwallet(wallet_name="builder", descriptors=False)
        wallet = builder.get_wallet_rpc("builder")

        self.log.info("Build a common spendable transparent chain through H-1")
        self.generatetoaddress(
            builder,
            ACTIVATION_HEIGHT - 1,
            wallet.getnewaddress(),
            MAX_MINING_TRIES,
        )
        self.sync_blocks()
        assert_equal(target.getblockcount(), ACTIVATION_HEIGHT - 1)

        self.log.info("Construct a valid H block containing a shielding Orchard transaction")
        private_address = wallet.getnewaddress("", "bech32x")
        private_txid = wallet.sendtoaddress(private_address, Decimal("1.0"))
        template = builder.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        private_txs = [
            tx_from_hex(entry["data"])
            for entry in template["transactions"]
            if entry["txid"] == private_txid
        ]
        assert_equal(len(private_txs), 1)
        block = create_block(tmpl=template, txlist=private_txs)
        add_witness_commitment(block)
        block.solve()
        self.disconnect_nodes(0, 1)

        self.log.info("A legacy source is disconnected without poisoning the block hash")
        legacy = target.add_p2p_connection(P2PDataStore(), services=LEGACY_SERVICES)
        legacy.send_message(msg_block(block))
        legacy.wait_for_disconnect()
        assert_equal(target.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert all(tip["hash"] != block.hash for tip in target.getchaintips())

        self.log.info("The exact same block hash is accepted from proto 70017 plus NODE_NITO_PRIVATE")
        capable = target.add_p2p_connection(P2PDataStore(), services=PRIVATE_SERVICES)
        capable.send_blocks_and_test([block], target, success=True, force_send=True)
        assert_equal(target.getbestblockhash(), block.hash)
        assert_equal(target.getblockcount(), ACTIVATION_HEIGHT)


if __name__ == "__main__":
    PrivateBlockSourceTest().main()
