#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the exact P2P transition at the Nito private activation height."""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    CBlockHeader,
    CTransaction,
    HeaderAndShortIDs,
    NODE_NETWORK,
    NODE_NITO_PRIVATE,
    NODE_WITNESS,
    msg_cmpctblock,
    msg_headers,
)
from test_framework.p2p import (
    P2PDataStore,
    P2PInterface,
    p2p_lock,
)
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


ACTIVATION_HEIGHT = 3
LEGACY_SERVICES = NODE_NETWORK | NODE_WITNESS
PRIVATE_SERVICES = LEGACY_SERVICES | NODE_NITO_PRIVATE


class PrivatePeerActivationTest(NitoTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-privateactivationheight={ACTIVATION_HEIGHT}"]]

    def assert_rejected_peer(self, *, services, version=70017):
        node = self.nodes[0]
        # Observe the TCP connection before sending the version that triggers
        # immediate rejection, so a fast disconnect cannot hide that connection.
        peer = node.add_p2p_connection(
            P2PInterface(version=version),
            services=services,
            send_version=False,
            wait_for_verack=False,
        )
        peer.peer_connect_send_version(services)
        with node.assert_debug_log(["does not meet Nito private activation requirements"]):
            peer.send_version()
            peer.wait_for_disconnect()

    @staticmethod
    def next_block(node):
        best_hash = node.getbestblockhash()
        best = node.getblock(best_hash)
        height = best["height"] + 1
        template = node.getblocktemplate({"rules": ["segwit"]})
        block = create_block(int(best_hash, 16), create_coinbase(height), template["curtime"])
        block.nVersion = template["version"]
        block.nBits = int(template["bits"], 16)
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Reach H-1 through a private-capable peer")
        capable = node.add_p2p_connection(P2PDataStore(), services=PRIVATE_SERVICES)
        while node.getblockcount() < ACTIVATION_HEIGHT - 1:
            capable.send_blocks_and_test([self.next_block(node)], node, success=True)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        node.disconnect_p2ps()

        self.log.info("A legacy H compact block with missing transactions falls back to the full block")
        compact_legacy = node.add_p2p_connection(P2PInterface(), services=LEGACY_SERVICES)
        ambiguous_h = self.next_block(node)
        missing_tx = CTransaction()
        missing_tx.rehash()
        ambiguous_h.vtx.append(missing_tx)
        ambiguous_h.hashMerkleRoot = ambiguous_h.calc_merkle_root()
        ambiguous_h.solve()
        compact = HeaderAndShortIDs()
        compact.initialize_from_block(ambiguous_h, prefill_list=[0], use_witness=True)
        compact_legacy.send_message(msg_cmpctblock(compact.to_p2p()))
        compact_legacy.wait_until(lambda: "getdata" in compact_legacy.last_message)
        with p2p_lock:
            assert "getblocktxn" not in compact_legacy.last_message
            assert_equal(compact_legacy.last_message["getdata"].inv[0].hash, ambiguous_h.sha256)
        node.disconnect_p2ps()

        self.log.info("A legacy peer may provide H and is disconnected immediately afterwards")
        legacy = node.add_p2p_connection(P2PDataStore(), services=LEGACY_SERVICES)
        activation_block = self.next_block(node)
        with p2p_lock:
            legacy.block_store[activation_block.sha256] = activation_block
            legacy.last_block_hash = activation_block.sha256
        legacy.send_message(msg_headers([CBlockHeader(activation_block)]))
        legacy.wait_until(
            lambda: activation_block.sha256 in legacy.getdata_requests,
            check_connected=True,
        )
        legacy.wait_for_disconnect()
        self.wait_until(lambda: node.getbestblockhash() == activation_block.hash)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)
        assert activation_block.sha256 in legacy.getdata_requests

        self.log.info("After H, NODE_NITO_PRIVATE without protocol 70017 is insufficient")
        self.assert_rejected_peer(services=PRIVATE_SERVICES, version=70016)

        self.log.info("After H, protocol 70017 without NODE_NITO_PRIVATE is insufficient")
        self.assert_rejected_peer(services=LEGACY_SERVICES)

        self.log.info("A peer satisfying both requirements remains connected")
        compatible = node.add_p2p_connection(P2PInterface(), services=PRIVATE_SERVICES)
        compatible.sync_with_ping()
        assert compatible.is_connected

        self.log.info("The durable activation latch survives a full -reindex")
        node.disconnect_p2ps()
        self.restart_node(0, extra_args=[
            f"-privateactivationheight={ACTIVATION_HEIGHT}",
            "-reindex",
        ])
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)
        self.assert_rejected_peer(services=LEGACY_SERVICES)


if __name__ == "__main__":
    PrivatePeerActivationTest().main()
