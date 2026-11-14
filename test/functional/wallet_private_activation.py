#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Bech32x/Orchard wallet gating around the activation height."""

from decimal import Decimal

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    NODE_NETWORK,
    NODE_WITNESS,
    msg_block,
    msg_headers,
)
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
)
from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

MAX_MINING_TRIES = 10_000_000


class WalletPrivateActivationTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False, legacy=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-privateactivationheight=110"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_height(self, node, wallet, height):
        blocks = []
        while node.getblockcount() < height:
            blocks.extend(self.generatetoaddress(
                node,
                height - node.getblockcount(),
                wallet.getnewaddress(),
                MAX_MINING_TRIES,
            ))
        assert_equal(node.getblockcount(), height)
        return blocks

    def assert_inactive_error(self, current_height, fn, *args, code=-4, **kwargs):
        assert_raises_rpc_error(
            code,
            f"Nito.network private transactions activate at block 110. Current block: {current_height}.",
            fn,
            *args,
            **kwargs,
        )

    def assert_orchard_index(self, node, height):
        def index_synced_at_height():
            info = node.getindexinfo("orchardindex").get("orchardindex")
            return info is not None and info["synced"] is True and info["best_block_height"] == height

        self.wait_until(index_synced_at_height)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="private_activation", descriptors=False)
        wallet = node.get_wallet_rpc("private_activation")
        network_info = node.getnetworkinfo()
        assert_equal(int(network_info["localservices"], 16) & P2P_SERVICES, P2P_SERVICES)
        assert "NITO_PRIVATE" in network_info["localservicesnames"]

        self.log.info("The local Orchard scan index is created before activation and follows the tip")
        self.assert_orchard_index(node, 0)

        self.log.info("Before activation, private address generation is hidden")
        self.assert_inactive_error(0, wallet.getnewaddress, "", "bech32x")
        self.assert_inactive_error(0, wallet.getprivatebalance)
        self.assert_inactive_error(0, wallet.listprivateunspent)
        self.assert_inactive_error(0, wallet.listdescriptors, True)
        assert "private" not in wallet.getbalances()

        self.log.info("Before activation, legacy service peers may stay connected")
        legacy_services_peer = node.add_p2p_connection(P2PInterface(), services=NODE_NETWORK | NODE_WITNESS)
        legacy_services_peer.wait_for_verack()
        no_services_peer = node.add_p2p_connection(P2PInterface(), services=0)
        no_services_peer.wait_for_verack()
        old_version_private_peer = node.add_p2p_connection(P2PInterface(version=70016), services=P2P_SERVICES)
        old_version_private_peer.wait_for_verack()

        self.log.info("Mine spendable transparent funds while still below activation")
        self.mine_to_height(node, wallet, 101)
        self.assert_orchard_index(node, 101)
        self.assert_inactive_error(101, wallet.getnewaddress, "", "bech32x")
        assert "private" not in wallet.getbalances()

        self.log.info("Transparent version 3 transactions keep the V3 policy/consensus split before activation")
        spendable = wallet.listunspent()[0]
        raw_v2 = node.createrawtransaction(
            [{"txid": spendable["txid"], "vout": spendable["vout"]}],
            {wallet.getnewaddress(): Decimal("1")},
            0,
            True,
        )
        raw_v3 = "03000000" + raw_v2[8:]
        signed_v3 = wallet.signrawtransactionwithwallet(raw_v3)
        assert_equal(signed_v3["complete"], True)
        assert_equal(node.decoderawtransaction(signed_v3["hex"])["version"], 3)
        assert_raises_rpc_error(-26, "version", node.sendrawtransaction, signed_v3["hex"])

        self.log.info("A legacy peer may provide H and is disconnected as soon as H becomes active")
        self.mine_to_height(node, wallet, 109)
        tip_hash = node.getbestblockhash()
        activation_block = create_block(
            int(tip_hash, 16),
            create_coinbase(110),
            node.getblock(tip_hash)["time"] + 1,
        )
        activation_block.solve()
        legacy_services_peer.last_message.pop("getdata", None)
        legacy_services_peer.send_message(msg_headers([activation_block]))
        legacy_services_peer.wait_for_getdata([activation_block.sha256])
        legacy_services_peer.send_message(msg_block(activation_block))
        legacy_services_peer.wait_for_disconnect(timeout=5)
        self.wait_until(lambda: node.getblockcount() == 110)
        activation_blocks = [activation_block.hash]

        v4_services_peer = node.add_p2p_connection(P2PInterface(), services=P2P_SERVICES)
        v4_services_peer.wait_for_verack()

        self.log.info("At the activation height, private address generation is allowed")
        no_services_peer.wait_for_disconnect(timeout=5)
        old_version_private_peer.wait_for_disconnect(timeout=5)
        v4_services_peer.sync_with_ping()
        self.assert_orchard_index(node, 110)
        private_addr = wallet.getnewaddress("", "bech32x")
        assert_equal(node.validateaddress(private_addr)["address_type"], "bech32x")
        assert_equal(wallet.getaddressinfo(private_addr)["address_type"], "bech32x")
        assert "private" in wallet.getbalances()
        assert wallet.getprivatebalance()["total_unspent"] == Decimal("0")
        assert_equal(wallet.listprivateunspent(), [])
        assert not any(desc["desc"].startswith("or(") for desc in wallet.listdescriptors(True)["descriptors"])
        assert_raises_rpc_error(-26, "version", node.sendrawtransaction, signed_v3["hex"])

        self.log.info("A reorg below activation disables private spending again")
        node.invalidateblock(activation_blocks[0])
        assert_equal(node.getblockcount(), 109)
        self.assert_orchard_index(node, 109)
        self.assert_inactive_error(109, wallet.getprivatebalance)
        self.assert_inactive_error(109, wallet.listprivateunspent)
        self.assert_inactive_error(109, wallet.listdescriptors, True)
        self.assert_inactive_error(109, wallet.getaddressinfo, private_addr)
        assert "private" not in wallet.getbalances()
        self.assert_inactive_error(109, wallet.sendtoaddress, private_addr, Decimal("0.1"), code=-6)
        self.assert_inactive_error(
            109,
            wallet.sendtoaddress,
            wallet.getnewaddress(),
            Decimal("0.1"),
            "",
            "",
            False,
            True,
            None,
            "unset",
            None,
            None,
            False,
            True,
            code=-6,
        )

        self.log.info("The peer capability latch survives the reorg and a full node restart")
        post_reorg_legacy_peer = node.add_p2p_connection(
            P2PInterface(), services=NODE_NETWORK | NODE_WITNESS, wait_for_verack=False
        )
        post_reorg_legacy_peer.wait_for_disconnect(timeout=5)
        self.restart_node(0)
        node = self.nodes[0]
        node.loadwallet("private_activation")
        wallet = node.get_wallet_rpc("private_activation")
        assert_equal(node.getblockcount(), 109)
        post_restart_legacy_peer = node.add_p2p_connection(
            P2PInterface(version=70016), services=P2P_SERVICES, wait_for_verack=False
        )
        post_restart_legacy_peer.wait_for_disconnect(timeout=5)

        self.log.info("Once reconsidered above activation, transparent-to-private works")
        node.reconsiderblock(activation_blocks[0])
        assert_equal(node.getblockcount(), 110)
        self.assert_orchard_index(node, 110)
        txid = wallet.sendtoaddress(private_addr, Decimal("0.1"))
        assert_equal(txid in node.getrawmempool(), True)
        self.mine_to_height(node, wallet, node.getblockcount() + 1)
        assert_equal(node.getrawmempool(), [])


if __name__ == "__main__":
    WalletPrivateActivationTest().main()
