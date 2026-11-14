#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reset an empty Orchard index after postponing activation, preserving transparent state."""

import time

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


RESET_LOG = "Reinitialized empty Orchard index for activation height change"
INDEX_NAMES = ("txindex", "orchardindex", "transparenthistoryindex")


class OrchardActivationResetTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.wallet_names = [False]
        self.extra_args = [self.node_args(200)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def node_args(activation_height):
        return [
            f"-privateactivationheight={activation_height}",
            "-txindex=1", "-orchardindex=1", "-transparenthistoryindex=1", "-keypool=20",
        ]

    def wait_for_indexes(self):
        node = self.nodes[0]
        height = node.getblockcount()

        def all_synced():
            indexes = node.getindexinfo()
            return all(
                indexes.get(name, {}).get("synced") is True
                and indexes[name]["best_block_height"] == height
                for name in INDEX_NAMES
            )

        self.wait_until(all_synced)

    def mine(self, count, address):
        node = self.nodes[0]
        for _ in range(count):
            node.setmocktime(max(int(time.time()), node.getblockheader(node.getbestblockhash())["time"] + 121))
            self.generatetoaddress(node, 1, address, maxtries=10_000_000)
        self.wait_for_indexes()

    def snapshot(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc("reference")
        return {
            "height": node.getblockcount(),
            "tip": node.getbestblockhash(),
            "balances": wallet.getbalances(),
            "utxos": sorted(wallet.listunspent(), key=lambda coin: (coin["txid"], coin["vout"])),
            "history": wallet.listtransactions("*", 1000),
            "indexes": node.getindexinfo(),
        }

    def restart_at_tip(self, activation_height):
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getbestblockhash())["time"] + 121
        self.restart_node(0, [*self.node_args(activation_height), f"-mocktime={mocktime}"])
        self.wait_for_indexes()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="reference", descriptors=True, load_on_startup=True)
        wallet = node.get_wallet_rpc("reference")
        mining_address = wallet.getnewaddress()

        self.log.info("Fund a transparent wallet and its indexes before Orchard activation")
        self.mine(110, mining_address)
        wallet.sendtoaddress(wallet.getnewaddress("transparent payment"), 1)
        self.mine(1, mining_address)
        before = self.snapshot()
        assert before["utxos"]

        self.log.info("Postponing activation resets only the empty Orchard index")
        with node.assert_debug_log([RESET_LOG], unexpected_msgs=["Wiping LevelDB"]):
            self.restart_at_tip(300)
        assert_equal(self.snapshot(), before)
        assert_equal(node.getblockchaininfo()["privateTxActivationHeight"], 300)
        assert_equal(node.getblockchaininfo()["activated"], False)

        self.log.info("The replacement checkpoint survives restart without another reset")
        with node.assert_debug_log([], unexpected_msgs=[RESET_LOG]):
            self.restart_at_tip(300)
        assert_equal(self.snapshot(), before)

        self.log.info("All indexes continue following newly connected blocks")
        self.mine(2, mining_address)
        after = self.snapshot()
        assert_equal(after["height"], before["height"] + 2)
        with node.assert_debug_log([], unexpected_msgs=[RESET_LOG]):
            self.restart_at_tip(300)
        assert_equal(self.snapshot(), after)


if __name__ == "__main__":
    OrchardActivationResetTest().main()
