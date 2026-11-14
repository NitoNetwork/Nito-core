#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test loading an encrypted Orchard wallet that fell behind while unloaded."""

from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

ACTIVATION_HEIGHT = 5
MAX_MINING_TRIES = 10_000_000
PASSPHRASE = "locked load test passphrase"
WALLET_NAME = "encrypted_private_locked_load"


class WalletPrivateLockedLoadTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f"-privateactivationheight={ACTIVATION_HEIGHT}",
            "-orchardindex=1",
        ]]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_address(self, node, count, address):
        self.generatetoaddress(
            node,
            count,
            address,
            MAX_MINING_TRIES,
            sync_fun=self.no_op,
        )
        node.syncwithvalidationinterfacequeue()

    def wait_for_orchard_index(self, node, height):
        def index_ready():
            info = node.getindexinfo("orchardindex").get("orchardindex")
            return info is not None and info["synced"] and info["best_block_height"] == height

        self.wait_until(index_ready)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create an encrypted Orchard wallet before activation")
        node.createwallet(wallet_name=WALLET_NAME, descriptors=True, passphrase=PASSPHRASE)
        locked_wallet = node.get_wallet_rpc(WALLET_NAME)
        locked_wallet.walletpassphrase(PASSPHRASE, 600)
        transparent_address = locked_wallet.getnewaddress("", "bech32")
        locked_wallet.walletlock()

        node.createwallet(wallet_name="miner", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        miner_address = miner.getnewaddress("", "bech32")
        self.mine_to_address(node, ACTIVATION_HEIGHT - 1, miner_address)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)

        self.log.info("Unload the encrypted wallet, then cross activation with a transparent payment")
        node.unloadwallet(WALLET_NAME)
        self.mine_to_address(node, 1, transparent_address)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)
        activation_block = node.getbestblockhash()
        self.wait_for_orchard_index(node, ACTIVATION_HEIGHT)

        self.log.info("Loading while locked must preserve transparent scan and defer Orchard exactly")
        node.loadwallet(WALLET_NAME)
        locked_wallet = node.get_wallet_rpc(WALLET_NAME)
        assert_greater_than(locked_wallet.getbalances()["mine"]["immature"], Decimal("0"))
        first_pending = locked_wallet.getwalletinfo()["seed_history"]["locked_live"]
        assert_equal(first_pending["status"], "pending")
        assert_equal(first_pending["start_height"], ACTIVATION_HEIGHT)
        assert_equal(first_pending["start_block"], activation_block)
        assert_equal(first_pending["target_height"], ACTIVATION_HEIGHT)
        assert_equal(first_pending["target_block"], activation_block)
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", locked_wallet.getprivatebalance)

        self.log.info("The deferred obligation must survive another locked reload without widening")
        first_generation = first_pending["generation"]
        node.unloadwallet(WALLET_NAME)
        node.loadwallet(WALLET_NAME)
        locked_wallet = node.get_wallet_rpc(WALLET_NAME)
        reloaded_pending = locked_wallet.getwalletinfo()["seed_history"]["locked_live"]
        assert_equal(reloaded_pending["status"], "pending")
        assert_equal(reloaded_pending["start_height"], ACTIVATION_HEIGHT)
        assert_equal(reloaded_pending["target_height"], ACTIVATION_HEIGHT)
        assert_equal(reloaded_pending["generation"], first_generation)

        self.log.info("Unlock performs the one deferred Orchard catch-up and clears it")
        locked_wallet.walletpassphrase(PASSPHRASE, 600)
        assert_equal(locked_wallet.getwalletinfo()["seed_history"]["locked_live"]["status"], "complete")
        private_address = locked_wallet.getnewaddress("", "bech32x")
        locked_wallet.walletlock()
        node.unloadwallet(WALLET_NAME)

        self.log.info("Let the unloaded wallet fall behind and create an unconfirmed Orchard receive")
        self.mine_to_address(node, 101, miner_address)
        self.wait_for_orchard_index(node, node.getblockcount())
        private_txid = miner.sendtoaddress(private_address, Decimal("0.01"))
        self.wait_until(lambda: private_txid in node.getrawmempool())

        self.log.info("Locked load defers confirmed Orchard history and does not expose mempool notes")
        node.loadwallet(WALLET_NAME)
        locked_wallet = node.get_wallet_rpc(WALLET_NAME)
        second_pending = locked_wallet.getwalletinfo()["seed_history"]["locked_live"]
        assert_equal(second_pending["status"], "pending")
        assert_equal(second_pending["start_height"], ACTIVATION_HEIGHT)
        assert_equal(second_pending["target_height"], node.getblockcount())
        known_locked_txids = {
            entry["txid"] for entry in locked_wallet.listtransactions("*", 1000, 0, True)
        }
        assert private_txid not in known_locked_txids
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", locked_wallet.getprivatebalance)

        self.log.info("Unlock catches up the exact range, then replays the current mempool once")
        locked_wallet.walletpassphrase(PASSPHRASE, 600)
        self.wait_until(
            lambda: locked_wallet.getprivatebalance()["untrusted_pending"] == Decimal("0.01"),
            timeout=240,
        )
        assert_equal(locked_wallet.getprivatebalance()["total_unspent"], Decimal("0.01"))
        known_unlocked_txids = {
            entry["txid"] for entry in locked_wallet.listtransactions("*", 1000, 0, True)
        }
        assert private_txid in known_unlocked_txids
        assert_equal(locked_wallet.getwalletinfo()["seed_history"]["locked_live"]["status"], "complete")

        self.log.info("Only attach-time catch-up is deferred; explicit rescans remain locked")
        locked_wallet.walletlock()
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", locked_wallet.rescanblockchain, 0)


if __name__ == "__main__":
    WalletPrivateLockedLoadTest().main()
