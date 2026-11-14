#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Orchard recovery scans from a restored BIP39 seed."""

import os
from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

MAX_MINING_TRIES = 10_000_000
# Public fixture, distinct from every wallet-file encryption password below.
BIP39_PASSPHRASE = "Orchard restore \u00e9 with spaces "
# Optional environment overrides select recovery fixtures; the defaults below
# are public deterministic test vectors.
MNEMONIC_12 = os.environ.get(
    "NITO_TEST_MNEMONIC_FULL",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
)
MNEMONIC_LOCKED = os.environ.get(
    "NITO_TEST_MNEMONIC_ENCRYPTED",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
)
GAP_LIMIT_LAST_INDEX = 63
EXTENDED_GAP_LAST_INDEX = 127
FAR_GAP_INDEX = 1000
TRANSPARENT_RECOVERY_MAX_INDEX = 1001
TRANSPARENT_RECOVERY_KEYPOOL_SIZE = TRANSPARENT_RECOVERY_MAX_INDEX + 1
TRANSPARENT_RECOVERY_KEYPOOL_ARG = f"-keypool={TRANSPARENT_RECOVERY_KEYPOOL_SIZE}"
TRANSPARENT_RECOVERY_BOUNDARY_INDICES = {999, 1000, 1001}


class WalletPrivateRestoreTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.extra_args = [
            ["-privateactivationheight=1"],
            [
                "-privateactivationheight=1",
                "-orchardindex=1",
                "-transparenthistoryindex=1",
                TRANSPARENT_RECOVERY_KEYPOOL_ARG,
            ],
            [
                "-privateactivationheight=1",
                "-orchardindex=1",
                "-transparenthistoryindex=1",
                TRANSPARENT_RECOVERY_KEYPOOL_ARG,
            ],
            [
                "-privateactivationheight=1",
                "-orchardindex=0",
                "-transparenthistoryindex=1",
                TRANSPARENT_RECOVERY_KEYPOOL_ARG,
            ],
        ]
        self.rpc_timeout = 120

    def setup_network(self):
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_height(self, node, wallet, height):
        while node.getblockcount() < height:
            self.generatetoaddress(
                node,
                height - node.getblockcount(),
                wallet.getnewaddress(),
                MAX_MINING_TRIES,
                sync_fun=self.no_op,
            )
        assert_equal(node.getblockcount(), height)

    def run_test(self):
        source_node = self.nodes[0]
        restore_node = self.nodes[1]
        indexed_node = self.nodes[2]
        lagged_index_node = self.nodes[3]

        self.log.info("Mine transparent funds and activate private transactions on the source node")
        source_node.createwallet(wallet_name="miner", descriptors=True)
        miner = source_node.get_wallet_rpc("miner")
        self.mine_to_height(source_node, miner, 101)

        self.log.info("Create private receive addresses at the recovery gap edge and after extension")
        source_node.createwallet(wallet_name="plain_private_reference", blank=True, descriptors=True)
        plain_private_reference = source_node.get_wallet_rpc("plain_private_reference")
        plain_private_reference.sethdseed(True, MNEMONIC_LOCKED, BIP39_PASSPHRASE)
        expected_private_address = plain_private_reference.getnewaddress("", "bech32x")

        self.log.info("Encrypted seed restore protects Bech32x wallet data while locked")
        passphrase = "private restore passphrase"
        source_node.createwallet(wallet_name="encrypted_private_restore", blank=True, descriptors=True, passphrase=passphrase)
        encrypted_private_restore = source_node.get_wallet_rpc("encrypted_private_restore")
        encrypted_private_restore.walletpassphrase(passphrase, 600)
        encrypted_private_restore.sethdseed(True, MNEMONIC_LOCKED, BIP39_PASSPHRASE)
        encrypted_private_restore.walletlock()
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", encrypted_private_restore.getnewaddress, "", "bech32x")
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", encrypted_private_restore.getprivatebalance)
        assert "private" not in encrypted_private_restore.getbalances()
        encrypted_private_restore.walletpassphrase(passphrase, 600)
        restored_private_address = encrypted_private_restore.getnewaddress("", "bech32x")
        assert_equal(restored_private_address, expected_private_address)
        restored_address_info = encrypted_private_restore.getaddressinfo(restored_private_address)
        assert_equal(restored_address_info["address_type"], "bech32x")
        restored_receive_txid = miner.sendtoaddress(restored_private_address, Decimal("0.07"))
        self.mine_to_height(source_node, miner, source_node.getblockcount() + 1)
        self.wait_until(lambda: encrypted_private_restore.getprivatebalance()["total_unspent"] == Decimal("0.07"), timeout=240)
        restored_notes = encrypted_private_restore.listprivateunspent()
        assert any(note["txid"] == restored_receive_txid and note["spendable"] for note in restored_notes)

        self.log.info("Receive another Orchard note while encrypted wallet keys are locked")
        encrypted_private_restore.walletlock()
        locked_receive_txid = miner.sendtoaddress(restored_private_address, Decimal("0.03"))
        self.mine_to_height(source_node, miner, source_node.getblockcount() + 1)
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", encrypted_private_restore.getprivatebalance)
        locked_pending = encrypted_private_restore.getwalletinfo()["seed_history"]["locked_live"]
        assert_equal(locked_pending["status"], "pending")
        assert_equal(locked_pending["target_height"], source_node.getblockcount())
        assert_equal(locked_pending["target_block"], source_node.getbestblockhash())
        encrypted_private_restore.walletpassphrase(passphrase, 600)
        self.wait_until(
            lambda: encrypted_private_restore.getprivatebalance()["total_unspent"] == Decimal("0.10"),
            timeout=240,
        )
        assert any(note["txid"] == locked_receive_txid for note in encrypted_private_restore.listprivateunspent())
        assert_greater_than_or_equal(encrypted_private_restore.gettransaction(locked_receive_txid)["confirmations"], 1)
        assert_equal(encrypted_private_restore.getwalletinfo()["seed_history"]["locked_live"]["status"], "complete")

        source_node.createwallet(wallet_name="deep_private_source", blank=True, descriptors=True)
        source_wallet = source_node.get_wallet_rpc("deep_private_source")
        source_wallet.sethdseed(True, MNEMONIC_12, BIP39_PASSPHRASE)
        assert_equal(source_wallet.dumpmnemonic()["scope"], "full_wallet")

        self.log.info("Fund transparent recovery addresses at indexes 999, 1000, and 1001")
        transparent_recovery_addresses = {}
        for index in range(TRANSPARENT_RECOVERY_KEYPOOL_SIZE):
            address = source_wallet.getnewaddress("", "bech32")
            if index in TRANSPARENT_RECOVERY_BOUNDARY_INDICES:
                transparent_recovery_addresses[index] = address
        transparent_recovery_txids = {
            miner.sendtoaddress(transparent_recovery_addresses[index], amount)
            for index, amount in zip(
                sorted(TRANSPARENT_RECOVERY_BOUNDARY_INDICES),
                [Decimal("0.01"), Decimal("0.02"), Decimal("0.03")],
            )
        }
        self.mine_to_height(source_node, miner, source_node.getblockcount() + 1)
        assert_equal(source_wallet.getbalances()["mine"]["trusted"], Decimal("0.06"))

        private_addresses = {}
        for index in range(EXTENDED_GAP_LAST_INDEX + 1):
            address = source_wallet.getnewaddress("", "bech32x")
            if index in {GAP_LIMIT_LAST_INDEX, EXTENDED_GAP_LAST_INDEX}:
                private_addresses[index] = address

        first_txid = miner.sendtoaddress(private_addresses[GAP_LIMIT_LAST_INDEX], Decimal("0.11"))
        self.mine_to_height(source_node, miner, source_node.getblockcount() + 1)
        second_txid = miner.sendtoaddress(private_addresses[EXTENDED_GAP_LAST_INDEX], Decimal("0.12"))
        self.mine_to_height(source_node, miner, source_node.getblockcount() + 1)

        self.wait_until(lambda: source_wallet.getprivatebalance()["total_unspent"] >= Decimal("0.23"), timeout=240)
        chained_addr = source_wallet.getnewaddress("", "bech32x")
        chained_txid = source_wallet.sendprivate(chained_addr, Decimal("0.05"))
        self.mine_to_height(source_node, miner, source_node.getblockcount() + 1)
        self.wait_until(lambda: source_wallet.gettransaction(chained_txid)["confirmations"] >= 1, timeout=240)

        self.log.info("Create a self private transaction after a large unused Bech32x gap")
        for _ in range(FAR_GAP_INDEX - EXTENDED_GAP_LAST_INDEX - 1):
            source_wallet.getnewaddress("", "bech32x")
        far_gap_addr = source_wallet.getnewaddress("", "bech32x")
        far_gap_txid = source_wallet.sendprivate(far_gap_addr, Decimal("0.01"))
        self.mine_to_height(source_node, miner, source_node.getblockcount() + 1)
        self.wait_until(lambda: source_wallet.gettransaction(far_gap_txid)["confirmations"] >= 1, timeout=240)
        expected_private_balance = source_wallet.getprivatebalance()["total_unspent"]

        self.log.info("Check that the normal source wallet keeps complete private history")
        assert_greater_than_or_equal(source_wallet.gettransaction(first_txid)["confirmations"], 1)
        assert_greater_than_or_equal(source_wallet.gettransaction(second_txid)["confirmations"], 1)
        assert_greater_than_or_equal(source_wallet.gettransaction(chained_txid)["confirmations"], 1)
        assert_greater_than_or_equal(source_wallet.gettransaction(far_gap_txid)["confirmations"], 1)
        source_history_txids = {entry["txid"] for entry in source_wallet.listtransactions("*", 100, 0, True)}
        assert first_txid in source_history_txids
        assert second_txid in source_history_txids
        assert chained_txid in source_history_txids
        assert far_gap_txid in source_history_txids

        self.log.info("Refuse an incomplete historical restore while orchardindex is disabled")
        self.connect_nodes(3, 0)
        self.sync_blocks([source_node, lagged_index_node], timeout=180)
        lagged_index_node.createwallet(
            wallet_name="restore_after_index_lag",
            blank=True,
            descriptors=True,
            load_on_startup=True,
        )
        lagged_wallet = lagged_index_node.get_wallet_rpc("restore_after_index_lag")
        assert_raises_rpc_error(
            -4,
            "requires -orchardindex=1",
            lagged_wallet.sethdseed,
            True,
            MNEMONIC_12,
            BIP39_PASSPHRASE,
        )

        self.log.info("Restore the same seed on an unsynced node with recovery indexes enabled")
        assert_equal(restore_node.getblockcount(), 0)
        assert "orchardindex" in restore_node.getindexinfo()
        restore_node.createwallet(wallet_name="restore_during_sync", blank=True, descriptors=True)
        restored_wallet = restore_node.get_wallet_rpc("restore_during_sync")
        restored_wallet.sethdseed(True, MNEMONIC_12, BIP39_PASSPHRASE)

        self.log.info("Sync the restored node and recover Orchard notes from the activation range")
        self.connect_nodes(1, 0)
        self.sync_blocks([source_node, restore_node], timeout=180)
        restore_node.syncwithvalidationinterfacequeue()

        self.wait_until(lambda: restored_wallet.getprivatebalance()["total_unspent"] == expected_private_balance, timeout=240)
        assert transparent_recovery_txids.issubset(
            {entry["txid"] for entry in restored_wallet.listunspent(1)}
        )
        notes = restored_wallet.listprivateunspent()
        spendable_notes = [note for note in notes if note["spendable"]]
        assert_greater_than_or_equal(len(spendable_notes), 2)
        for note in spendable_notes:
            assert_greater_than_or_equal(note["commitment_index"], 0)
        assert_greater_than_or_equal(restored_wallet.getprivatekeymaninfo()["next_external_index"], FAR_GAP_INDEX + 1)
        assert_greater_than_or_equal(restored_wallet.gettransaction(first_txid)["confirmations"], 1)
        assert_greater_than_or_equal(restored_wallet.gettransaction(second_txid)["confirmations"], 1)
        assert_greater_than_or_equal(restored_wallet.gettransaction(chained_txid)["confirmations"], 1)
        assert_greater_than_or_equal(restored_wallet.gettransaction(far_gap_txid)["confirmations"], 1)
        restored_history_txids = {entry["txid"] for entry in restored_wallet.listtransactions("*", 100, 0, True)}
        assert first_txid in restored_history_txids
        assert second_txid in restored_history_txids
        assert chained_txid in restored_history_txids
        assert far_gap_txid in restored_history_txids

        self.log.info("Restore the same seed with synced compact orchardindex")
        self.connect_nodes(2, 0)
        self.sync_blocks([source_node, indexed_node], timeout=180)
        indexed_node.syncwithvalidationinterfacequeue()

        def indexes_ready():
            info = indexed_node.getindexinfo()
            orchard = info.get("orchardindex")
            history = info.get("transparenthistoryindex")
            height = indexed_node.getblockcount()
            return (
                orchard is not None and orchard["synced"] is True and orchard["best_block_height"] == height
                and history is not None and history["synced"] is True and history["best_block_height"] == height
            )

        self.wait_until(indexes_ready, timeout=180)
        self.log.info("The phrase alone cannot recover either funded passphrase-derived domain")
        indexed_node.createwallet(wallet_name="phrase_without_passphrase", blank=True, descriptors=True)
        phrase_only_wallet = indexed_node.get_wallet_rpc("phrase_without_passphrase")
        phrase_only_wallet.sethdseed(True, MNEMONIC_12)
        assert_equal(phrase_only_wallet.getbalance(), 0)
        assert_equal(phrase_only_wallet.getprivatebalance()["total_unspent"], 0)
        assert_equal(phrase_only_wallet.listprivateunspent(), [])

        indexed_node.createwallet(wallet_name="indexed_restore", blank=True, descriptors=True)
        indexed_wallet = indexed_node.get_wallet_rpc("indexed_restore")
        indexed_wallet.sethdseed(True, MNEMONIC_12, BIP39_PASSPHRASE)
        self.wait_until(lambda: indexed_wallet.getprivatebalance()["total_unspent"] == expected_private_balance, timeout=240)
        assert transparent_recovery_txids.issubset(
            {entry["txid"] for entry in indexed_wallet.listunspent(1)}
        )
        indexed_full_state = indexed_wallet.getwalletinfo()["seed_history"]
        assert_equal(indexed_full_state["mode"], "full_history")
        assert_equal(indexed_full_state["transparent"]["restore_funds"]["status"], "complete")
        assert_equal(indexed_full_state["orchard"]["restore_funds"]["status"], "complete")
        assert_equal(indexed_full_state["transparent"]["explicit_history"]["status"], "complete")
        assert_equal(indexed_full_state["orchard"]["explicit_history"]["status"], "complete")
        indexed_notes = indexed_wallet.listprivateunspent()
        indexed_spendable_notes = [note for note in indexed_notes if note["spendable"]]
        assert_greater_than_or_equal(len(indexed_spendable_notes), 2)
        for note in indexed_spendable_notes:
            assert note["txid"] in {first_txid, second_txid, chained_txid, far_gap_txid}
            assert_greater_than_or_equal(note["blockheight"], 1)
            assert_greater_than_or_equal(note["confirmations"], 1)
            assert_greater_than_or_equal(note["commitment_index"], 0)
        indexed_all_notes = indexed_wallet.listprivateunspent(1, True)
        assert_greater_than_or_equal(len([note for note in indexed_all_notes if note["spent"]]), 1)
        assert_greater_than_or_equal(indexed_wallet.getprivatekeymaninfo()["next_external_index"], FAR_GAP_INDEX + 1)
        indexed_history_txids = {entry["txid"] for entry in indexed_wallet.listtransactions("*", 100, 0, True)}
        assert first_txid in indexed_history_txids
        assert second_txid in indexed_history_txids
        assert chained_txid in indexed_history_txids
        assert far_gap_txid in indexed_history_txids
        for txid in [first_txid, second_txid, chained_txid, far_gap_txid]:
            assert_greater_than_or_equal(indexed_wallet.gettransaction(txid)["confirmations"], 1)

        self.log.info("A same-height reorg advances the automatic full-history hash anchor")
        self.disconnect_nodes(2, 0)
        anchored_height = indexed_node.getblockcount()
        anchored_hash = indexed_node.getbestblockhash()
        indexed_node.invalidateblock(anchored_hash)
        self.mine_to_height(indexed_node, indexed_wallet, anchored_height)
        assert indexed_node.getbestblockhash() != anchored_hash
        indexed_node.syncwithvalidationinterfacequeue()
        indexed_node.unloadwallet("indexed_restore")
        indexed_node.loadwallet("indexed_restore")
        indexed_wallet = indexed_node.get_wallet_rpc("indexed_restore")
        indexed_history_state = indexed_wallet.getwalletinfo()["seed_history"]
        assert_equal(indexed_history_state["full_history_height"], indexed_node.getblockcount())
        assert_equal(indexed_history_state["full_history_block"], indexed_node.getbestblockhash())

        indexed_node.reconsiderblock(anchored_hash)
        self.mine_to_height(source_node, miner, anchored_height + 2)
        self.connect_nodes(2, 0)
        self.sync_blocks([source_node, indexed_node], timeout=180)
        self.wait_until(
            lambda: indexed_wallet.getprivatebalance()["total_unspent"] == expected_private_balance,
            timeout=240,
        )

        self.log.info("Spend a recovered Orchard note from the indexed seed restore")
        recovered_spend_txid = indexed_wallet.sendprivate(miner.getnewaddress(), Decimal("0.01"))
        self.sync_mempools([source_node, indexed_node], timeout=180)
        self.mine_to_height(source_node, miner, source_node.getblockcount() + 1)
        self.sync_blocks([source_node, indexed_node], timeout=180)
        assert_greater_than_or_equal(indexed_wallet.gettransaction(recovered_spend_txid)["confirmations"], 1)

        self.log.info("Restore, reload, and spend the second seed from an encrypted wallet")
        encrypted_indexed_passphrase = "encrypted indexed restore passphrase"
        indexed_node.createwallet(
            wallet_name="encrypted_indexed_restore",
            blank=True,
            descriptors=True,
            passphrase=encrypted_indexed_passphrase,
        )
        encrypted_indexed_wallet = indexed_node.get_wallet_rpc("encrypted_indexed_restore")
        encrypted_indexed_wallet.walletpassphrase(encrypted_indexed_passphrase, 600)
        encrypted_indexed_wallet.sethdseed(True, MNEMONIC_LOCKED, BIP39_PASSPHRASE)
        self.wait_until(
            lambda: encrypted_indexed_wallet.getprivatebalance()["total_unspent"] == Decimal("0.10"),
            timeout=240,
        )
        assert_equal(encrypted_indexed_wallet.dumpmnemonic()["mnemonic"], MNEMONIC_LOCKED)
        encrypted_indexed_wallet.walletlock()
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", encrypted_indexed_wallet.getprivatebalance)

        indexed_node.unloadwallet("encrypted_indexed_restore")
        indexed_node.loadwallet("encrypted_indexed_restore")
        encrypted_indexed_wallet = indexed_node.get_wallet_rpc("encrypted_indexed_restore")
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", encrypted_indexed_wallet.getprivatebalance)
        assert_equal(encrypted_indexed_wallet.getwalletinfo()["bip39_passphrase_enabled"], True)
        encrypted_indexed_wallet.walletpassphrase(encrypted_indexed_passphrase, 600)
        assert_equal(encrypted_indexed_wallet.dumpmnemonic()["mnemonic"], MNEMONIC_LOCKED)
        assert_equal(encrypted_indexed_wallet.dumpmnemonic()["bip39_passphrase_required"], True)

        encrypted_recovered_spend_txid = encrypted_indexed_wallet.sendprivate(miner.getnewaddress(), Decimal("0.02"))
        self.sync_mempools([source_node, indexed_node], timeout=180)
        self.mine_to_height(source_node, miner, source_node.getblockcount() + 1)
        self.sync_blocks([source_node, indexed_node], timeout=180)
        assert_greater_than_or_equal(
            encrypted_indexed_wallet.gettransaction(encrypted_recovered_spend_txid)["confirmations"],
            1,
        )


if __name__ == "__main__":
    WalletPrivateRestoreTest().main()
