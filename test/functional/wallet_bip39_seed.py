#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP39 wallet seed export and restore."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletBIP39SeedTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-blockfilterindex=1", "-orchardindex=1", "-transparenthistoryindex=1"]]
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    MNEMONIC_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    MNEMONIC_24 = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"

    def assert_mnemonic_info(self, wallet_rpc, expected_words=24, expected_scope="full_wallet", expected_seed_type="bip39_pbkdf2_master_seed", expected_passphrase_required=False):
        mnemonic_info = wallet_rpc.dumpmnemonic()
        assert_equal(mnemonic_info["words"], expected_words)
        assert_equal(mnemonic_info["format"], "bip39-english")
        assert_equal(mnemonic_info["seed_type"], expected_seed_type)
        assert_equal(mnemonic_info["scope"], expected_scope)
        assert_equal(mnemonic_info["bip39_passphrase_required"], expected_passphrase_required)
        assert_equal(wallet_rpc.getwalletinfo()["bip39_passphrase_enabled"], expected_passphrase_required)
        mnemonic = mnemonic_info["mnemonic"]
        assert_equal(len(mnemonic.split()), expected_words)
        return mnemonic

    def run_test(self):
        node = self.nodes[0]
        first_address = node.getnewaddress()
        mnemonic = self.assert_mnemonic_info(
            node,
            expected_seed_type="bip39_pbkdf2_master_seed" if self.options.descriptors else "legacy_hd_entropy",
        )

        restore_name = "descriptor_mnemonic_restore" if self.options.descriptors else "legacy_mnemonic_restore"
        node.createwallet(wallet_name=restore_name, blank=True, descriptors=self.options.descriptors)
        restore_rpc = node.get_wallet_rpc(restore_name)
        restore_rpc.sethdseed(True, mnemonic)
        if not self.options.descriptors:
            upgrade = restore_rpc.upgradeorchardwallet(mnemonic)
            assert_equal(upgrade["bip39_passphrase_required"], False)
        assert_equal(restore_rpc.getwalletinfo()["blank"], False)
        assert_equal(self.assert_mnemonic_info(
            restore_rpc,
            expected_scope="full_wallet" if self.options.descriptors else "orchard_only",
            expected_seed_type="bip39_pbkdf2_master_seed" if self.options.descriptors else "orchard_root_entropy",
        ), mnemonic)
        assert_raises_rpc_error(-5, "Invalid BIP39 mnemonic checksum", restore_rpc.sethdseed, True, " ".join(["abandon"] * 24))
        assert_raises_rpc_error(-5, "Invalid BIP39 mnemonic checksum", restore_rpc.sethdseed, True, " ".join(["abandon"] * 12))
        default_rpc = node.get_wallet_rpc(self.default_wallet_name)

        if self.options.descriptors:
            assert_equal(restore_rpc.getnewaddress(), first_address)
            assert_raises_rpc_error(-4, "Descriptor wallet HD seed can only be set on a blank descriptor wallet", default_rpc.sethdseed, True, mnemonic)

            node.createwallet(wallet_name="mnemonic12_plain", blank=True, descriptors=True)
            plain_rpc = node.get_wallet_rpc("mnemonic12_plain")
            plain_rpc.sethdseed(True, self.MNEMONIC_12)
            address_plain = plain_rpc.getnewaddress()
            assert_equal(self.assert_mnemonic_info(plain_rpc, 12), self.MNEMONIC_12)

            self.log.info("Test optional BIP39 passphrase RPC contract and NFKD equivalence")
            node.createwallet(wallet_name="mnemonic12_passphrase", blank=True, descriptors=True)
            passphrase_rpc = node.get_wallet_rpc("mnemonic12_passphrase")
            passphrase_rpc.sethdseed(True, self.MNEMONIC_12, "TREZOR")
            address_passphrase = passphrase_rpc.getnewaddress()
            assert address_passphrase != address_plain
            assert_equal(self.assert_mnemonic_info(passphrase_rpc, 12, expected_passphrase_required=True), self.MNEMONIC_12)

            node.createwallet(wallet_name="mnemonic12_passphrase_restore", blank=True, descriptors=True)
            passphrase_restore_rpc = node.get_wallet_rpc("mnemonic12_passphrase_restore")
            passphrase_restore_rpc.sethdseed(True, self.MNEMONIC_12, "TREZOR")
            assert_equal(passphrase_restore_rpc.getnewaddress(), address_passphrase)

            node.createwallet(wallet_name="mnemonic12_wrong_passphrase", blank=True, descriptors=True)
            wrong_passphrase_rpc = node.get_wallet_rpc("mnemonic12_wrong_passphrase")
            wrong_passphrase_rpc.sethdseed(True, self.MNEMONIC_12, "TREZOS")
            assert wrong_passphrase_rpc.getnewaddress() != address_passphrase

            node.createwallet(wallet_name="mnemonic12_explicit_empty", blank=True, descriptors=True)
            explicit_empty_rpc = node.get_wallet_rpc("mnemonic12_explicit_empty")
            explicit_empty_rpc.sethdseed(True, self.MNEMONIC_12, "")
            assert_equal(explicit_empty_rpc.getnewaddress(), address_plain)
            assert_equal(explicit_empty_rpc.dumpmnemonic()["bip39_passphrase_required"], False)

            node.createwallet(wallet_name="mnemonic12_nfkd_composed", blank=True, descriptors=True)
            nfkd_composed_rpc = node.get_wallet_rpc("mnemonic12_nfkd_composed")
            nfkd_composed_rpc.sethdseed(True, self.MNEMONIC_12, "é")
            node.createwallet(wallet_name="mnemonic12_nfkd_decomposed", blank=True, descriptors=True)
            nfkd_decomposed_rpc = node.get_wallet_rpc("mnemonic12_nfkd_decomposed")
            nfkd_decomposed_rpc.sethdseed(True, self.MNEMONIC_12, "e\u0301")
            assert_equal(nfkd_decomposed_rpc.getnewaddress(), nfkd_composed_rpc.getnewaddress())

            node.createwallet(wallet_name="mnemonic12_invalid_passphrase", blank=True, descriptors=True)
            invalid_passphrase_rpc = node.get_wallet_rpc("mnemonic12_invalid_passphrase")
            assert_raises_rpc_error(-8, "must not contain a NUL", invalid_passphrase_rpc.sethdseed, True, self.MNEMONIC_12, "bad\x00passphrase")
            assert_raises_rpc_error(-8, "maximum of 1024 UTF-8 bytes", invalid_passphrase_rpc.sethdseed, True, self.MNEMONIC_12, "x" * 1025)
            assert_equal(invalid_passphrase_rpc.getwalletinfo()["blank"], True)

            node.createwallet(wallet_name="bip39_wif_source", descriptors=False)
            wif_source_rpc = node.get_wallet_rpc("bip39_wif_source")
            wif_seed = wif_source_rpc.dumpprivkey(wif_source_rpc.getnewaddress())
            assert_raises_rpc_error(-8, "cannot be used with a WIF seed", invalid_passphrase_rpc.sethdseed, True, wif_seed, "TREZOR")

            self.log.info("Test createwallet propagates its optional BIP39 passphrase")
            node.createwallet(wallet_name="native_bip39_passphrase", descriptors=True, bip39_passphrase="TREZOR")
            native_passphrase_rpc = node.get_wallet_rpc("native_bip39_passphrase")
            native_address = native_passphrase_rpc.getnewaddress()
            native_mnemonic = self.assert_mnemonic_info(native_passphrase_rpc, expected_passphrase_required=True)
            node.createwallet(wallet_name="native_bip39_restore", blank=True, descriptors=True)
            native_restore_rpc = node.get_wallet_rpc("native_bip39_restore")
            native_restore_rpc.sethdseed(True, native_mnemonic, "TREZOR")
            assert_equal(native_restore_rpc.getnewaddress(), native_address)

            node.createwallet(
                wallet_name="native_bip39_encrypted",
                descriptors=True,
                passphrase="wallet file password",
                bip39_passphrase="TREZOR",
            )
            native_encrypted_rpc = node.get_wallet_rpc("native_bip39_encrypted")
            assert_equal(native_encrypted_rpc.getwalletinfo()["bip39_passphrase_enabled"], True)
            native_encrypted_rpc.walletpassphrase("wallet file password", 60)
            encrypted_native_address = native_encrypted_rpc.getnewaddress()
            encrypted_native_mnemonic = self.assert_mnemonic_info(
                native_encrypted_rpc,
                expected_passphrase_required=True,
            )
            node.createwallet(wallet_name="native_bip39_encrypted_restore", blank=True, descriptors=True)
            encrypted_native_restore_rpc = node.get_wallet_rpc("native_bip39_encrypted_restore")
            encrypted_native_restore_rpc.sethdseed(True, encrypted_native_mnemonic, "TREZOR")
            assert_equal(encrypted_native_restore_rpc.getnewaddress(), encrypted_native_address)

            for name, args, error in (
                ("bip39_reject_blank", (False, True, "", False, True, None, False, "TREZOR"), "blank wallet"),
                ("bip39_reject_no_private_keys", (True, False, "", False, True, None, False, "TREZOR"), "private keys are disabled"),
                ("bip39_reject_legacy", (False, False, "", False, False, None, False, "TREZOR"), "only for descriptor wallets"),
                ("bip39_reject_external_signer", (False, False, "", False, True, None, True, "TREZOR"), "external signer"),
            ):
                assert_raises_rpc_error(-8, error, node.createwallet_passthrough, name, *args)
                assert name not in node.listwallets()

            node.createwallet(wallet_name="mnemonic12_encrypted", blank=True, descriptors=True, passphrase="seed test passphrase")
            encrypted_rpc = node.get_wallet_rpc("mnemonic12_encrypted")
            encrypted_rpc.walletpassphrase("seed test passphrase", 60)
            encrypted_rpc.sethdseed(True, self.MNEMONIC_12, "TREZOR")
            assert_equal(encrypted_rpc.getnewaddress(), address_passphrase)
            assert_equal(self.assert_mnemonic_info(encrypted_rpc, 12, expected_passphrase_required=True), self.MNEMONIC_12)
            encrypted_rpc.walletlock()
            assert_equal(encrypted_rpc.getwalletinfo()["bip39_passphrase_enabled"], True)
            encrypted_rpc.walletpassphrase("seed test passphrase", 60)

            node.createwallet(wallet_name="mnemonic24_plain", blank=True, descriptors=True)
            plain24_rpc = node.get_wallet_rpc("mnemonic24_plain")
            plain24_rpc.sethdseed(True, self.MNEMONIC_24)
            address24_plain = plain24_rpc.getnewaddress()
            assert_equal(self.assert_mnemonic_info(plain24_rpc, 24), self.MNEMONIC_24)

            node.createwallet(wallet_name="mnemonic24_encrypted", blank=True, descriptors=True, passphrase="seed test passphrase")
            encrypted24_rpc = node.get_wallet_rpc("mnemonic24_encrypted")
            encrypted24_rpc.walletpassphrase("seed test passphrase", 60)
            encrypted24_rpc.sethdseed(True, self.MNEMONIC_24)
            assert_equal(encrypted24_rpc.getnewaddress(), address24_plain)
            assert_equal(self.assert_mnemonic_info(encrypted24_rpc, 24), self.MNEMONIC_24)

            node.createwallet(wallet_name="mnemonic_seed_import_no_third_arg", blank=True, descriptors=True)
            seed_import_no_third_arg_rpc = node.get_wallet_rpc("mnemonic_seed_import_no_third_arg")
            assert_raises_rpc_error(-1, "sethdseed", seed_import_no_third_arg_rpc.sethdseed, True, self.MNEMONIC_12, "", "unexpected")

            self.log.info("Test descriptor BIP39 restore reconstructs complete history and current transparent UTXOs")
            def mine_blocks(count):
                target_height = node.getblockcount() + count
                attempts_without_progress = 0
                while node.getblockcount() < target_height:
                    remaining = target_height - node.getblockcount()
                    generated = self.generatetoaddress(node, remaining, default_rpc.getnewaddress("", "bech32"))
                    if generated:
                        attempts_without_progress = 0
                    else:
                        attempts_without_progress += 1
                        assert attempts_without_progress < 200

            mine_blocks(COINBASE_MATURITY + 1)
            spent_history_fund_txid = default_rpc.sendtoaddress(address_plain, Decimal("0.50"))
            mine_blocks(1)
            spent_history_spend_txid = plain_rpc.sendtoaddress(default_rpc.getnewaddress("", "bech32"), Decimal("0.50"), "", "", True)
            mine_blocks(1)

            current_receive_txid = default_rpc.sendtoaddress(address_plain, Decimal("1.25"))
            mine_blocks(1)
            current_spend_txid = plain_rpc.sendtoaddress(default_rpc.getnewaddress("", "bech32"), Decimal("0.10"))
            mine_blocks(1)
            self.log.info("Advance HD receive discovery beyond the old small script cache")
            for _ in range(20):
                plain_rpc.getnewaddress("", "bech32")
            consolidation_addr = plain_rpc.getnewaddress("", "bech32")
            consolidation_txid = plain_rpc.sendtoaddress(consolidation_addr, plain_rpc.getbalances()["mine"]["trusted"], "", "", True)
            mine_blocks(1)
            expected_restore_balance = plain_rpc.getbalances()["mine"]["trusted"]
            assert_equal(len(plain_rpc.listunspent()), 1)
            assert_equal(plain_rpc.listunspent()[0]["txid"], consolidation_txid)

            node.createwallet(wallet_name="mnemonic12_utxo_restore", blank=True, descriptors=True)
            utxo_restore_rpc = node.get_wallet_rpc("mnemonic12_utxo_restore")
            utxo_restore_rpc.sethdseed(True, self.MNEMONIC_12)
            assert_equal(utxo_restore_rpc.getbalances()["mine"]["trusted"], expected_restore_balance)
            assert_equal(len(utxo_restore_rpc.listunspent()), 1)
            assert_equal(utxo_restore_rpc.listunspent()[0]["txid"], consolidation_txid)
            restored_txids = {tx["txid"] for tx in utxo_restore_rpc.listtransactions("*", 1000)}
            assert {
                spent_history_fund_txid,
                spent_history_spend_txid,
                current_receive_txid,
                current_spend_txid,
                consolidation_txid,
            }.issubset(restored_txids)

            self.log.info("Test complete seed restore remains available while the node reports initial block download")
            ibd_args = ["-blockfilterindex=1", "-orchardindex=1", "-transparenthistoryindex=1", "-minimumchainwork=0xffffffffffffffff"]
            self.restart_node(0, extra_args=ibd_args)
            node = self.nodes[0]
            default_rpc = node.get_wallet_rpc(self.default_wallet_name)
            assert_equal(node.getblockchaininfo()["initialblockdownload"], True)
            node.createwallet(wallet_name="mnemonic12_pending_sync_restore", blank=True, descriptors=True)
            pending_sync_rpc = node.get_wallet_rpc("mnemonic12_pending_sync_restore")
            pending_sync_rpc.sethdseed(True, self.MNEMONIC_12)
            pending_wallet_info = pending_sync_rpc.getwalletinfo()
            assert_equal(pending_wallet_info["seed_history"]["mode"], "full_history")
            assert_equal(pending_wallet_info["seed_history"]["sync_pending"], False)
            assert_equal(pending_wallet_info["balance"], expected_restore_balance)
            assert_equal(pending_sync_rpc.getbalance(), expected_restore_balance)
            assert_equal(pending_sync_rpc.getbalances()["mine"]["trusted"], expected_restore_balance)
            assert_equal(pending_sync_rpc.listunspent()[0]["txid"], consolidation_txid)
            pending_history_txids = {tx["txid"] for tx in pending_sync_rpc.listtransactions("*", 1000)}
            assert spent_history_fund_txid in pending_history_txids
            assert spent_history_spend_txid in pending_history_txids

            live_receive_addr = pending_sync_rpc.getnewaddress("", "bech32")
            live_receive_txid = default_rpc.sendtoaddress(live_receive_addr, Decimal("0.07"))
            mine_blocks(1)
            assert_equal(pending_sync_rpc.getbalances()["mine"]["trusted"], expected_restore_balance + Decimal("0.07"))
            assert live_receive_txid in {tx["txid"] for tx in pending_sync_rpc.listtransactions("*", 1000)}

            def get_wallet_receive_outpoint(wallet_rpc, txid):
                tx = wallet_rpc.gettransaction(txid)
                receive_details = [detail for detail in tx["details"] if detail["category"] == "receive" and detail["amount"] > 0]
                assert_equal(len(receive_details), 1)
                return {"txid": txid, "vout": receive_details[0]["vout"]}, receive_details[0]["amount"]

            initial_consolidation_txid = consolidation_txid
            consolidation_input, consolidation_amount = get_wallet_receive_outpoint(pending_sync_rpc, consolidation_txid)
            live_receive_input, live_receive_amount = get_wallet_receive_outpoint(pending_sync_rpc, live_receive_txid)
            live_consolidation_addr = pending_sync_rpc.getnewaddress("", "bech32")
            live_consolidation_fee = Decimal("0.00001000")
            live_consolidation_amount = consolidation_amount + live_receive_amount - live_consolidation_fee
            raw_live_consolidation = node.createrawtransaction(
                [consolidation_input, live_receive_input],
                {live_consolidation_addr: live_consolidation_amount},
            )
            signed_live_consolidation = pending_sync_rpc.signrawtransactionwithwallet(raw_live_consolidation)
            assert_equal(signed_live_consolidation["complete"], True)
            live_consolidation_txid = node.sendrawtransaction(signed_live_consolidation["hex"])
            mine_blocks(1)
            pending_wallet_info = pending_sync_rpc.getwalletinfo()
            assert_equal(pending_wallet_info["balance"], live_consolidation_amount)
            assert live_consolidation_txid in {tx["txid"] for tx in pending_sync_rpc.listtransactions("*", 1000)}
            expected_restore_balance = live_consolidation_amount
            consolidation_txid = live_consolidation_txid

            self.restart_node(0, extra_args=["-blockfilterindex=1", "-orchardindex=1", "-transparenthistoryindex=1"])
            node = self.nodes[0]
            node.loadwallet("mnemonic12_plain")
            node.loadwallet("mnemonic24_plain")
            node.loadwallet("mnemonic12_pending_sync_restore")
            default_rpc = node.get_wallet_rpc(self.default_wallet_name)
            plain_rpc = node.get_wallet_rpc("mnemonic12_plain")
            plain24_rpc = node.get_wallet_rpc("mnemonic24_plain")
            pending_sync_rpc = node.get_wallet_rpc("mnemonic12_pending_sync_restore")
            assert_equal(node.getblockchaininfo()["initialblockdownload"], False)
            assert_equal(pending_sync_rpc.getbalances()["mine"]["trusted"], expected_restore_balance)
            assert_equal(len(pending_sync_rpc.listunspent()), 1)

            node.createwallet(wallet_name="mnemonic12_automatic_history_restore", blank=True, descriptors=True)
            automatic_history_restore_rpc = node.get_wallet_rpc("mnemonic12_automatic_history_restore")
            automatic_history_restore_rpc.sethdseed(True, self.MNEMONIC_12)
            assert_equal(automatic_history_restore_rpc.getbalances()["mine"]["trusted"], expected_restore_balance)
            assert_equal(len(automatic_history_restore_rpc.listunspent()), 1)
            assert_equal(automatic_history_restore_rpc.listunspent()[0]["txid"], consolidation_txid)
            self.wait_until(lambda: node.getindexinfo().get("transparenthistoryindex", {}).get("synced") is True)
            self.wait_until(lambda: node.getindexinfo().get("orchardindex", {}).get("synced") is True)
            rebuilt_history_txids = {tx["txid"] for tx in automatic_history_restore_rpc.listtransactions("*", 1000)}
            assert spent_history_fund_txid in rebuilt_history_txids
            assert spent_history_spend_txid in rebuilt_history_txids
            assert current_receive_txid in rebuilt_history_txids
            assert current_spend_txid in rebuilt_history_txids
            assert initial_consolidation_txid in rebuilt_history_txids
            assert live_receive_txid in rebuilt_history_txids
            assert consolidation_txid in rebuilt_history_txids
            consolidation_entries = [tx for tx in automatic_history_restore_rpc.listtransactions("*", 1000) if tx["txid"] == consolidation_txid]
            assert any(tx["amount"] == expected_restore_balance for tx in consolidation_entries)
            assert_equal(automatic_history_restore_rpc.listunspent()[0]["txid"], consolidation_txid)

            self.log.info("Test descriptor BIP39 restore does not double-count spent sibling outputs")
            keep_addr = address24_plain
            spend_addr = plain24_rpc.getrawchangeaddress("bech32")
            sibling_fund_txid = default_rpc.sendmany("", {
                keep_addr: Decimal("0.01"),
                spend_addr: Decimal("2.00"),
            })
            mine_blocks(1)
            assert_equal(plain24_rpc.getbalances()["mine"]["trusted"], Decimal("2.01000000"))
            sibling_spend_txid = plain24_rpc.sendtoaddress(
                default_rpc.getnewaddress("", "bech32"), Decimal("2.00"), "", "", True)
            mine_blocks(1)
            assert_equal(plain24_rpc.getbalances()["mine"]["trusted"], Decimal("0.01000000"))

            node.createwallet(wallet_name="mnemonic24_spent_sibling_restore", blank=True, descriptors=True)
            sibling_restore_rpc = node.get_wallet_rpc("mnemonic24_spent_sibling_restore")
            sibling_restore_rpc.sethdseed(True, self.MNEMONIC_24)
            assert_equal(sibling_restore_rpc.getbalances()["mine"]["trusted"], Decimal("0.01000000"))
            assert_equal(len(sibling_restore_rpc.listunspent()), 1)
            sibling_restore_txids = {tx["txid"] for tx in sibling_restore_rpc.listtransactions("*", 1000)}
            assert sibling_fund_txid in sibling_restore_txids
            assert sibling_spend_txid in sibling_restore_txids

            self.log.info("Test complete restore refuses an existing post-activation chain without Orchard index")
            self.restart_node(0, extra_args=["-blockfilterindex=0", "-orchardindex=0", "-transparenthistoryindex=1"])
            node = self.nodes[0]
            self.wait_until(lambda: node.getindexinfo().get("transparenthistoryindex", {}).get("synced") is True)
            node.createwallet(wallet_name="mnemonic24_spent_sibling_no_filter", blank=True, descriptors=True)
            no_filter_restore_rpc = node.get_wallet_rpc("mnemonic24_spent_sibling_no_filter")
            assert_raises_rpc_error(
                -4,
                "requires -orchardindex=1",
                no_filter_restore_rpc.sethdseed,
                True,
                self.MNEMONIC_24,
            )

            self.log.info("Test automatic complete history restore works without compact filters")
            self.restart_node(0, extra_args=["-blockfilterindex=0", "-orchardindex=1", "-transparenthistoryindex=1"])
            node = self.nodes[0]
            self.wait_until(lambda: node.getindexinfo().get("transparenthistoryindex", {}).get("synced") is True)
            self.wait_until(lambda: node.getindexinfo().get("orchardindex", {}).get("synced") is True)
            node.createwallet(wallet_name="mnemonic12_rebuild_no_filter", blank=True, descriptors=True)
            rebuild_no_filter_rpc = node.get_wallet_rpc("mnemonic12_rebuild_no_filter")
            with node.assert_debug_log(expected_msgs=[], unexpected_msgs=["slow variant inspecting all blocks"], timeout=1):
                rebuild_no_filter_rpc.sethdseed(True, self.MNEMONIC_12)
            no_filter_rebuild_txids = {tx["txid"] for tx in rebuild_no_filter_rpc.listtransactions("*", 1000)}
            assert spent_history_fund_txid in no_filter_rebuild_txids
            assert spent_history_spend_txid in no_filter_rebuild_txids
            assert current_receive_txid in no_filter_rebuild_txids
            assert current_spend_txid in no_filter_rebuild_txids
            assert consolidation_txid in no_filter_rebuild_txids
            assert_equal(rebuild_no_filter_rpc.listunspent()[0]["txid"], consolidation_txid)

            self.log.info("Test automatic complete restore refuses an existing chain without transparent history index")
            self.restart_node(0, extra_args=["-blockfilterindex=0", "-orchardindex=1", "-transparenthistoryindex=0"])
            node = self.nodes[0]
            node.createwallet(wallet_name="mnemonic12_rebuild_no_history_index", blank=True, descriptors=True)
            rebuild_no_history_index_rpc = node.get_wallet_rpc("mnemonic12_rebuild_no_history_index")
            assert_raises_rpc_error(
                -4,
                "requires -transparenthistoryindex=1",
                rebuild_no_history_index_rpc.sethdseed,
                True,
                self.MNEMONIC_12,
            )
            assert_raises_rpc_error(
                -32601,
                "Method not found",
                node.rebuildwallethistory,
            )
        else:
            assert_raises_rpc_error(-8, "not supported by legacy wallets", default_rpc.sethdseed, True, self.MNEMONIC_12, "TREZOR")
            assert_raises_rpc_error(-5, "Invalid private key or BIP39 mnemonic", default_rpc.sethdseed, False, "not_wif")

            self.log.info("Test a V3 wallet Orchard upgrade with a BIP39 passphrase")
            node.createwallet(wallet_name="legacy_orchard_passphrase", blank=True, descriptors=False)
            orchard_passphrase_rpc = node.get_wallet_rpc("legacy_orchard_passphrase")
            orchard_passphrase_rpc.sethdseed(True, self.MNEMONIC_12)
            upgrade = orchard_passphrase_rpc.upgradeorchardwallet(self.MNEMONIC_12, "TREZOR")
            assert_equal(upgrade["scope"], "orchard_only")
            assert_equal(upgrade["bip39_passphrase_required"], True)
            assert_equal(
                self.assert_mnemonic_info(
                    orchard_passphrase_rpc,
                    12,
                    expected_scope="orchard_only",
                    expected_seed_type="orchard_root_entropy",
                    expected_passphrase_required=True,
                ),
                self.MNEMONIC_12,
            )
            self.generate(node, 1)
            assert orchard_passphrase_rpc.getnewaddress("", "bech32x") != restore_rpc.getnewaddress("", "bech32x")


if __name__ == "__main__":
    WalletBIP39SeedTest().main()
