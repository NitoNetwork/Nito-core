#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Nito.network bech32x wallet address RPC integration."""

from decimal import Decimal

from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletPrivateAddressTest(NitoTestFramework):
    IMPORT_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    def assert_bech32x_address(self, address):
        assert address.split("1", 1)[1].startswith("x")

    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False, legacy=True)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [
            ["-privateactivationheight=0"],
            ["-privateactivationheight=0", "-orchardindex=0"],
            ["-privateactivationheight=0", "-fastprune", "-prune=1", "-orchardindex=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="private_v4", descriptors=False)
        wallet = node.get_wallet_rpc("private_v4")

        private_addr = wallet.getnewaddress("", "bech32x")
        assert private_addr.split("1", 1)[1].startswith("x")

        validated = node.validateaddress(private_addr)
        assert_equal(validated["isvalid"], True)
        assert_equal(validated["address"], private_addr)
        assert_equal(validated["isprivate"], True)
        assert_equal(validated["address_type"], "bech32x")

        info = wallet.getaddressinfo(private_addr)
        assert_equal(info["address"], private_addr)
        assert_equal(info["ismine"], True)
        assert_equal(info["solvable"], True)
        assert_equal(info["isprivate"], True)
        assert_equal(info["address_type"], "bech32x")
        assert info["hdkeypath"].startswith("m/96'/0'/0'/0/")
        assert_equal(info["private_derivation_id"], "nito_orchard_derivation")
        assert_equal(info["private_derivation_version"], 1)
        assert "desc" not in info

        keyman_info = wallet.getprivatekeymaninfo()
        assert_equal(keyman_info["derivation_id"], "nito_orchard_derivation")
        assert_equal(keyman_info["derivation_version"], 1)
        assert_equal(keyman_info["next_external_index"], 1)
        assert_equal(keyman_info["next_internal_index"], 0)
        assert "external_descriptor" not in keyman_info
        assert "change_descriptor" not in keyman_info

        private_keyman_info = wallet.getprivatekeymaninfo(True)
        assert private_keyman_info["external_descriptor"].startswith("or(")
        assert private_keyman_info["change_descriptor"].startswith("or(")
        assert "full deterministic recovery authority" in private_keyman_info["warning"]
        assert "equivalent in authority to the full_wallet recovery phrase" in private_keyman_info["warning"]

        node.createwallet(wallet_name="generic_descriptor_import_guard", descriptors=True)
        generic_import_wallet = node.get_wallet_rpc("generic_descriptor_import_guard")
        generic_import_result = generic_import_wallet.importdescriptors([
            {"desc": private_keyman_info["external_descriptor"], "timestamp": "now"},
        ])
        assert_equal(generic_import_result[0]["success"], False)
        assert "error" in generic_import_result[0]
        assert not any(
            descriptor["desc"].startswith("or(")
            for descriptor in generic_import_wallet.listdescriptors(True)["descriptors"]
        )

        view_key = wallet.getprivateviewkey(private_addr)
        assert_equal(view_key["address"], private_addr)
        assert_equal(view_key["derivation_id"], "nito_orchard_derivation")
        assert_equal(view_key["derivation_version"], 1)
        assert_equal(view_key["scope"], "external_branch")
        assert_equal(view_key["covers_all_branch_diversifiers"], True)
        assert_equal(len(view_key["full_viewing_key"]), 192)
        second_private_addr = wallet.getnewaddress("", "bech32x")
        second_view_key = wallet.getprivateviewkey(second_private_addr)
        assert_equal(second_view_key["full_viewing_key"], view_key["full_viewing_key"])
        assert_equal(second_view_key["covers_all_branch_diversifiers"], True)

        node.createwallet(wallet_name="legacy_seed_import", blank=True, descriptors=False)
        imported_seed_wallet = node.get_wallet_rpc("legacy_seed_import")
        imported_seed_wallet.sethdseed(True, self.IMPORT_MNEMONIC)
        upgrade_result = imported_seed_wallet.upgradeorchardwallet(self.IMPORT_MNEMONIC)
        assert_equal(upgrade_result["scope"], "orchard_only")
        assert_equal(upgrade_result["mnemonic"], self.IMPORT_MNEMONIC)
        orchard_keyman = imported_seed_wallet.getprivatekeymaninfo(True)
        assert_equal(orchard_keyman["address_type"], "bech32x")
        assert orchard_keyman["external_descriptor"].startswith("or(")
        assert orchard_keyman["change_descriptor"].startswith("or(")
        assert "Orchard recovery authority only" in orchard_keyman["warning"]
        assert "do not recover pre-existing v3 transparent" in orchard_keyman["warning"]
        assert_raises_rpc_error(-32601, "Method not found", imported_seed_wallet.upgradev4wallet, self.IMPORT_MNEMONIC)
        imported_seed_addr = imported_seed_wallet.getnewaddress("", "bech32x")
        self.assert_bech32x_address(imported_seed_addr)
        assert_equal(imported_seed_wallet.dumpmnemonic()["scope"], "orchard_only")
        assert_raises_rpc_error(-4, "Cannot rotate the transparent HD seed", imported_seed_wallet.sethdseed, True, self.IMPORT_MNEMONIC)

        node.createwallet(wallet_name="legacy_seed_reference", blank=True, descriptors=False)
        reference_seed_wallet = node.get_wallet_rpc("legacy_seed_reference")
        reference_seed_wallet.sethdseed(True, self.IMPORT_MNEMONIC)
        reference_seed_wallet.upgradeorchardwallet(self.IMPORT_MNEMONIC)
        assert_equal(reference_seed_wallet.getnewaddress("", "bech32x"), imported_seed_addr)
        expected_second_imported_addr = reference_seed_wallet.getnewaddress("", "bech32x")
        encrypt_result = imported_seed_wallet.encryptwallet("encrypt after seed import")
        assert "HD seed and address sequence were kept unchanged" in encrypt_result
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", imported_seed_wallet.getnewaddress, "", "bech32x")
        imported_seed_wallet.walletpassphrase("encrypt after seed import", 600)
        assert_equal(imported_seed_wallet.getnewaddress("", "bech32x"), expected_second_imported_addr)

        self.log.info("Reject transparent seed rotation without losing Orchard notes or address state")
        expected_third_imported_addr = reference_seed_wallet.getnewaddress("", "bech32x")
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 101)
        preserved_note_txid = miner.sendtoaddress(imported_seed_addr, Decimal("0.10"))
        self.generate(node, 1)
        self.wait_until(
            lambda: imported_seed_wallet.getprivatebalance()["total_unspent"] == Decimal("0.10"),
            timeout=240,
        )
        assert_raises_rpc_error(
            -4,
            "Cannot rotate the transparent HD seed",
            imported_seed_wallet.sethdseed,
            True,
            self.IMPORT_MNEMONIC,
        )
        node.unloadwallet("legacy_seed_import")
        node.loadwallet("legacy_seed_import")
        imported_seed_wallet = node.get_wallet_rpc("legacy_seed_import")
        imported_seed_wallet.walletpassphrase("encrypt after seed import", 600)
        assert_equal(imported_seed_wallet.getnewaddress("", "bech32x"), expected_third_imported_addr)
        assert_equal(imported_seed_wallet.getprivatebalance()["total_unspent"], Decimal("0.10"))
        assert any(note["txid"] == preserved_note_txid for note in imported_seed_wallet.listprivateunspent())
        preserved_spend_txid = imported_seed_wallet.sendprivate(miner.getnewaddress(), Decimal("0.02"))
        self.generate(node, 1)
        assert imported_seed_wallet.gettransaction(preserved_spend_txid)["confirmations"] >= 1

        node.createwallet(wallet_name="encrypted_legacy_seed_import", blank=True, descriptors=False, passphrase="private passphrase")
        encrypted_seed_wallet = node.get_wallet_rpc("encrypted_legacy_seed_import")
        encrypted_seed_wallet.walletpassphrase("private passphrase", 600)
        encrypted_seed_wallet.sethdseed(True, self.IMPORT_MNEMONIC)
        encrypted_seed_wallet.upgradeorchardwallet(self.IMPORT_MNEMONIC)
        encrypted_seed_wallet.walletlock()
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", encrypted_seed_wallet.getnewaddress, "", "bech32x")
        encrypted_seed_wallet.walletpassphrase("private passphrase", 600)
        encrypted_seed_addr = encrypted_seed_wallet.getnewaddress("", "bech32x")
        self.assert_bech32x_address(encrypted_seed_addr)

        assert_raises_rpc_error(-5, "Unknown address type 'private'", wallet.getnewaddress, "", "private")
        assert_raises_rpc_error(-32601, "Method not found", wallet.getnewprivateaddress)

        no_index_node = self.nodes[1]
        assert "orchardindex" not in no_index_node.getindexinfo()
        no_index_node.createwallet(wallet_name="private_without_index", descriptors=True)
        no_index_wallet = no_index_node.get_wallet_rpc("private_without_index")
        assert "private" not in no_index_wallet.getbalances()
        assert_raises_rpc_error(
            -4,
            "The private wallet index is not available",
            no_index_wallet.getnewaddress,
            "",
            "bech32x",
        )
        assert_raises_rpc_error(-4, "The private wallet index is not available", no_index_wallet.getprivatebalance)
        assert_raises_rpc_error(-4, "The private wallet index is not available", no_index_wallet.listprivateunspent)
        assert_raises_rpc_error(-4, "The private wallet index is not available", no_index_wallet.getprivatekeymaninfo)
        assert not any(desc["desc"].startswith("or(") for desc in no_index_wallet.listdescriptors(True)["descriptors"])
        assert_raises_rpc_error(-4, "The private wallet index is not available", no_index_wallet.getaddressinfo, private_addr)

        pruned_node = self.nodes[2]
        assert pruned_node.getblockchaininfo()["pruned"]
        assert "orchardindex" not in pruned_node.getindexinfo()
        pruned_node.createwallet(wallet_name="private_pruned", descriptors=True)
        pruned_wallet = pruned_node.get_wallet_rpc("private_pruned")
        assert "private" not in pruned_wallet.getbalances()
        assert_raises_rpc_error(
            -4,
            "The private wallet index is not available",
            pruned_wallet.getnewaddress,
            "",
            "bech32x",
        )
        assert_raises_rpc_error(-4, "The private wallet index is not available", pruned_wallet.getprivatebalance)
        assert_raises_rpc_error(-4, "The private wallet index is not available", pruned_wallet.listprivateunspent)
        assert_raises_rpc_error(-4, "The private wallet index is not available", pruned_wallet.getprivatekeymaninfo)
        assert not any(desc["desc"].startswith("or(") for desc in pruned_wallet.listdescriptors(True)["descriptors"])
        assert_raises_rpc_error(-4, "The private wallet index is not available", pruned_wallet.getaddressinfo, private_addr)


if __name__ == "__main__":
    WalletPrivateAddressTest().main()
