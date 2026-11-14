#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Nito.network Bech32x/Orchard PSBT shielding support."""

from decimal import Decimal

from test_framework.psbt import PSBT
from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


MAX_MINING_TRIES = 10_000_000
NITO_LEGACY_PRIVATE_AUTH_KEY = b"\xfc\x04nito\x01"
NITO_ORCHARD_ACTION_AUTH_KEY_PREFIX = b"\xfc\x04nito\x02"
NITO_ORCHARD_BUNDLE_AUTH_KEY = b"\xfc\x04nito\x03"
NITO_ORCHARD_SPEND_MATERIAL_KEY_PREFIX = b"\xfc\x04nito\x04"
NITO_ORCHARD_OUTPUT_MATERIAL_KEY_PREFIX = b"\xfc\x04nito\x05"
NITO_ORCHARD_BUNDLE_PLAN_KEY = b"\xfc\x04nito\x06"
NITO_PRIVATE_AUTH_KEY_PREFIXES = (
    NITO_ORCHARD_ACTION_AUTH_KEY_PREFIX,
    NITO_ORCHARD_BUNDLE_AUTH_KEY,
)
NITO_PRIVATE_SIGNING_KEY_PREFIXES = (
    NITO_ORCHARD_SPEND_MATERIAL_KEY_PREFIX,
    NITO_ORCHARD_OUTPUT_MATERIAL_KEY_PREFIX,
    NITO_ORCHARD_BUNDLE_PLAN_KEY,
)


class WalletPrivatePSBTTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-privateactivationheight=1"]]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_height(self, node, height):
        while node.getblockcount() < height:
            mining_wallet = node.get_wallet_rpc(self.default_wallet_name)
            self.generatetoaddress(
                node,
                height - node.getblockcount(),
                mining_wallet.getnewaddress(),
                MAX_MINING_TRIES,
            )
        assert_equal(node.getblockcount(), height)

    def strip_private_auth(self, psbt, keep_action_auth=False, keep_bundle_auth=False):
        parsed = PSBT.from_base64(psbt)
        keys = [
            key for key in parsed.g.map
            if isinstance(key, bytes) and key.startswith(NITO_PRIVATE_AUTH_KEY_PREFIXES)
            and not (keep_action_auth and key.startswith(NITO_ORCHARD_ACTION_AUTH_KEY_PREFIX))
            and not (keep_bundle_auth and key.startswith(NITO_ORCHARD_BUNDLE_AUTH_KEY))
        ]
        assert_greater_than(len(keys), 0)
        for key in keys:
            del parsed.g.map[key]
        return parsed.to_base64()

    def strip_private_signing_material(self, psbt, keep_spend=False, keep_output=False, keep_plan=False):
        parsed = PSBT.from_base64(psbt)
        keys = [
            key for key in parsed.g.map
            if isinstance(key, bytes) and key.startswith(NITO_PRIVATE_SIGNING_KEY_PREFIXES)
            and not (keep_spend and key.startswith(NITO_ORCHARD_SPEND_MATERIAL_KEY_PREFIX))
            and not (keep_output and key.startswith(NITO_ORCHARD_OUTPUT_MATERIAL_KEY_PREFIX))
            and not (keep_plan and key.startswith(NITO_ORCHARD_BUNDLE_PLAN_KEY))
        ]
        assert_greater_than(len(keys), 0)
        for key in keys:
            del parsed.g.map[key]
        return parsed.to_base64()

    def tamper_first_private_auth_byte(self, psbt):
        parsed = PSBT.from_base64(psbt)
        for key in sorted(key for key in parsed.g.map if isinstance(key, bytes)):
            if isinstance(key, bytes) and key.startswith(NITO_ORCHARD_ACTION_AUTH_KEY_PREFIX):
                assert_greater_than(len(parsed.g.map[key]), 1)
                parsed.g.map[key] = parsed.g.map[key][:1] + bytes([parsed.g.map[key][1] ^ 1]) + parsed.g.map[key][2:]
                return parsed.to_base64()
        raise AssertionError("private auth key not found")

    def shorten_first_private_auth(self, psbt):
        parsed = PSBT.from_base64(psbt)
        for key in sorted(key for key in parsed.g.map if isinstance(key, bytes)):
            if key.startswith(NITO_ORCHARD_ACTION_AUTH_KEY_PREFIX):
                value = parsed.g.map[key]
                assert_equal(value[0], 64)
                assert_equal(len(value), 65)
                parsed.g.map[key] = bytes([63]) + value[1:-1]
                return parsed.to_base64()
        raise AssertionError("private auth key not found")

    def tamper_first_private_signing_material_byte(self, psbt):
        parsed = PSBT.from_base64(psbt)
        for key in sorted(key for key in parsed.g.map if isinstance(key, bytes)):
            if isinstance(key, bytes) and key.startswith(NITO_ORCHARD_SPEND_MATERIAL_KEY_PREFIX):
                assert_greater_than(len(parsed.g.map[key]), 1)
                parsed.g.map[key] = parsed.g.map[key][:-1] + bytes([parsed.g.map[key][-1] ^ 1])
                return parsed.to_base64()
        raise AssertionError("private signing material key not found")

    def replace_first_external_private_output_recipient(self, psbt, donor_psbt):
        parsed = PSBT.from_base64(psbt)
        donor = PSBT.from_base64(donor_psbt)

        def external_output_material(target):
            for key in sorted(key for key in target.g.map if isinstance(key, bytes)):
                if not key.startswith(NITO_ORCHARD_OUTPUT_MATERIAL_KEY_PREFIX):
                    continue
                value = target.g.map[key]
                # int32 version, CompactSize(43), recipient, int64 value, bool internal.
                assert_equal(len(value), 4 + 1 + 43 + 8 + 1)
                assert_equal(value[4], 43)
                if value[-1] == 0:
                    return key, value
            raise AssertionError("external private output material not found")

        target_key, target_value = external_output_material(parsed)
        _, donor_value = external_output_material(donor)
        assert target_value[5:48] != donor_value[5:48]
        parsed.g.map[target_key] = target_value[:5] + donor_value[5:48] + target_value[48:]
        return parsed.to_base64()

    def private_intent_hash(self, node, psbt):
        intent = node.decodepsbt(psbt)["nito_private_intent"]
        assert_equal(intent["spend_count"], len(intent["spends"]))
        assert_equal(intent["output_count"], len(intent["outputs"]))
        for output in intent["outputs"]:
            assert "address" in output
            assert_greater_than(output["amount"], 0)
        return intent["hash"]

    def process_psbt(self, node, wallet, psbt):
        decoded = node.decodepsbt(psbt)
        if "nito_private_intent" not in decoded:
            return wallet.walletprocesspsbt(psbt)
        return wallet.walletprocesspsbt(
            psbt,
            True,
            "ALL",
            True,
            True,
            self.private_intent_hash(node, psbt),
        )

    def assert_well_formed_private_recipient_tamper_rejected(self, node, wallet, psbt, donor_psbt):
        reviewed_hash = self.private_intent_hash(node, psbt)
        tampered = self.replace_first_external_private_output_recipient(psbt, donor_psbt)
        tampered_intent = node.decodepsbt(tampered)["nito_private_intent"]
        assert reviewed_hash != tampered_intent["hash"]
        assert_raises_rpc_error(
            -8,
            "PSBT is not well-formed",
            wallet.walletprocesspsbt,
            tampered,
            True,
            "ALL",
            True,
            True,
            reviewed_hash,
        )

    def add_legacy_private_auth_record(self, psbt):
        parsed = PSBT.from_base64(psbt)
        parsed.g.map[NITO_LEGACY_PRIVATE_AUTH_KEY] = b"\x00"
        return parsed.to_base64()

    def assert_private_auth_psbt(self, node, psbt, fee, expected_next):
        decoded = node.decodepsbt(psbt)
        assert_equal(decoded["tx"]["has_private_bundle"], True)
        assert_greater_than(decoded["tx"]["private_bundle"]["actions"], 0)
        assert_equal(decoded["tx"]["private_bundle"]["has_auth"], True)
        legacy_auth_props = [
            entry for entry in decoded["proprietary"]
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 1
        ]
        bundle_auth_props = [
            entry for entry in decoded["proprietary"]
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 3
        ]
        action_auth_props = [
            entry for entry in decoded["proprietary"]
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 2
        ]
        assert_equal(len(legacy_auth_props), 0)
        assert_equal(len(bundle_auth_props), 1)
        assert_equal(len(action_auth_props), decoded["tx"]["private_bundle"]["actions"])
        assert bundle_auth_props[0]["key"].startswith(NITO_ORCHARD_BUNDLE_AUTH_KEY.hex())
        for entry in action_auth_props:
            assert entry["key"].startswith(NITO_ORCHARD_ACTION_AUTH_KEY_PREFIX.hex())

        analysis = node.analyzepsbt(psbt)
        assert_equal(analysis["fee"], fee)
        assert_equal(analysis["next"], expected_next)
        return decoded

    def assert_private_signing_plan_psbt(self, node, wallet, psbt, fee):
        decoded = node.decodepsbt(psbt)
        assert_equal(decoded["tx"]["has_private_bundle"], True)
        assert_equal(decoded["tx"]["private_bundle"]["has_auth"], False)
        legacy_auth_props = [
            entry for entry in decoded.get("proprietary", [])
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 1
        ]
        bundle_auth_props = [
            entry for entry in decoded.get("proprietary", [])
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 3
        ]
        action_auth_props = [
            entry for entry in decoded.get("proprietary", [])
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 2
        ]
        plan_props = [
            entry for entry in decoded.get("proprietary", [])
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 6
        ]
        spend_material_props = [
            entry for entry in decoded.get("proprietary", [])
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 4
        ]
        output_material_props = [
            entry for entry in decoded.get("proprietary", [])
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 5
        ]
        assert_equal(len(legacy_auth_props), 0)
        assert_equal(len(bundle_auth_props), 0)
        assert_equal(len(action_auth_props), 0)
        assert_equal(len(plan_props), 1)
        assert_greater_than(len(spend_material_props), 0)
        assert_greater_than(len(output_material_props), 0)
        intent_hash = self.private_intent_hash(node, psbt)
        assert_equal(decoded["nito_private_intent"]["spend_count"], len(spend_material_props))
        assert_equal(decoded["nito_private_intent"]["output_count"], len(output_material_props))

        analysis = node.analyzepsbt(psbt)
        assert_equal(analysis["fee"], fee)
        assert_equal(analysis["next"], "signer")
        assert_equal(node.finalizepsbt(psbt)["complete"], False)

        unsigned_processed = wallet.walletprocesspsbt(psbt, False)
        assert_equal(unsigned_processed["complete"], False)
        assert "hex" not in unsigned_processed

        assert_raises_rpc_error(
            -8,
            "private_intent_hash is required",
            wallet.walletprocesspsbt,
            psbt,
        )
        processed = wallet.walletprocesspsbt(psbt, True, "ALL", True, True, intent_hash)
        assert_equal(processed["complete"], True)
        assert "hex" in processed
        signed_decoded = self.assert_private_auth_psbt(node, processed["psbt"], node.analyzepsbt(processed["psbt"])["fee"], "extractor")
        signed_plan_props = [
            entry for entry in signed_decoded.get("proprietary", [])
            if entry["identifier"] == "6e69746f" and entry["subtype"] in (4, 5, 6)
        ]
        assert_equal(len(signed_plan_props), 0)
        return processed

    def assert_standard_transparent_psbt(self, node, wallet, psbt, fee):
        decoded = node.decodepsbt(psbt)
        assert_equal(decoded["tx"].get("has_private_bundle", False), False)
        private_auth_props = [
            entry for entry in decoded.get("proprietary", [])
            if entry["identifier"] == "6e69746f" and entry["subtype"] == 1
        ]
        assert_equal(len(private_auth_props), 0)

        analysis = node.analyzepsbt(psbt)
        assert_equal(analysis["fee"], fee)
        assert_equal(analysis["next"], "signer")

        processed = wallet.walletprocesspsbt(psbt)
        assert_equal(processed["complete"], True)
        assert "hex" in processed
        final_tx = node.decoderawtransaction(processed["hex"])
        assert_equal(final_tx.get("has_private_bundle", False), False)

        finalized = node.finalizepsbt(processed["psbt"])
        assert_equal(finalized["complete"], True)
        assert_equal(finalized["hex"], processed["hex"])

        txid = node.sendrawtransaction(processed["hex"])
        self.mine_to_height(node, node.getblockcount() + 1)
        block = node.getblock(node.getbestblockhash(), 2)
        assert txid in {tx["txid"] for tx in block["tx"]}
        return txid

    def assert_legacy_private_auth_rejected(self, node, psbt):
        legacy_auth_psbt = self.add_legacy_private_auth_record(psbt)
        assert_raises_rpc_error(
            -22,
            "Unsupported legacy Nito private authorization record",
            node.decodepsbt,
            legacy_auth_psbt,
        )

    def assert_missing_private_auth_not_extractable(self, node, wallet, psbt):
        missing_auth_psbt = self.strip_private_auth(psbt)
        missing_auth_decoded = node.decodepsbt(missing_auth_psbt)
        assert_equal(missing_auth_decoded["tx"]["has_private_bundle"], True)
        assert_equal(missing_auth_decoded["tx"]["private_bundle"]["has_auth"], False)
        missing_auth_signed = wallet.walletprocesspsbt(missing_auth_psbt)
        assert_equal(missing_auth_signed["complete"], False)
        assert "hex" not in missing_auth_signed
        assert_equal(node.finalizepsbt(missing_auth_signed["psbt"])["complete"], False)

    def assert_split_private_auth_combines(self, node, wallet, psbt):
        bundle_only_psbt = self.strip_private_auth(psbt, keep_bundle_auth=True)
        action_only_psbt = self.strip_private_auth(psbt, keep_action_auth=True)

        assert_equal(node.decodepsbt(bundle_only_psbt)["tx"]["private_bundle"]["has_auth"], False)
        assert_equal(node.decodepsbt(action_only_psbt)["tx"]["private_bundle"]["has_auth"], False)
        assert_equal(node.finalizepsbt(bundle_only_psbt)["complete"], False)
        assert_equal(node.finalizepsbt(action_only_psbt)["complete"], False)

        combined = node.combinepsbt([bundle_only_psbt, action_only_psbt])
        self.assert_private_auth_psbt(node, combined, node.analyzepsbt(combined)["fee"], "extractor")
        finalized = node.finalizepsbt(wallet.walletprocesspsbt(combined)["psbt"])
        assert_equal(finalized["complete"], True)

    def assert_private_signing_material_combines(self, node, wallet, psbt):
        spend_side = self.strip_private_signing_material(psbt, keep_plan=True, keep_spend=True)
        output_side = self.strip_private_signing_material(psbt, keep_output=True)
        assert_equal(node.finalizepsbt(spend_side)["complete"], False)
        assert_equal(node.finalizepsbt(output_side)["complete"], False)

        combined = node.combinepsbt([spend_side, output_side])
        processed = self.process_psbt(node, wallet, combined)
        assert_equal(processed["complete"], True)
        self.assert_private_auth_psbt(node, processed["psbt"], node.analyzepsbt(processed["psbt"])["fee"], "extractor")
        return processed["psbt"]

    def assert_tampered_private_auth_not_extractable(self, node, wallet, psbt):
        tampered = self.tamper_first_private_auth_byte(psbt)
        assert_equal(node.finalizepsbt(tampered)["complete"], False)
        processed = wallet.walletprocesspsbt(tampered)
        assert_equal(processed["complete"], False)
        assert "hex" not in processed

    def assert_short_private_auth_rejected_before_verification(self, node, psbt):
        malformed = self.shorten_first_private_auth(psbt)
        assert_equal(node.finalizepsbt(malformed)["complete"], False)

    def assert_tampered_private_signing_material_rejected(self, node, wallet, psbt):
        reviewed_hash = self.private_intent_hash(node, psbt)
        tampered = self.tamper_first_private_signing_material_byte(psbt)
        tampered_hash = self.private_intent_hash(node, tampered)
        assert reviewed_hash != tampered_hash
        assert_raises_rpc_error(
            -8,
            "PSBT is not well-formed",
            wallet.walletprocesspsbt,
            tampered,
            True,
            "ALL",
            True,
            True,
            reviewed_hash,
        )
        assert_raises_rpc_error(
            -8,
            "PSBT is not well-formed",
            wallet.walletprocesspsbt,
            tampered,
            True,
            "ALL",
            True,
            True,
            tampered_hash,
        )

    def public_output_value(self, decoded_tx, address):
        matches = [
            Decimal(str(vout["value"]))
            for vout in decoded_tx["vout"]
            if vout["scriptPubKey"].get("address") == address
        ]
        assert_equal(len(matches), 1)
        return matches[0]

    def process_broadcast_and_confirm_psbt(self, node, wallet, psbt):
        processed = self.process_psbt(node, wallet, psbt)
        assert_equal(processed["complete"], True)
        assert "hex" in processed
        final_tx = node.decoderawtransaction(processed["hex"])
        assert_equal(final_tx["has_private_bundle"], True)
        assert_greater_than(final_tx["private_bundle"]["actions"], 0)
        assert_equal(final_tx["private_bundle"]["has_auth"], True)

        finalized = node.finalizepsbt(processed["psbt"])
        assert_equal(finalized["complete"], True)
        assert_equal(finalized["hex"], processed["hex"])

        txid = node.sendrawtransaction(processed["hex"])
        self.mine_to_height(node, node.getblockcount() + 1)
        block = node.getblock(node.getbestblockhash(), 2)
        assert txid in {tx["txid"] for tx in block["tx"]}
        return txid

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Mine transparent funds and activate private transactions")
        self.mine_to_height(node, 101)

        self.log.info("CLI named private flags preserve JSON boolean types")
        cli_wallet = node.cli(f"-rpcwallet={self.default_wallet_name}")
        assert_equal(cli_wallet.getprivatekeymaninfo(include_private=False), wallet.getprivatekeymaninfo(False))
        cli_outputs = {wallet.getnewaddress(): Decimal("0.1")}
        cli_funded = cli_wallet.walletcreatefundedpsbt(inputs=[], outputs=cli_outputs, private=False, fee_rate=1)
        assert "private_bundle" not in node.decodepsbt(cli_funded["psbt"])["tx"]
        raw = wallet.createrawtransaction([], cli_outputs)
        cli_raw = cli_wallet.fundrawtransaction(hexstring=raw, private=False, fee_rate=1)
        assert "private_bundle" not in node.decoderawtransaction(cli_raw["hex"])
        mempool_before_cli = node.getrawmempool()
        cli_send = cli_wallet.send(outputs=cli_outputs, private=False, fee_rate=1, add_to_wallet=False)
        assert cli_send["complete"]
        assert_equal(node.getrawmempool(), mempool_before_cli)

        self.log.info("sendmany can create one transparent-funded transaction with many Bech32x outputs")
        multi_private_outputs = {
            wallet.getnewaddress("", "bech32x"): Decimal("0.001")
            for _ in range(11)
        }
        multi_private_txid = wallet.sendmany(dummy="", amounts=multi_private_outputs, fee_rate=1)
        assert multi_private_txid in node.getrawmempool()
        multi_private_tx = wallet.gettransaction(multi_private_txid, verbose=True)
        assert_equal(multi_private_tx["decoded"]["has_private_bundle"], True)
        assert_equal(multi_private_tx["decoded"]["private_bundle"]["actions"], len(multi_private_outputs))
        assert_equal(multi_private_tx["private_external_credit"], sum(multi_private_outputs.values(), Decimal("0")))
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= len(multi_private_outputs), timeout=240)

        self.log.info("A transparent-only PSBT stays on the standard PSBT path")
        transparent_addr = wallet.getnewaddress()
        transparent_only = wallet.walletcreatefundedpsbt(
            [],
            {transparent_addr: Decimal("0.10")},
            0,
            {"fee_rate": 1},
            True,
        )
        self.assert_legacy_private_auth_rejected(node, transparent_only["psbt"])
        self.assert_standard_transparent_psbt(node, wallet, transparent_only["psbt"], transparent_only["fee"])

        self.log.info("Transparent change overrides apply to shielding, but not private-note spends")
        override_recipient = wallet.getnewaddress("", "bech32x")
        override_change = wallet.getnewaddress("", "bech32")
        for override in ({"changeAddress": override_change}, {"change_type": "legacy"}):
            overridden = wallet.walletcreatefundedpsbt(
                [], {override_recipient: Decimal("0.01")}, 0, {"fee_rate": 1, **override}, True,
            )
            override_outputs = node.decodepsbt(overridden["psbt"])["tx"]["vout"]
            assert_equal(len(override_outputs), 1)
            if "changeAddress" in override:
                assert_equal(override_outputs[0]["scriptPubKey"]["address"], override_change)
            else:
                assert_equal(override_outputs[0]["scriptPubKey"]["type"], "pubkeyhash")
            self.process_broadcast_and_confirm_psbt(node, wallet, overridden["psbt"])

        private_change_error = "Transparent change options cannot be used when spending private notes; change remains in Orchard."
        for override in ({"changeAddress": override_change}, {"change_address": override_change}, {"change_type": "bech32"}):
            private_options = {"fee_rate": 1, "private": True, **override}
            assert_raises_rpc_error(
                -8, private_change_error, wallet.walletcreatefundedpsbt,
                [], {transparent_addr: Decimal("0.01")}, 0, private_options,
            )
            assert_raises_rpc_error(
                -8, private_change_error, wallet.fundrawtransaction,
                node.createrawtransaction([], {transparent_addr: Decimal("0.01")}), private_options,
            )
            if "changeAddress" not in override:
                assert_raises_rpc_error(
                    -8, private_change_error, wallet.send,
                    outputs={transparent_addr: Decimal("0.01")}, options=private_options,
                )

        self.log.info("Create a transparent-funded PSBT to a Bech32x recipient")
        shield_addr = wallet.getnewaddress("", "bech32x")
        funded = wallet.walletcreatefundedpsbt(
            [],
            {shield_addr: Decimal("0.25")},
            0,
            {"fee_rate": 1},
            True,
        )
        psbt = funded["psbt"]
        assert_greater_than(funded["fee"], Decimal("0"))

        # The private recipient is encoded in Orchard, so the sole transparent
        # output is fresh internal change. With no matching transparent
        # recipient, the type falls back to BIP86 for descriptors and SegWit-v0
        # for legacy wallets. Orchard change is unaffected.
        shield_psbt = node.decodepsbt(psbt)
        shield_decoded = shield_psbt["tx"]
        assert_equal(len(shield_decoded["vout"]), 1)
        shield_change = shield_decoded["vout"][0]
        assert_equal(shield_change["scriptPubKey"]["type"],
                     "witness_v1_taproot" if self.options.descriptors else "witness_v0_keyhash")
        shield_change_info = wallet.getaddressinfo(shield_change["scriptPubKey"]["address"])
        assert_equal(shield_change_info["ischange"], True)
        change_branch = "m/86h/1h/0h/1/" if self.options.descriptors else "m/0'/1'/"
        assert shield_change_info["hdkeypath"].startswith(change_branch)

        # The analyzer's role depends on the selected INPUT scripts, not on
        # descriptor versus legacy wallet format or the new change output type.
        # Its dummy provider reports unsigned key-path Taproot as updater;
        # native key-hash inputs with complete metadata only need signatures.
        input_types = {entry["witness_utxo"]["scriptPubKey"]["type"] for entry in shield_psbt["inputs"]}
        assert input_types and input_types <= {"witness_v0_keyhash", "witness_v1_taproot"}
        expected_next = "updater" if "witness_v1_taproot" in input_types else "signer"
        self.assert_private_auth_psbt(node, psbt, funded["fee"], expected_next)

        self.log.info("A PSBT missing Orchard auth must not be extractable")
        self.assert_missing_private_auth_not_extractable(node, wallet, psbt)

        self.log.info("Sign, finalize, broadcast, and confirm the Bech32x PSBT")
        shield_txid = self.process_broadcast_and_confirm_psbt(node, wallet, psbt)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        if self.options.descriptors:
            self.log.info("Explicitly sign a shield PSBT funded by the confirmed Taproot change")
            taproot_funded = wallet.walletcreatefundedpsbt(
                [{"txid": shield_txid, "vout": shield_change["n"]}],
                {shield_addr: Decimal("0.01")},
                0,
                {"fee_rate": 1, "add_inputs": False},
                True,
            )
            taproot_decoded = self.assert_private_auth_psbt(node, taproot_funded["psbt"], taproot_funded["fee"], "updater")
            assert_equal(len(taproot_decoded["inputs"]), 1)
            assert_equal(taproot_decoded["inputs"][0]["witness_utxo"]["scriptPubKey"]["type"], "witness_v1_taproot")
            assert_equal(self.process_psbt(node, wallet, taproot_funded["psbt"])["complete"], True)

        self.log.info("Create and confirm a private-note PSBT to a transparent recipient")
        next_internal_before_private_spends = wallet.getprivatekeymaninfo()["next_internal_index"]
        transparent_addr = wallet.getnewaddress()
        private_to_transparent = wallet.walletcreatefundedpsbt(
            [],
            {transparent_addr: Decimal("0.08")},
            0,
            {"fee_rate": 1, "private": True},
            True,
        )
        signed_private_to_transparent = self.assert_private_signing_plan_psbt(node, wallet, private_to_transparent["psbt"], private_to_transparent["fee"])
        self.assert_tampered_private_signing_material_rejected(node, wallet, private_to_transparent["psbt"])
        private_to_transparent_txid = self.process_broadcast_and_confirm_psbt(node, wallet, signed_private_to_transparent["psbt"])
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)
        assert_equal(wallet.getprivatekeymaninfo()["next_internal_index"], next_internal_before_private_spends)
        private_to_transparent_tx = wallet.gettransaction(private_to_transparent_txid)
        assert_greater_than(private_to_transparent_tx["private_internal_credit"], Decimal("0"))
        assert_equal(private_to_transparent_tx["private_external_credit"], Decimal("0"))

        self.log.info("Create and confirm a private-note PSBT to a Bech32x recipient")
        private_addr = wallet.getnewaddress("", "bech32x")
        private_to_private = wallet.walletcreatefundedpsbt(
            [],
            {private_addr: Decimal("0.05")},
            0,
            {"fee_rate": 1, "private": True},
            True,
        )
        private_to_private_intent = node.decodepsbt(private_to_private["psbt"])["nito_private_intent"]
        assert any(
            output["address"] == private_addr and output["amount"] == Decimal("0.05") and not output["internal"]
            for output in private_to_private_intent["outputs"]
        )
        donor_private_to_private = wallet.walletcreatefundedpsbt(
            [],
            {wallet.getnewaddress("", "bech32x"): Decimal("0.05")},
            0,
            {"fee_rate": 1, "private": True},
            True,
        )
        self.assert_well_formed_private_recipient_tamper_rejected(
            node,
            wallet,
            private_to_private["psbt"],
            donor_private_to_private["psbt"],
        )
        signed_private_to_private = self.assert_private_signing_plan_psbt(node, wallet, private_to_private["psbt"], private_to_private["fee"])
        self.log.info("Split Orchard signing material records combine and sign into a complete private PSBT")
        combined_signed_psbt = self.assert_private_signing_material_combines(node, wallet, private_to_private["psbt"])
        self.log.info("Split Orchard PSBT auth records combine back into a complete private PSBT")
        self.assert_split_private_auth_combines(node, wallet, combined_signed_psbt)
        self.log.info("Tampered Orchard PSBT auth records must not be extractable")
        self.assert_tampered_private_auth_not_extractable(node, wallet, signed_private_to_private["psbt"])
        self.assert_short_private_auth_rejected_before_verification(node, signed_private_to_private["psbt"])
        private_to_private_txid = self.process_broadcast_and_confirm_psbt(node, wallet, signed_private_to_private["psbt"])
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)
        assert_equal(wallet.getprivatekeymaninfo()["next_internal_index"], next_internal_before_private_spends)
        private_to_private_tx = wallet.gettransaction(private_to_private_txid)
        assert_greater_than(private_to_private_tx["private_internal_credit"], Decimal("0"))
        assert_equal(private_to_private_tx["private_external_credit"], Decimal("0.05"))

        self.log.info("A transparent-funded PSBT can mix transparent and Bech32x recipients")
        mixed_transparent_psbt_t_addr = wallet.getnewaddress()
        mixed_transparent_psbt_p_addr = wallet.getnewaddress("", "bech32x")
        mixed_transparent_psbt = wallet.walletcreatefundedpsbt(
            [],
            {
                mixed_transparent_psbt_t_addr: Decimal("0.006"),
                mixed_transparent_psbt_p_addr: Decimal("0.007"),
            },
            0,
            {"fee_rate": 1},
            True,
        )
        self.assert_private_auth_psbt(node, mixed_transparent_psbt["psbt"], mixed_transparent_psbt["fee"], "signer")
        mixed_transparent_psbt_txid = self.process_broadcast_and_confirm_psbt(node, wallet, mixed_transparent_psbt["psbt"])
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)
        mixed_transparent_psbt_tx = wallet.gettransaction(mixed_transparent_psbt_txid, verbose=True)
        assert_equal(mixed_transparent_psbt_tx["decoded"]["has_private_bundle"], True)
        assert any(vout["scriptPubKey"].get("address") == mixed_transparent_psbt_t_addr for vout in mixed_transparent_psbt_tx["decoded"]["vout"])
        assert_greater_than(mixed_transparent_psbt_tx["private_external_credit"], Decimal("0"))

        self.log.info("A direct transparent-funded send can mix transparent and Bech32x recipients")
        mixed_transparent_direct_t_addr = wallet.getnewaddress()
        mixed_transparent_direct_p_addr = wallet.getnewaddress("", "bech32x")
        mixed_transparent_direct_res = wallet.send(
            outputs={
                mixed_transparent_direct_t_addr: Decimal("0.003"),
                mixed_transparent_direct_p_addr: Decimal("0.004"),
            },
            options={"fee_rate": 1},
        )
        assert_equal(mixed_transparent_direct_res["complete"], True)
        assert "txid" in mixed_transparent_direct_res
        assert "psbt" not in mixed_transparent_direct_res
        assert "hex" not in mixed_transparent_direct_res
        assert mixed_transparent_direct_res["txid"] in node.getrawmempool()
        mixed_transparent_direct_tx = wallet.gettransaction(mixed_transparent_direct_res["txid"], verbose=True)
        assert_equal(mixed_transparent_direct_tx["decoded"]["has_private_bundle"], True)
        assert any(vout["scriptPubKey"].get("address") == mixed_transparent_direct_t_addr for vout in mixed_transparent_direct_tx["decoded"]["vout"])
        assert_greater_than(mixed_transparent_direct_tx["private_external_credit"], Decimal("0"))
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("Transparent-funded mixed sends honor subtract_fee_from_outputs")
        mixed_transparent_sffo_t_addr = wallet.getnewaddress()
        mixed_transparent_sffo_p_addr = wallet.getnewaddress("", "bech32x")
        mixed_transparent_sffo_res = wallet.send(
            outputs={
                mixed_transparent_sffo_t_addr: Decimal("0.003"),
                mixed_transparent_sffo_p_addr: Decimal("0.004"),
            },
            options={"fee_rate": 1, "subtract_fee_from_outputs": [0, 1]},
        )
        assert_equal(mixed_transparent_sffo_res["complete"], True)
        mixed_transparent_sffo_tx = wallet.gettransaction(mixed_transparent_sffo_res["txid"], verbose=True)
        transparent_sffo_value = self.public_output_value(mixed_transparent_sffo_tx["decoded"], mixed_transparent_sffo_t_addr)
        assert_greater_than(Decimal("0.003"), transparent_sffo_value)
        assert_greater_than(transparent_sffo_value, Decimal("0"))
        assert_greater_than(Decimal("0.004"), mixed_transparent_sffo_tx["private_external_credit"])
        assert_greater_than(mixed_transparent_sffo_tx["private_external_credit"], Decimal("0"))
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("A private-note PSBT can mix transparent and Bech32x recipients")
        mixed_private_psbt_t_addr = wallet.getnewaddress()
        mixed_private_psbt_p_addr = wallet.getnewaddress("", "bech32x")
        mixed_private_psbt = wallet.walletcreatefundedpsbt(
            [],
            {
                mixed_private_psbt_t_addr: Decimal("0.006"),
                mixed_private_psbt_p_addr: Decimal("0.007"),
            },
            0,
            {"fee_rate": 1, "private": True},
            True,
        )
        signed_mixed_private_psbt = self.assert_private_signing_plan_psbt(node, wallet, mixed_private_psbt["psbt"], mixed_private_psbt["fee"])
        mixed_private_psbt_txid = self.process_broadcast_and_confirm_psbt(node, wallet, signed_mixed_private_psbt["psbt"])
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)
        mixed_private_psbt_tx = wallet.gettransaction(mixed_private_psbt_txid, verbose=True)
        assert_equal(mixed_private_psbt_tx["decoded"]["has_private_bundle"], True)
        assert any(vout["scriptPubKey"].get("address") == mixed_private_psbt_t_addr for vout in mixed_private_psbt_tx["decoded"]["vout"])
        assert_greater_than(mixed_private_psbt_tx["private_external_credit"], Decimal("0"))

        self.log.info("A direct private send can mix transparent and Bech32x recipients")
        mixed_private_direct_t_addr = wallet.getnewaddress()
        mixed_private_direct_p_addr = wallet.getnewaddress("", "bech32x")
        mixed_private_direct_res = wallet.send(
            outputs={
                mixed_private_direct_t_addr: Decimal("0.003"),
                mixed_private_direct_p_addr: Decimal("0.004"),
            },
            options={"fee_rate": 1, "private": True},
        )
        assert_equal(mixed_private_direct_res["complete"], True)
        assert "txid" in mixed_private_direct_res
        assert "psbt" not in mixed_private_direct_res
        assert "hex" not in mixed_private_direct_res
        assert mixed_private_direct_res["txid"] in node.getrawmempool()
        mixed_private_direct_tx = wallet.gettransaction(mixed_private_direct_res["txid"], verbose=True)
        assert_equal(mixed_private_direct_tx["decoded"]["has_private_bundle"], True)
        assert any(vout["scriptPubKey"].get("address") == mixed_private_direct_t_addr for vout in mixed_private_direct_tx["decoded"]["vout"])
        assert_greater_than(mixed_private_direct_tx["private_external_credit"], Decimal("0"))
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("A wallet receiving a private-funded mixed transaction has no sent rows")
        node.createwallet(wallet_name="mixed_receiver", descriptors=True)
        receiver = node.get_wallet_rpc("mixed_receiver")
        receiver_t_addr = receiver.getnewaddress()
        receiver_p_addr = receiver.getnewaddress("", "bech32x")
        receiver_mixed_res = wallet.send(
            outputs={
                receiver_t_addr: Decimal("0.003"),
                receiver_p_addr: Decimal("0.004"),
            },
            options={"fee_rate": 1, "private": True},
        )
        assert_equal(receiver_mixed_res["complete"], True)
        node.syncwithvalidationinterfacequeue()
        receiver_rows = [
            entry for entry in receiver.listtransactions("*", 20, 0, True)
            if entry["txid"] == receiver_mixed_res["txid"]
        ]
        assert_equal(sorted(entry["category"] for entry in receiver_rows), ["receive", "receive"])
        assert_equal(sum((entry["amount"] for entry in receiver_rows), Decimal("0")), Decimal("0.007"))
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("Private-note mixed sends honor subtract_fee_from_outputs")
        mixed_private_sffo_t_addr = wallet.getnewaddress()
        mixed_private_sffo_p_addr = wallet.getnewaddress("", "bech32x")
        mixed_private_sffo_res = wallet.send(
            outputs={
                mixed_private_sffo_t_addr: Decimal("0.003"),
                mixed_private_sffo_p_addr: Decimal("0.004"),
            },
            options={"fee_rate": 1, "private": True, "subtract_fee_from_outputs": [0, 1]},
        )
        assert_equal(mixed_private_sffo_res["complete"], True)
        mixed_private_sffo_tx = wallet.gettransaction(mixed_private_sffo_res["txid"], verbose=True)
        private_sffo_public_value = self.public_output_value(mixed_private_sffo_tx["decoded"], mixed_private_sffo_t_addr)
        assert_greater_than(Decimal("0.003"), private_sffo_public_value)
        assert_greater_than(private_sffo_public_value, Decimal("0"))
        assert_greater_than(Decimal("0.004"), mixed_private_sffo_tx["private_external_credit"])
        assert_greater_than(mixed_private_sffo_tx["private_external_credit"], Decimal("0"))
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("The send RPC also returns a PSBT for private-note funding")
        send_private_addr = wallet.getnewaddress("", "bech32x")
        send_res = wallet.send(
            outputs={send_private_addr: Decimal("0.02")},
            options={"fee_rate": 1, "private": True, "psbt": True},
        )
        assert_equal(send_res["complete"], True)
        assert "psbt" in send_res
        assert "hex" in send_res
        self.assert_private_auth_psbt(node, send_res["psbt"], node.analyzepsbt(send_res["psbt"])["fee"], "extractor")
        txid = node.sendrawtransaction(send_res["hex"])
        self.mine_to_height(node, node.getblockcount() + 1)
        block = node.getblock(node.getbestblockhash(), 2)
        assert txid in {tx["txid"] for tx in block["tx"]}
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("The direct private send path returns signed hex when add_to_wallet is false")
        offline_transparent_addr = wallet.getnewaddress()
        offline_transparent_res = wallet.send(
            outputs={offline_transparent_addr: Decimal("0.005")},
            options={"fee_rate": 1, "private": True, "add_to_wallet": False},
        )
        assert_equal(offline_transparent_res["complete"], True)
        assert "txid" in offline_transparent_res
        assert "hex" in offline_transparent_res
        assert "psbt" not in offline_transparent_res
        assert offline_transparent_res["txid"] not in node.getrawmempool()
        offline_transparent_tx = node.decoderawtransaction(offline_transparent_res["hex"])
        assert_equal(offline_transparent_tx["has_private_bundle"], True)
        offline_accept = node.testmempoolaccept([offline_transparent_res["hex"]])[0]
        assert_equal(offline_accept["allowed"], True)

        self.log.info("The send RPC broadcasts private-note funding directly when psbt is not requested")
        direct_transparent_addr = wallet.getnewaddress()
        direct_transparent_res = wallet.send(
            outputs={direct_transparent_addr: Decimal("0.01")},
            options={"fee_rate": 1, "private": True},
        )
        assert_equal(direct_transparent_res["complete"], True)
        assert "txid" in direct_transparent_res
        assert "psbt" not in direct_transparent_res
        assert "hex" not in direct_transparent_res
        assert direct_transparent_res["txid"] in node.getrawmempool()
        direct_transparent_tx = wallet.gettransaction(direct_transparent_res["txid"], verbose=True)
        assert_equal(direct_transparent_tx["decoded"]["has_private_bundle"], True)
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        direct_private_addr = wallet.getnewaddress("", "bech32x")
        direct_private_res = wallet.send(
            outputs={direct_private_addr: Decimal("0.01")},
            options={"fee_rate": 1, "private": True, "replaceable": True},
        )
        assert_equal(direct_private_res["complete"], True)
        assert "txid" in direct_private_res
        assert "psbt" not in direct_private_res
        assert "hex" not in direct_private_res
        assert direct_private_res["txid"] in node.getrawmempool()
        direct_private_tx = wallet.gettransaction(direct_private_res["txid"], verbose=True)
        assert_equal(direct_private_tx["bip125-replaceable"], "yes")
        assert_equal(direct_private_tx["decoded"]["version"], 3)
        assert_equal(direct_private_tx["decoded"]["has_private_bundle"], True)
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("Transparent-funded private bundles can be fee-bumped")
        transparent_bump_addr = wallet.getnewaddress("", "bech32x")
        transparent_bump_txid = wallet.shieldtoaddress(address=transparent_bump_addr, amount=Decimal("0.03"), replaceable=True, fee_rate=1)
        transparent_bump_tx = wallet.gettransaction(transparent_bump_txid, verbose=True)
        assert_equal(transparent_bump_tx["bip125-replaceable"], "yes")
        assert_equal(transparent_bump_tx["decoded"]["version"], 2)
        assert_equal(transparent_bump_tx["decoded"]["has_private_bundle"], True)
        transparent_bumped = wallet.bumpfee(transparent_bump_txid, {"fee_rate": 10})
        assert_greater_than(transparent_bumped["fee"], transparent_bumped["origfee"])
        assert_equal(transparent_bumped["txid"] in node.getrawmempool(), True)
        assert_equal(transparent_bump_txid in node.getrawmempool(), False)
        transparent_replacement = wallet.gettransaction(transparent_bumped["txid"], verbose=True)
        assert_equal(transparent_replacement["decoded"]["version"], 2)
        assert_equal(transparent_replacement["decoded"]["has_private_bundle"], True)
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("Private-note spends can be fee-bumped directly")
        direct_rbf_addr = wallet.getnewaddress("", "bech32x")
        direct_rbf_txid = wallet.sendprivate(address=direct_rbf_addr, amount=Decimal("0.01"), replaceable=True, fee_rate=1)
        direct_rbf_tx = wallet.gettransaction(direct_rbf_txid, verbose=True)
        assert_equal(direct_rbf_tx["bip125-replaceable"], "yes")
        assert_equal(direct_rbf_tx["decoded"]["version"], 3)
        assert_equal(direct_rbf_tx["decoded"]["has_private_bundle"], True)
        direct_bumped = wallet.bumpfee(direct_rbf_txid, {"fee_rate": 10})
        assert_greater_than(direct_bumped["fee"], direct_bumped["origfee"])
        assert_equal(direct_bumped["txid"] in node.getrawmempool(), True)
        assert_equal(direct_rbf_txid in node.getrawmempool(), False)
        direct_bumped_tx = wallet.gettransaction(direct_bumped["txid"], verbose=True)
        assert_equal(direct_bumped_tx["decoded"]["version"], 3)
        assert_equal(direct_bumped_tx["decoded"]["has_private_bundle"], True)
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        self.log.info("Private-note spends can be fee-bumped through PSBT signing material")
        rbf_addr = wallet.getnewaddress("", "bech32x")
        rbf_txid = wallet.sendprivate(address=rbf_addr, amount=Decimal("0.01"), replaceable=True, fee_rate=1)
        rbf_tx = wallet.gettransaction(rbf_txid, verbose=True)
        assert_equal(rbf_tx["bip125-replaceable"], "yes")
        assert_equal(rbf_tx["decoded"]["version"], 3)
        assert_equal(rbf_tx["decoded"]["has_private_bundle"], True)
        bumped_psbt = wallet.psbtbumpfee(rbf_txid, {"fee_rate": 10})
        assert_greater_than(bumped_psbt["fee"], bumped_psbt["origfee"])
        signed_bump = self.assert_private_signing_plan_psbt(node, wallet, bumped_psbt["psbt"], bumped_psbt["fee"])
        bumped_txid = node.sendrawtransaction(signed_bump["hex"])
        assert_equal(bumped_txid in node.getrawmempool(), True)
        assert_equal(rbf_txid in node.getrawmempool(), False)
        bumped_tx = wallet.gettransaction(bumped_txid, verbose=True)
        assert_equal(bumped_tx["decoded"]["version"], 3)
        assert_equal(bumped_tx["decoded"]["has_private_bundle"], True)
        self.mine_to_height(node, node.getblockcount() + 1)


if __name__ == "__main__":
    WalletPrivatePSBTTest().main()
