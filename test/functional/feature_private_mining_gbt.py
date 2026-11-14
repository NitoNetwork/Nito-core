#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that Nito.network private transactions do not require private coinbase fields."""

import copy
from decimal import Decimal

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    NORMAL_GBT_REQUEST_PARAMS,
)
from test_framework.messages import (
    COIN,
    tx_from_hex,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

MAX_MINING_TRIES = 10_000_000


def assert_no_private_gbt_fields(template):
    for key in template:
        assert not key.startswith("default_private")
        assert not key.startswith("private_")


class PrivateMiningGBTTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False, legacy=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-privateactivationheight=1"]]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_height(self, node, height):
        blocks = []
        while node.getblockcount() < height:
            blocks.extend(self.generatetoaddress(
                node,
                height - node.getblockcount(),
                node.getnewaddress(),
                MAX_MINING_TRIES,
            ))
        assert_equal(node.getblockcount(), height)
        return blocks

    def assert_proposal(self, node, block, expected):
        result = node.getblocktemplate({
            "data": block.serialize().hex(),
            "mode": "proposal",
            "rules": ["segwit"],
        })
        assert_equal(result, expected)

    def assert_proposal_reject_prefix(self, node, block, expected_prefix):
        result = node.getblocktemplate({
            "data": block.serialize().hex(),
            "mode": "proposal",
            "rules": ["segwit"],
        })
        assert result is not None, "block proposal unexpectedly accepted"
        assert result.startswith(expected_prefix), result

    def parse_template_private_txs(self, template, expected_txids):
        found = set()
        parsed = []
        for entry in template["transactions"]:
            if entry["txid"] not in expected_txids:
                continue
            tx = tx_from_hex(entry["data"])
            assert tx.private_effects is not None
            assert tx.private_auth is not None
            tx.calc_sha256()
            assert_equal(tx.hash, entry["txid"])
            assert_equal(tx.getwtxid(), entry["hash"])
            found.add(entry["txid"])
            parsed.append(tx)
        assert_equal(found, expected_txids)
        return parsed

    def assert_standard_coinbase_shape(self, block, witness_commitment):
        coinbase = block.vtx[0]
        assert coinbase.private_effects is None
        assert coinbase.private_auth is None
        assert_equal(len(coinbase.vin), 1)
        assert_equal(coinbase.vin[0].prevout.hash, 0)
        assert_equal(coinbase.vin[0].prevout.n, 0xffffffff)
        assert_equal(len(coinbase.wit.vtxinwit), 1)
        assert_equal(coinbase.wit.vtxinwit[0].scriptWitness.stack, [b"\x00" * 32])
        assert_equal(coinbase.vout[-1].scriptPubKey.hex(), witness_commitment)

    def get_orchard_pool(self, node):
        return node.getorchardpools()["orchard"]

    def assert_orchard_pool(self, node, expected_value):
        pool = self.get_orchard_pool(node)
        assert_equal(pool["monitored"], True)
        assert_equal(pool["chainValue"], expected_value)
        assert_equal(pool["chainValueNitoshi"], int(expected_value * COIN))

    def private_pool_delta_from_block(self, block):
        delta = Decimal("0")
        for tx in block["tx"]:
            bundle = tx.get("private_bundle")
            if bundle is None:
                continue
            delta -= bundle["value_balance"]
        return delta

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Before private use, getorchardpools exposes an empty monitored Orchard pool")
        self.assert_orchard_pool(node, Decimal("0"))

        self.log.info("Mine spendable transparent funds")
        self.mine_to_height(node, 101)
        self.assert_orchard_pool(node, Decimal("0"))

        self.log.info("Create and confirm private notes used by later private spends")
        note_txids = {
            node.sendtoaddress(node.getnewaddress("", "bech32x"), Decimal("1.0")),
            node.sendtoaddress(node.getnewaddress("", "bech32x"), Decimal("1.0")),
            node.sendtoaddress(node.getnewaddress("", "bech32x"), Decimal("1.0")),
        }
        self.mine_to_height(node, node.getblockcount() + 1)
        self.wait_until(lambda: node.getprivatebalance()["spendable_notes"] >= 3, timeout=240)

        shield_block = node.getblock(node.getbestblockhash(), 2)
        shield_delta = self.private_pool_delta_from_block(shield_block)
        assert_equal(shield_delta, Decimal("3.0"))
        self.assert_orchard_pool(node, shield_delta)
        assert note_txids.issubset({tx["txid"] for tx in shield_block["tx"]})
        confirmed_notes = node.listprivateunspent()
        assert_equal(len([note for note in confirmed_notes if note["spendable"]]), 3)
        for note in confirmed_notes:
            assert_equal(note["derivation_id"], "nito_orchard_derivation")
            assert_equal(note["derivation_version"], 1)
            assert note["path"].startswith("m/96'/0'/0'/0/")
        assert_equal(set(node.getrawmempool()), set())

        self.log.info("Verify private notes lose spendability across a block disconnect and recover on reconsider")
        node.invalidateblock(shield_block["hash"])
        self.wait_until(lambda: node.getprivatebalance()["spendable_notes"] == 0, timeout=120)
        assert_equal(node.listprivateunspent(), [])
        self.assert_orchard_pool(node, Decimal("0"))
        node.reconsiderblock(shield_block["hash"])
        self.wait_until(lambda: node.getprivatebalance()["spendable_notes"] >= 3, timeout=240)
        self.assert_orchard_pool(node, shield_delta)
        assert_equal(set(node.getrawmempool()), set())

        self.log.info("Verify nito-cli conversion for private RPC typed arguments")
        cli_private_address = node.cli().send_cli("getnewaddress", label="", address_type="bech32x")
        assert cli_private_address.split("1", 1)[1].startswith("x"), cli_private_address
        assert_equal(node.validateaddress(cli_private_address)["address_type"], "bech32x")
        assert_raises_rpc_error(-5, "Unknown address type 'private'", node.getnewaddress, "", "private")
        cli_notes = node.cli("listprivateunspent", "0", "false").send_cli()
        assert_equal(len([note for note in cli_notes if note["spendable"]]), 3)

        sender = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Verify indexed Merkle auth paths after rewinding a branch with extra Orchard commitments")
        stale_branch_txid = sender.sendtoaddress(sender.getnewaddress("", "bech32x"), Decimal("0.40"))
        self.mine_to_height(node, node.getblockcount() + 1)
        stale_branch_block = node.getblock(node.getbestblockhash(), 2)
        assert stale_branch_txid in {tx["txid"] for tx in stale_branch_block["tx"]}
        stale_branch_delta = self.private_pool_delta_from_block(stale_branch_block)
        self.assert_orchard_pool(node, shield_delta + stale_branch_delta)
        self.wait_until(lambda: sender.getprivatebalance()["spendable_notes"] >= 4, timeout=240)

        node.invalidateblock(stale_branch_block["hash"])
        self.wait_until(lambda: sender.getprivatebalance()["spendable_notes"] == 3, timeout=120)
        self.assert_orchard_pool(node, shield_delta)
        rewind_psbt = sender.walletcreatefundedpsbt(
            [],
            {sender.getnewaddress(): Decimal("0.25")},
            0,
            {"fee_rate": 1, "private": True},
            True,
        )
        rewind_intent = node.decodepsbt(rewind_psbt["psbt"])["nito_private_intent"]
        processed_rewind_psbt = sender.walletprocesspsbt(
            rewind_psbt["psbt"], True, "ALL", True, True, rewind_intent["hash"]
        )
        assert_equal(processed_rewind_psbt["complete"], True)

        node.reconsiderblock(stale_branch_block["hash"])
        self.wait_until(lambda: sender.getprivatebalance()["spendable_notes"] >= 4, timeout=240)
        shield_delta += stale_branch_delta
        self.assert_orchard_pool(node, shield_delta)
        assert_equal(set(node.getrawmempool()), set())

        self.log.info("Verify notes and nullifiers survive a deeper private reorg")
        deep_spend_tx = sender.sendprivate(sender.getnewaddress(), Decimal("0.25"))
        self.mine_to_height(node, node.getblockcount() + 3)
        self.wait_until(lambda: sender.gettransaction(deep_spend_tx)["confirmations"] >= 3, timeout=120)
        deep_spend_block = node.getblock(sender.gettransaction(deep_spend_tx)["blockhash"], 2)
        deep_spend_delta = self.private_pool_delta_from_block(deep_spend_block)
        self.assert_orchard_pool(node, shield_delta + deep_spend_delta)
        after_deep_spend_balance = sender.getprivatebalance()["total_unspent"]
        node.invalidateblock(shield_block["hash"])
        self.wait_until(lambda: node.getprivatebalance()["spendable_notes"] == 0, timeout=120)
        assert_equal(node.listprivateunspent(), [])
        self.assert_orchard_pool(node, Decimal("0"))
        node.reconsiderblock(shield_block["hash"])
        self.wait_until(lambda: sender.gettransaction(deep_spend_tx)["confirmations"] >= 3, timeout=240)
        assert_equal(sender.getprivatebalance()["total_unspent"], after_deep_spend_balance)
        self.assert_orchard_pool(node, shield_delta + deep_spend_delta)
        assert_equal(set(node.getrawmempool()), set())

        self.log.info("Create a second wallet to verify external private-to-transparent receive display")
        node.createwallet(wallet_name="receiver", descriptors=True)
        receiver = node.get_wallet_rpc("receiver")
        receiver_addr = receiver.getnewaddress("", "bech32")

        self.log.info("Create private transactions in all operational mining directions")
        tx_t_to_p = sender.sendtoaddress(sender.getnewaddress("", "bech32x"), Decimal("0.20"))
        tx_p_to_p = sender.sendprivate(sender.getnewaddress("", "bech32x"), Decimal("0.10"))
        tx_p_to_t = sender.sendprivate(sender.getnewaddress(), Decimal("0.10"))
        tx_p_to_external_t = sender.sendprivate(receiver_addr, Decimal("0.10"))
        expected_txids = {tx_t_to_p, tx_p_to_p, tx_p_to_t, tx_p_to_external_t}
        assert_equal(set(node.getrawmempool()), expected_txids)

        self.log.info("Verify GBT exposes only standard coinbase/witness fields")
        template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_no_private_gbt_fields(template)
        assert "default_witness_commitment" in template
        assert "coinbasetxn" not in template
        expected_private_fees = sum(
            entry["fee"] for entry in template["transactions"] if entry["txid"] in expected_txids
        )
        current_subsidy = node.getblockstats(node.getbestblockhash(), ["subsidy"])["subsidy"]
        assert_equal(template["coinbasevalue"], current_subsidy + expected_private_fees)

        private_txs = self.parse_template_private_txs(template, expected_txids)

        self.log.info("Build a pool-style block from GBT data and submit it")
        block = create_block(tmpl=template, txlist=private_txs)
        add_witness_commitment(block)
        self.assert_standard_coinbase_shape(block, template["default_witness_commitment"])

        bad_coinbase_block = copy.deepcopy(block)
        bad_coinbase_block.vtx[0].private_effects = copy.deepcopy(private_txs[0].private_effects)
        bad_coinbase_block.vtx[0].private_auth = copy.deepcopy(private_txs[0].private_auth)
        bad_coinbase_block.vtx[0].rehash()
        bad_coinbase_block.hashMerkleRoot = bad_coinbase_block.calc_merkle_root()
        bad_coinbase_block.solve()
        self.assert_proposal(node, bad_coinbase_block, "bad-cb-private")

        self.log.info("Reject a P2P block with a tampered public Orchard value balance")
        bad_value_block = copy.deepcopy(block)
        bad_value_block.vtx[1].private_effects.value_balance += COIN
        bad_value_block.vtx[1].rehash()
        add_witness_commitment(bad_value_block)
        bad_value_block.solve()
        self.assert_proposal_reject_prefix(node, bad_value_block, "bad-private-orchard-")
        peer = node.add_p2p_connection(P2PDataStore())
        peer.send_blocks_and_test([bad_value_block], node, success=False, force_send=True, expect_disconnect=True)

        block.solve()
        self.assert_proposal(node, block, None)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getrawmempool(), [])

        accepted = node.getblock(node.getbestblockhash(), 2)
        accepted_delta = self.private_pool_delta_from_block(accepted)
        self.assert_orchard_pool(node, shield_delta + deep_spend_delta + accepted_delta)
        accepted_txids = [tx["txid"] for tx in accepted["tx"]]
        assert expected_txids.issubset(set(accepted_txids))

        self.log.info("Verify private self-transfer and private-to-transparent classifications")
        shield_self_details = sender.gettransaction(tx_t_to_p)["details"]
        assert_equal(len(shield_self_details), 2)
        assert_equal(
            sorted([(d["category"], d["amount"], d.get("private")) for d in shield_self_details]),
            [("receive", Decimal("0.20"), True), ("send", Decimal("-0.20"), True)],
        )

        private_self_details = sender.gettransaction(tx_p_to_p)["details"]
        assert_equal(len(private_self_details), 2)
        assert_equal(
            sorted([(d["category"], d["amount"], d.get("private")) for d in private_self_details]),
            [("receive", Decimal("0.10"), True), ("send", Decimal("-0.10"), True)],
        )

        same_wallet_details = sender.gettransaction(tx_p_to_t)["details"]
        assert_equal(len(same_wallet_details), 1)
        assert_equal(same_wallet_details[0]["category"], "unshield")
        assert_equal(same_wallet_details[0]["transparent_credit"], Decimal("0.10"))

        receiver_details = receiver.gettransaction(tx_p_to_external_t)["details"]
        assert_equal(len(receiver_details), 1)
        assert_equal(receiver_details[0]["category"], "receive")
        assert_equal(receiver_details[0]["amount"], Decimal("0.10"))
        assert "private_debit" not in receiver_details[0]


if __name__ == "__main__":
    PrivateMiningGBTTest().main()
