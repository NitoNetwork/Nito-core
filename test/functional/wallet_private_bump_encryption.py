#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Keep Orchard fee-bump metadata encrypted across wallet lifecycle operations."""

from decimal import Decimal
import base64
from pathlib import Path

from test_framework.segwit_addr import bech32_decode, convertbits
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


PASSPHRASE = "private bump encryption test"
NEW_PASSPHRASE = "private bump encryption changed"


class WalletPrivateBumpEncryptionTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-privateactivationheight=1"]]
        self.rpc_timeout = 240

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        mining_address = miner.getnewaddress()

        def mine(count=1):
            self.generatetoaddress(node, count, mining_address, 10_000_000)
            node.syncwithvalidationinterfacequeue()

        mine(101)
        node.createwallet(wallet_name="sender", descriptors=self.options.descriptors)
        node.createwallet(wallet_name="recipient", descriptors=self.options.descriptors)
        sender = node.get_wallet_rpc("sender")
        recipient = node.get_wallet_rpc("recipient")
        recipient_address = recipient.getnewaddress("", "bech32x")
        _, _, address_data = bech32_decode(recipient_address)
        raw_address = bytes(convertbits(address_data[1:], 5, 8, False))[2:]
        assert_equal(len(raw_address), 43)
        raw_fragments = [base64.b64encode(bytes(padding) + raw_address)[4:-4] for padding in range(3)]
        miner.sendtoaddress(sender.getnewaddress(), 2)
        mine()

        self.log.info("Encrypt a wallet with an existing unconfirmed shielding recipe")
        txid = sender.shieldtoaddress(recipient_address, Decimal("0.25"), replaceable=True, fee_rate=1)
        before_encryption = Path(self.options.tmpdir) / "before-encryption.dat"
        sender.backupwallet(str(before_encryption))
        before_data = before_encryption.read_bytes()
        assert any(fragment in before_data for fragment in raw_fragments)
        before_encryption.unlink()
        sender.encryptwallet(PASSPHRASE)
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", sender.bumpfee, txid)

        backup_number = 0

        def assert_backup_private():
            nonlocal backup_number
            backup_number += 1
            backup = Path(self.options.tmpdir) / f"encrypted-bump-{backup_number}.dat"
            sender.backupwallet(str(backup))
            data = backup.read_bytes()
            # This address belongs only to the recipient wallet. Its raw Orchard
            # bytes must not appear in the sender's backup through a bump recipe.
            assert recipient_address.encode() not in data
            assert raw_address not in data
            assert not any(fragment in data for fragment in raw_fragments)
            assert b"nito_private_bump_recipients" not in data
            assert b"nito_private_bump_recipe" in data
            assert not any(key.startswith("nito_private_") for key in sender.gettransaction(txid))

        assert_backup_private()
        node.unloadwallet("sender")
        node.loadwallet("sender")
        sender = node.get_wallet_rpc("sender")
        sender.walletpassphrase(PASSPHRASE, 600)
        bumped = sender.bumpfee(txid, {"fee_rate": 10})
        assert_greater_than(bumped["fee"], bumped["origfee"])
        assert txid not in node.getrawmempool()
        txid = bumped["txid"]
        assert txid in node.getrawmempool()

        self.log.info("Rebind the encrypted recipe when bumping a replacement after passphrase change")
        sender.walletpassphrasechange(PASSPHRASE, NEW_PASSPHRASE)
        sender.walletlock()
        assert_backup_private()
        node.unloadwallet("sender")
        node.loadwallet("sender")
        sender = node.get_wallet_rpc("sender")
        sender.walletpassphrase(NEW_PASSPHRASE, 600)
        bumped = sender.bumpfee(txid, {"fee_rate": 20})
        assert txid not in node.getrawmempool()
        txid = bumped["txid"]
        mine()
        assert_equal(sender.gettransaction(txid)["confirmations"], 1)
        assert_equal(recipient.getprivatebalance()["total_unspent"], Decimal("0.25"))

        self.log.info("An already encrypted wallet can replace a private-note spend")
        funding_address = sender.getnewaddress("", "bech32x")
        miner.shieldtoaddress(funding_address, 2)
        mine()
        txid = sender.sendprivate(recipient_address, Decimal("0.125"), replaceable=True, fee_rate=1)
        sender.walletlock()
        assert_backup_private()
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", sender.psbtbumpfee, txid)
        sender.walletpassphrase(NEW_PASSPHRASE, 600)
        psbt_bump = sender.psbtbumpfee(txid, {"fee_rate": 10})
        assert_greater_than(psbt_bump["fee"], psbt_bump["origfee"])
        assert "psbt" in psbt_bump
        bumped = sender.bumpfee(txid, {"fee_rate": 10})
        assert txid not in node.getrawmempool()
        txid = bumped["txid"]
        sender.walletlock()
        assert_backup_private()
        mine()
        assert_equal(recipient.getprivatebalance()["total_unspent"], Decimal("0.375"))


if __name__ == "__main__":
    WalletPrivateBumpEncryptionTest().main()
