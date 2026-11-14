#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Hierarchical Deterministic wallet function."""

import shutil

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import get_generate_key

MAX_MINING_TRIES = 10_000_000


class WalletHDTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], ['-keypool=0']]
        # whitelist peers to speed up tx relay / mempool sync
        for args in self.extra_args:
            args.append("-whitelist=noban@127.0.0.1")

        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_node(self, node, blocks):
        mined = []
        target_height = node.getblockcount() + blocks
        while node.getblockcount() < target_height:
            mined.extend(self.generatetoaddress(
                node,
                target_height - node.getblockcount(),
                node.getnewaddress(),
                MAX_MINING_TRIES,
            ))
        node.syncwithvalidationinterfacequeue()
        return mined

    def run_test(self):
        if self.options.descriptors:
            self.log.info("Passphrase-derived HD authority survives encryption and restart with an empty keypool")
            node = self.nodes[1]
            node.createwallet(wallet_name='passphrase_hd', descriptors=True, bip39_passphrase='HD fixture passphrase')
            hd_wallet = node.get_wallet_rpc('passphrase_hd')
            mnemonic = hd_wallet.dumpmnemonic()['mnemonic']
            node.createwallet(wallet_name='passphrase_hd_reference', blank=True, descriptors=True)
            reference = node.get_wallet_rpc('passphrase_hd_reference')
            reference.sethdseed(True, mnemonic, 'HD fixture passphrase')

            self.mine_node(self.nodes[0], 1)
            self.sync_all()

            def compare_next_keys():
                for _ in range(3):
                    assert_equal(hd_wallet.getnewaddress(), reference.getnewaddress())
                    assert_equal(hd_wallet.getrawchangeaddress(), reference.getrawchangeaddress())
                    assert_equal(hd_wallet.getnewaddress('', 'bech32x'), reference.getnewaddress('', 'bech32x'))

            compare_next_keys()
            hd_wallet.encryptwallet('HD file password')
            self.restart_node(1)
            node = self.nodes[1]
            node.loadwallet('passphrase_hd')
            node.loadwallet('passphrase_hd_reference')
            hd_wallet = node.get_wallet_rpc('passphrase_hd')
            reference = node.get_wallet_rpc('passphrase_hd_reference')
            assert_equal(hd_wallet.getwalletinfo()['bip39_passphrase_enabled'], True)
            hd_wallet.walletpassphrase('HD file password', 60)
            assert_equal(hd_wallet.dumpmnemonic()['mnemonic'], mnemonic)
            compare_next_keys()
            node.unloadwallet('passphrase_hd')
            node.unloadwallet('passphrase_hd_reference')
            self.connect_nodes(0, 1)

        # Make sure we use hd, keep masterkeyid
        hd_fingerprint = self.nodes[1].getaddressinfo(self.nodes[1].getnewaddress())['hdmasterfingerprint']
        assert_equal(len(hd_fingerprint), 8)

        # create an internal key
        change_addr = self.nodes[1].getrawchangeaddress()
        change_addrV = self.nodes[1].getaddressinfo(change_addr)
        if self.options.descriptors:
            assert_equal(change_addrV["hdkeypath"], "m/84h/1h/0h/1/0")
        else:
            assert_equal(change_addrV["hdkeypath"], "m/0'/1'/0'")  #first internal child key

        # Import a non-HD private key in the HD wallet
        non_hd_key = get_generate_key()
        non_hd_add = non_hd_key.p2wpkh_addr
        self.nodes[1].importprivkey(non_hd_key.privkey)

        # This should be enough to keep the master key and the non-HD key
        self.nodes[1].backupwallet(self.nodes[1].datadir_path / "hd.bak")
        #self.nodes[1].dumpwallet(self.nodes[1].datadir_path / "hd.dump")

        # Derive some HD addresses and remember the last
        # Also send funds to each add
        self.mine_node(self.nodes[0], COINBASE_MATURITY + 1)
        hd_add = None
        NUM_HD_ADDS = 10
        for i in range(1, NUM_HD_ADDS + 1):
            hd_add = self.nodes[1].getnewaddress()
            hd_info = self.nodes[1].getaddressinfo(hd_add)
            if self.options.descriptors:
                assert_equal(hd_info["hdkeypath"], "m/84h/1h/0h/0/" + str(i))
            else:
                assert_equal(hd_info["hdkeypath"], "m/0'/0'/" + str(i) + "'")
            assert_equal(hd_info["hdmasterfingerprint"], hd_fingerprint)
            self.nodes[0].sendtoaddress(hd_add, 1)
            self.mine_node(self.nodes[0], 1)
        self.nodes[0].sendtoaddress(non_hd_add, 1)
        self.mine_node(self.nodes[0], 1)

        # create an internal key (again)
        change_addr = self.nodes[1].getrawchangeaddress()
        change_addrV = self.nodes[1].getaddressinfo(change_addr)
        if self.options.descriptors:
            assert_equal(change_addrV["hdkeypath"], "m/84h/1h/0h/1/1")
        else:
            assert_equal(change_addrV["hdkeypath"], "m/0'/1'/1'")  #second internal child key

        self.sync_all()
        assert_equal(self.nodes[1].getbalance(), NUM_HD_ADDS + 1)

        self.log.info("Restore backup ...")
        self.stop_node(1)
        # we need to delete the complete chain directory
        # otherwise node1 would auto-recover all funds in flag the keypool keys as used
        shutil.rmtree(self.nodes[1].blocks_path)
        shutil.rmtree(self.nodes[1].chain_path / "chainstate")
        shutil.rmtree(self.nodes[1].chain_path / "indexes")
        shutil.copyfile(
            self.nodes[1].datadir_path / "hd.bak",
            self.nodes[1].wallets_path / self.default_wallet_name / self.wallet_data_filename
        )
        self.start_node(1)

        # Assert that derivation is deterministic
        hd_add_2 = None
        for i in range(1, NUM_HD_ADDS + 1):
            hd_add_2 = self.nodes[1].getnewaddress()
            hd_info_2 = self.nodes[1].getaddressinfo(hd_add_2)
            if self.options.descriptors:
                assert_equal(hd_info_2["hdkeypath"], "m/84h/1h/0h/0/" + str(i))
            else:
                assert_equal(hd_info_2["hdkeypath"], "m/0'/0'/" + str(i) + "'")
            assert_equal(hd_info_2["hdmasterfingerprint"], hd_fingerprint)
        assert_equal(hd_add, hd_add_2)
        self.connect_nodes(0, 1)
        self.sync_all()

        # Needs rescan
        self.nodes[1].rescanblockchain()
        assert_equal(self.nodes[1].getbalance(), NUM_HD_ADDS + 1)

        # Try a RPC based rescan
        self.stop_node(1)
        shutil.rmtree(self.nodes[1].blocks_path)
        shutil.rmtree(self.nodes[1].chain_path / "chainstate")
        shutil.rmtree(self.nodes[1].chain_path / "indexes")
        shutil.copyfile(
            self.nodes[1].datadir_path / "hd.bak",
            self.nodes[1].wallets_path / self.default_wallet_name / self.wallet_data_filename
        )
        self.start_node(1, extra_args=self.extra_args[1])
        self.connect_nodes(0, 1)
        self.sync_all()
        # Wallet automatically scans blocks older than key on startup
        assert_equal(self.nodes[1].getbalance(), NUM_HD_ADDS + 1)
        out = self.nodes[1].rescanblockchain(0, 1)
        assert_equal(out['start_height'], 0)
        assert_equal(out['stop_height'], 1)
        out = self.nodes[1].rescanblockchain()
        assert_equal(out['start_height'], 0)
        assert_equal(out['stop_height'], self.nodes[1].getblockcount())
        assert_equal(self.nodes[1].getbalance(), NUM_HD_ADDS + 1)

        # send a tx and make sure its using the internal chain for the changeoutput
        dest_addr = self.nodes[0].getnewaddress()
        txid = self.nodes[1].sendtoaddress(dest_addr, 1)
        outs = self.nodes[1].gettransaction(txid=txid, verbose=True)['decoded']['vout']
        keypath = ""
        change_info = None
        for out in outs:
            address = out['scriptPubKey'].get('address')
            if address != dest_addr:
                change_info = self.nodes[1].getaddressinfo(address)
                keypath = change_info['hdkeypath']

        if self.options.descriptors:
            assert_equal(keypath[0:14], "m/84h/1h/0h/1/")
        else:
            assert_equal(change_info['ismine'], True)
            assert_equal(change_info["hdmasterfingerprint"], hd_fingerprint)
            assert keypath.startswith("m/0'/")

        if not self.options.descriptors:
            # An Orchard recovery root must keep its transparent seed fixed.
            protected_seed = self.nodes[1].getwalletinfo()['hdseedid']
            assert_raises_rpc_error(-4, "Cannot rotate the transparent HD seed", self.nodes[1].sethdseed)
            assert_equal(self.nodes[1].getwalletinfo()['hdseedid'], protected_seed)

            # A blank legacy wallet initialized from WIF has no Orchard root.
            # It retains the original transparent-only seed rotation contract.
            self.nodes[1].createwallet(wallet_name='legacy_seed', blank=True, descriptors=False)
            legacy_rpc = self.nodes[1].get_wallet_rpc('legacy_seed')
            legacy_rpc.sethdseed(True, self.nodes[0].dumpprivkey(self.nodes[0].getnewaddress()))
            # Generate a new HD seed on node 1 and make sure it is set
            orig_masterkeyid = legacy_rpc.getwalletinfo()['hdseedid']
            legacy_rpc.sethdseed()
            new_masterkeyid = legacy_rpc.getwalletinfo()['hdseedid']
            assert orig_masterkeyid != new_masterkeyid
            addr = legacy_rpc.getnewaddress()
            # Make sure the new address is the first from the keypool
            assert_equal(legacy_rpc.getaddressinfo(addr)['hdkeypath'], 'm/0\'/0\'/0\'')
            legacy_rpc.keypoolrefill(1)  # Fill keypool with 1 key

            # Set a new HD seed on node 1 without flushing the keypool
            new_seed = self.nodes[0].dumpprivkey(self.nodes[0].getnewaddress())
            orig_masterkeyid = new_masterkeyid
            legacy_rpc.sethdseed(False, new_seed)
            new_masterkeyid = legacy_rpc.getwalletinfo()['hdseedid']
            assert orig_masterkeyid != new_masterkeyid
            addr = legacy_rpc.getnewaddress()
            assert_equal(orig_masterkeyid, legacy_rpc.getaddressinfo(addr)['hdseedid'])
            # Make sure the new address continues previous keypool
            assert_equal(legacy_rpc.getaddressinfo(addr)['hdkeypath'], 'm/0\'/0\'/1\'')

            # Check that the next address is from the new seed
            legacy_rpc.keypoolrefill(1)
            next_addr = legacy_rpc.getnewaddress()
            assert_equal(new_masterkeyid, legacy_rpc.getaddressinfo(next_addr)['hdseedid'])
            # Make sure the new address is not from previous keypool
            assert_equal(legacy_rpc.getaddressinfo(next_addr)['hdkeypath'], 'm/0\'/0\'/0\'')
            assert next_addr != addr

            # Sethdseed parameter validity
            assert_raises_rpc_error(-1, 'sethdseed', self.nodes[0].sethdseed, False, new_seed, "available_balance", "extra")
            assert_raises_rpc_error(-5, "Invalid private key or BIP39 mnemonic", legacy_rpc.sethdseed, False, "not_wif")
            assert_raises_rpc_error(-3, "JSON value of type string is not of expected type bool", legacy_rpc.sethdseed, "Not_bool")
            assert_raises_rpc_error(-3, "JSON value of type bool is not of expected type string", legacy_rpc.sethdseed, False, True)
            assert_raises_rpc_error(-5, "Already have this key", legacy_rpc.sethdseed, False, new_seed)
            assert_raises_rpc_error(-5, "Already have this key", legacy_rpc.sethdseed, False, legacy_rpc.dumpprivkey(legacy_rpc.getnewaddress()))

            self.log.info('Test sethdseed restoring with keys outside of the initial keypool')
            self.mine_node(self.nodes[0], 10)
            # Restart node 1 with keypool of 3 and a different wallet
            self.nodes[1].createwallet(wallet_name='origin', blank=True)
            self.restart_node(1, extra_args=['-keypool=3', '-wallet=origin'])
            self.connect_nodes(0, 1)

            # sethdseed restoring and seeing txs to addresses out of the keypool
            origin_rpc = self.nodes[1].get_wallet_rpc('origin')
            seed = self.nodes[0].dumpprivkey(self.nodes[0].getnewaddress())
            origin_rpc.sethdseed(True, seed)

            self.nodes[1].createwallet(wallet_name='restore', blank=True)
            restore_rpc = self.nodes[1].get_wallet_rpc('restore')
            restore_rpc.sethdseed(True, seed)  # Set to be the same seed as origin_rpc
            restore_rpc.sethdseed(True)  # Rotate to a new seed, making original `seed` inactive

            self.nodes[1].createwallet(wallet_name='restore2', blank=True)
            restore2_rpc = self.nodes[1].get_wallet_rpc('restore2')
            restore2_rpc.sethdseed(True, seed)  # Set to be the same seed as origin_rpc
            restore2_rpc.sethdseed(True)  # Rotate to a new seed, making original `seed` inactive

            # Check persistence of inactive seed by reloading restore. restore2 is still loaded to test the case where the wallet is not reloaded
            restore_rpc.unloadwallet()
            self.nodes[1].loadwallet('restore')
            restore_rpc = self.nodes[1].get_wallet_rpc('restore')

            # Empty origin keypool and get an address that is beyond the initial keypool
            origin_rpc.getnewaddress()
            origin_rpc.getnewaddress()
            last_addr = origin_rpc.getnewaddress()  # Last address of initial keypool
            addr = origin_rpc.getnewaddress()  # First address beyond initial keypool

            # Check that the restored seed has last_addr but does not have addr
            info = restore_rpc.getaddressinfo(last_addr)
            assert_equal(info['ismine'], True)
            info = restore_rpc.getaddressinfo(addr)
            assert_equal(info['ismine'], False)
            info = restore2_rpc.getaddressinfo(last_addr)
            assert_equal(info['ismine'], True)
            info = restore2_rpc.getaddressinfo(addr)
            assert_equal(info['ismine'], False)
            # Check that the origin seed has addr
            info = origin_rpc.getaddressinfo(addr)
            assert_equal(info['ismine'], True)

            # Send a transaction to addr, which is out of the initial keypool.
            # The wallet that has set a new seed (restore_rpc) should not detect this transaction.
            txid = self.nodes[0].sendtoaddress(addr, 1)
            origin_rpc.sendrawtransaction(self.nodes[0].gettransaction(txid)['hex'])
            self.mine_node(self.nodes[0], 1)
            origin_rpc.gettransaction(txid)
            assert_raises_rpc_error(-5, 'Invalid or non-wallet transaction id', restore_rpc.gettransaction, txid)
            out_of_kp_txid = txid

            # Send a transaction to last_addr, which is in the initial keypool.
            # The wallet that has set a new seed (restore_rpc) should detect this transaction and generate 3 new keys from the initial seed.
            # The previous transaction (out_of_kp_txid) should still not be detected as a rescan is required.
            txid = self.nodes[0].sendtoaddress(last_addr, 1)
            origin_rpc.sendrawtransaction(self.nodes[0].gettransaction(txid)['hex'])
            self.mine_node(self.nodes[0], 1)
            origin_rpc.gettransaction(txid)
            restore_rpc.gettransaction(txid)
            assert_raises_rpc_error(-5, 'Invalid or non-wallet transaction id', restore_rpc.gettransaction, out_of_kp_txid)
            restore2_rpc.gettransaction(txid)
            assert_raises_rpc_error(-5, 'Invalid or non-wallet transaction id', restore2_rpc.gettransaction, out_of_kp_txid)

            # After rescanning, restore_rpc should now see out_of_kp_txid and generate an additional key.
            # addr should now be part of restore_rpc and be ismine
            restore_rpc.rescanblockchain()
            restore_rpc.gettransaction(out_of_kp_txid)
            info = restore_rpc.getaddressinfo(addr)
            assert_equal(info['ismine'], True)
            restore2_rpc.rescanblockchain()
            restore2_rpc.gettransaction(out_of_kp_txid)
            info = restore2_rpc.getaddressinfo(addr)
            assert_equal(info['ismine'], True)

            # Check again that 3 keys were derived.
            # Empty keypool and get an address that is beyond the initial keypool
            origin_rpc.getnewaddress()
            origin_rpc.getnewaddress()
            last_addr = origin_rpc.getnewaddress()
            addr = origin_rpc.getnewaddress()

            # Check that the restored seed has last_addr but does not have addr
            info = restore_rpc.getaddressinfo(last_addr)
            assert_equal(info['ismine'], True)
            info = restore_rpc.getaddressinfo(addr)
            assert_equal(info['ismine'], False)
            info = restore2_rpc.getaddressinfo(last_addr)
            assert_equal(info['ismine'], True)
            info = restore2_rpc.getaddressinfo(addr)
            assert_equal(info['ismine'], False)


if __name__ == '__main__':
    WalletHDTest().main()
