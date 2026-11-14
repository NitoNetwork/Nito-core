#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise supported wallet-format upgrades with explicit serialized fixtures.

Real V3.0.1 produces the imported-key wallet. Lower minversion/HD metadata
fixtures exercise inherited upgrade branches; they are not fabricated Nito
release binaries. The separate migration test covers ordinary public V3 wallets.
"""

import shutil
import struct

from test_framework.previous_releases import (
    add_v3_options, create_wallet_records, mine_blocks, read_wallet_records, v3_binaries,
)
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import get_generate_key


class UpgradeWalletTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)
        add_v3_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.wallet_names = [None, None]
        self.extra_args = [['-keypool=2'], ['-keypool=2']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_bdb()
        self.skip_if_no_wallet_tool()
        self.old_binary, self.old_cli = v3_binaries(self)

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args,
                       binary=[self.old_binary, self.options.nitod],
                       binary_cli=[self.old_cli, self.options.nitocli])
        self.start_node(0)
        assert_equal(self.nodes[0].getnetworkinfo()['version'], 30001)

    def check_upgrade(self, wallet, previous, requested=None, expected=None, error=None):
        if expected is None:
            expected = previous if error else (requested or 169900)
        result = wallet.upgradewallet(requested)
        assert_equal(result['previous_version'], previous)
        assert_equal(result['current_version'], expected)
        assert_equal(wallet.getwalletinfo()['walletversion'], expected)
        if error:
            assert error in result['error']
            assert 'result' not in result
        else:
            assert 'result' in result
            assert 'error' not in result

    def run_test(self):
        old, new = self.nodes
        old.createwallet(wallet_name='miner', descriptors=True, load_on_startup=False)
        miner = old.get_wallet_rpc('miner')
        mine_blocks(self, old, 101, miner.getnewaddress())
        old.createwallet(wallet_name='source', descriptors=False, blank=True, load_on_startup=False)
        source = old.get_wallet_rpc('source')
        key = get_generate_key()
        source.importprivkey(key.privkey, 'imported key', False)
        assert 'hdseedid' not in source.getwalletinfo()
        miner.sendtoaddress(key.p2pkh_addr, 2)
        mine_blocks(self, old, 1, miner.getnewaddress())
        source.unloadwallet()
        timestamp = old.getblockchaininfo()['time'] + 121
        self.stop_node(0)
        records = read_wallet_records(self, old, 'source', 'source-upgrade')
        assert b'\x07hdchain' not in records
        records[b'\x0aminversion'] = struct.pack('<i', 60000)
        for dirname in ('blocks', 'chainstate'):
            shutil.copytree(old.chain_path / dirname, new.chain_path / dirname)
        self.start_node(1, extra_args=self.extra_args[1] + [f'-mocktime={timestamp}'])

        for name, target in (('hd', 130000), ('split', 169900), ('default', None)):
            create_wallet_records(self, new, name, records)
            new.loadwallet(name)
            wallet = new.get_wallet_rpc(name)
            assert_equal(wallet.getbalance(), 2)
            self.check_upgrade(wallet, 60000, requested=129999, expected=60000)
            self.check_upgrade(wallet, 60000, requested=40000, error='Cannot downgrade wallet')
            assert 'hdseedid' not in wallet.getwalletinfo()
            self.check_upgrade(wallet, 60000, requested=target)
            seed = wallet.getwalletinfo()['hdseedid']
            assert_equal(wallet.dumpprivkey(key.p2pkh_addr), key.privkey)
            assert_equal(wallet.getbalance(), 2)
            first = wallet.getaddressinfo(wallet.getnewaddress())
            assert_equal(first['hdseedid'], seed)
            if target == 130000:
                wallet.unloadwallet()
                hd_records = read_wallet_records(self, new, name, 'hd-v1')
                assert_equal(len(hd_records[b'\x07hdchain']), 28)
                assert_equal(struct.unpack('<i', hd_records[b'\x07hdchain'][:4])[0], 1)
                new.loadwallet(name)
                for version in (139900, 159900, 169899):
                    self.check_upgrade(wallet, 130000, requested=version,
                                       error='without upgrading to support pre-split keypool')
                self.check_upgrade(wallet, 130000, requested=169900)
                assert_equal(wallet.getwalletinfo()['hdseedid'], seed)
            wallet.unloadwallet()
            upgraded = read_wallet_records(self, new, name, name + '-upgraded')
            assert_equal(len(upgraded[b'\x07hdchain']), 32)
            assert_equal(struct.unpack('<i', upgraded[b'\x07hdchain'][:4])[0], 2)
            new.loadwallet(name)
            self.check_upgrade(wallet, 169900, expected=169900)
            assert_equal(wallet.getbalance(), 2)

        # Retiring the default-key feature must preserve the key record itself.
        split = new.get_wallet_rpc('split')
        split.unloadwallet()
        split_records = read_wallet_records(self, new, 'split', 'split-default-key')
        split_records[b'\x0aminversion'] = struct.pack('<i', 139900)
        defaultkey = bytes([len(bytes.fromhex(key.pubkey))]) + bytes.fromhex(key.pubkey)
        split_records[b'\x0adefaultkey'] = defaultkey
        create_wallet_records(self, new, 'default_key', split_records)
        new.loadwallet('default_key')
        wallet = new.get_wallet_rpc('default_key')
        self.check_upgrade(wallet, 139900, requested=159900)
        wallet.unloadwallet()
        after = read_wallet_records(self, new, 'default_key', 'default-key-after')
        assert_equal(after[b'\x0adefaultkey'], defaultkey)

        if self.is_sqlite_compiled():
            for disabled in (False, True):
                name = 'descriptors_watch' if disabled else 'descriptors'
                new.createwallet(wallet_name=name, descriptors=True, disable_private_keys=disabled)
                self.check_upgrade(new.get_wallet_rpc(name), 169900, expected=169900)


if __name__ == '__main__':
    UpgradeWalletTest().main()