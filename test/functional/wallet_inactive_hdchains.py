#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Bitcoin Core developers
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Recover inactive V3 HD chains, including encrypted old-key-metadata fixtures."""

from io import BytesIO
from pathlib import Path
import shutil
import struct

from test_framework.messages import deser_string
from test_framework.previous_releases import (
    add_v3_options, create_wallet_records, mine_blocks, read_wallet_records, v3_binaries,
)
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import get_generate_key


class InactiveHDChainsTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)
        add_v3_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.wallet_names = [None, None]
        self.extra_args = [['-keypool=10'], ['-keypool=10']]

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

    def run_test(self):
        old, new = self.nodes
        old.createwallet(wallet_name='miner', descriptors=True, load_on_startup=False)
        miner = old.get_wallet_rpc('miner')
        mining_address = miner.getnewaddress()
        mine_blocks(self, old, 101, mining_address)
        backups = Path(self.options.tmpdir) / 'backups'
        backups.mkdir()
        cases = [('plain', False, False), ('encrypted', True, False), ('old_keymeta', True, True)]
        for name, encrypted, _ in cases:
            seed = get_generate_key()
            for suffix in ('base', 'test'):
                wallet_name = f'{name}_{suffix}'
                old.createwallet(wallet_name=wallet_name, descriptors=False, blank=True, load_on_startup=False)
                wallet = old.get_wallet_rpc(wallet_name)
                wallet.sethdseed(True, seed.privkey)
                if suffix == 'test':
                    if encrypted:
                        wallet.encryptwallet('inactive chain test')
                        wallet.walletpassphrase('inactive chain test', 600)
                    wallet.sethdseed()
                    if encrypted:
                        wallet.walletlock()
                wallet.backupwallet(str(backups / (wallet_name + '.dat')))
                wallet.unloadwallet()
        miner.backupwallet(str(backups / 'miner.dat'))
        timestamp = old.getblockchaininfo()['time'] + 121
        self.stop_node(0)
        for dirname in ('blocks', 'chainstate'):
            shutil.copytree(old.chain_path / dirname, new.chain_path / dirname)
        self.start_node(1, extra_args=self.extra_args[1] + [f'-mocktime={timestamp}'])
        new.restorewallet('miner', str(backups / 'miner.dat'))
        miner = new.get_wallet_rpc('miner')

        for name, encrypted, old_keymeta in cases:
            self.log.info('Inactive HD chain: %s', name)
            for suffix in ('base', 'test'):
                wallet_name = f'{name}_{suffix}'
                if old_keymeta and suffix == 'test':
                    # Serialized CKeyMetadata v10 predates key-origin fields. Keep
                    # the actual V3 encrypted keys/HD paths and remove only the
                    # origin extension to cover the inherited missing-origin path.
                    records = read_wallet_records(self, old, wallet_name, wallet_name)
                    count = 0
                    for key, value in list(records.items()):
                        if key.startswith(b'\x07keymeta'):
                            stream = BytesIO(value)
                            version = struct.unpack('<i', stream.read(4))[0]
                            assert_equal(version, 12)
                            stream.read(8)
                            deser_string(stream)
                            stream.read(20)
                            records[key] = struct.pack('<i', 10) + value[4:stream.tell()]
                            count += 1
                    assert count > 0
                    create_wallet_records(self, new, wallet_name, records)
                    new.loadwallet(wallet_name)
                else:
                    new.restorewallet(wallet_name, str(backups / (wallet_name + '.dat')))
            base = new.get_wallet_rpc(f'{name}_base')
            test = new.get_wallet_rpc(f'{name}_test')
            first = base.getnewaddress()
            assert test.getaddressinfo(first)['ismine']
            for _ in range(9):
                base.getnewaddress()
            distant = base.getnewaddress()
            assert not test.getaddressinfo(distant)['ismine']
            txid = miner.sendtoaddress(first, 10)
            mine_blocks(self, new, 1, mining_address)
            test.gettransaction(txid)
            if encrypted:
                assert not test.getaddressinfo(distant)['ismine']
                test.walletpassphrase('inactive chain test', 600)
            assert test.getaddressinfo(distant)['ismine']
            txid = miner.sendtoaddress(distant, 10)
            mine_blocks(self, new, 1, mining_address)
            assert test.gettransaction(txid)['confirmations'] > 0
            assert_equal(test.getbalance(), 20)
            if encrypted:
                test.walletlock()
            test.unloadwallet()
            new.loadwallet(f'{name}_test')
            assert new.get_wallet_rpc(f'{name}_test').getaddressinfo(distant)['ismine']


if __name__ == '__main__':
    InactiveHDChainsTest().main()