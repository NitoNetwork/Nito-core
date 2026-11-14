#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Restore official V3.0.1 wallets in V4 and spend before and after Orchard upgrade."""

import os
from pathlib import Path
import shutil
import time

from test_framework.test_framework import NitoTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletV3MigrationTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument('--v3-bindir', default=os.getenv('NITO_V3_BINDIR'),
                            help='Directory containing official Nito V3.0.1 binaries')

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.wallet_names = [None, None]
        self.extra_args = [['-keypool=20'], ['-keypool=20', '-orchardindex=1', '-transparenthistoryindex=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not self.options.v3_bindir:
            raise SkipTest('Specify --v3-bindir or NITO_V3_BINDIR for official V3.0.1 binaries')

    def setup_network(self):
        suffix = self.config['environment']['EXEEXT']
        old = Path(self.options.v3_bindir)
        self.add_nodes(self.num_nodes, extra_args=self.extra_args,
                       binary=[str(old / ('nitod' + suffix)), self.options.nitod],
                       binary_cli=[str(old / ('nito-cli' + suffix)), self.options.nitocli])
        self.start_node(0)
        assert_equal(self.nodes[0].getnetworkinfo()['version'], 30001)

    @staticmethod
    def snapshot(wallet):
        info = wallet.getwalletinfo()
        return {
            'balance': wallet.getbalance(),
            'txcount': info['txcount'],
            'format': info['format'],
            'descriptors': info['descriptors'],
            'utxos': sorted(wallet.listunspent(), key=lambda coin: (coin['txid'], coin['vout'])),
            'locks': sorted(wallet.listlockunspent(), key=lambda coin: (coin['txid'], coin['vout'])),
            'labels': {label: wallet.getaddressesbylabel(label) for label in wallet.listlabels()},
            'history': wallet.listtransactions('*', 1000, 0, True),
        }

    def mine(self, node, count, address):
        target = node.getblockcount() + count
        deadline = time.monotonic() + 300 * self.options.timeout_factor
        while node.getblockcount() < target:
            assert time.monotonic() < deadline, 'Regtest mining timed out'
            node.setmocktime(max(int(time.time()), node.getblockchaininfo()['time'] + 121))
            self.generatetoaddress(node, 1, address, maxtries=10_000_000, sync_fun=self.no_op)

    def run_test(self):
        old, new = self.nodes
        old.createwallet(wallet_name='miner', descriptors=True, load_on_startup=False)
        miner = old.get_wallet_rpc('miner')
        mining_address = miner.getnewaddress()
        self.mine(old, 101, mining_address)
        cases = []
        for encrypted in (False, True):
            name = 'encrypted' if encrypted else 'plain'
            password = 'migration test passphrase' if encrypted else ''
            old.createwallet(wallet_name=name, descriptors=self.options.descriptors,
                             passphrase=password, load_on_startup=False)
            wallet = old.get_wallet_rpc(name)
            if encrypted:
                wallet.walletpassphrase(password, 600)
            address = wallet.getnewaddress('recipient', 'bech32')
            miner.sendtoaddress(address, 10, 'migration payment', 'recipient')
            cases.append({'name': name, 'password': password, 'address': address})
        self.mine(old, 2, mining_address)
        backup_dir = Path(self.options.tmpdir) / 'backups'
        backup_dir.mkdir()
        for case in cases:
            wallet = old.get_wallet_rpc(case['name'])
            coin = wallet.listunspent()[0]
            wallet.lockunspent(False, [{'txid': coin['txid'], 'vout': coin['vout']}], True)
            case['snapshot'] = self.snapshot(wallet)
            case['backup'] = backup_dir / (case['name'] + '.dat')
            wallet.backupwallet(str(case['backup']))
            case['next_receive'] = wallet.getnewaddress()
            case['next_change'] = wallet.getrawchangeaddress()
        tip = old.getbestblockhash()
        new.extra_args.append('-mocktime=' + str(old.getblockchaininfo()['time'] + 121))
        self.stop_node(0)
        for dirname in ('blocks', 'chainstate'):
            shutil.copytree(old.chain_path / dirname, new.chain_path / dirname)
        self.start_node(1)
        assert_equal(new.getbestblockhash(), tip)
        for case in cases:
            name, password = case['name'], case['password']
            self.log.info('Restore V3 %s wallet with descriptors=%s', name, self.options.descriptors)
            new.restorewallet(name, str(case['backup']), False)
            wallet = new.get_wallet_rpc(name)
            if password:
                wallet.walletpassphrase(password, 600)
            assert_equal(self.snapshot(wallet), case['snapshot'])
            assert_equal(wallet.getnewaddress(), case['next_receive'])
            assert_equal(wallet.getrawchangeaddress(), case['next_change'])
            assert_raises_rpc_error(-4, 'Orchard', wallet.dumpmnemonic)
            restored_backup = backup_dir / (name + '-v4.dat')
            wallet.backupwallet(str(restored_backup))
            wallet.unloadwallet()
        for case in cases:
            name, password = case['name'], case['password']
            restored_backup = backup_dir / (name + '-v4.dat')
            self.restart_node(1)
            restored_name = name + '-restored'
            new.restorewallet(restored_name, str(restored_backup), False)
            wallet = new.get_wallet_rpc(restored_name)
            if password:
                wallet.walletpassphrase(password, 600)
            assert_equal(wallet.getbalance(), case['snapshot']['balance'])
            assert_equal(wallet.listlockunspent(), case['snapshot']['locks'])
            wallet.lockunspent(True)
            receive = wallet.getnewaddress()
            txid = wallet.sendtoaddress(receive, 1)
            self.mine(new, 1, mining_address)
            assert wallet.gettransaction(txid)['confirmations'] >= 1
            self.log.info('Reject Orchard upgrade when the required backup cannot be created')
            timestamp = new.getblockchaininfo()['time'] + 121
            new.setmocktime(timestamp)
            wallet_root = new.wallets_path if new.wallets_path.is_dir() else new.chain_path
            wallet_dir = wallet_root / restored_name
            reserved_backups = [wallet_dir / f'wallet-pre-orchard-{timestamp}.bak']
            reserved_backups += [wallet_dir / f'wallet-pre-orchard-{timestamp}-{suffix}.bak'
                                 for suffix in range(1, 1000)]
            created_backups = []
            before_upgrade = self.snapshot(wallet)
            try:
                for path in reserved_backups:
                    with path.open('x') as output:
                        output.write('Reserved by wallet_v3_migration.py\n')
                    created_backups.append(path)
                assert_raises_rpc_error(-4, 'required pre-upgrade wallet.dat backup', wallet.upgradeorchardwallet)
                assert_equal(self.snapshot(wallet), before_upgrade)
                assert_raises_rpc_error(-4, 'Orchard', wallet.dumpmnemonic)
            finally:
                for path in created_backups:
                    path.unlink(missing_ok=True)

            upgrade = wallet.upgradeorchardwallet()
            assert Path(upgrade['backup']).is_file()
            mnemonic = wallet.dumpmnemonic()
            assert_equal(wallet.dumpmnemonic()['scope'], 'orchard_only')
            assert_raises_rpc_error(-4, 'already has a canonical Orchard recovery root', wallet.upgradeorchardwallet)
            assert_equal(wallet.dumpmnemonic(), mnemonic)
            assert wallet.getaddressinfo(case['address'])['ismine']
            assert wallet.getnewaddress().startswith('nrt1q')
            private = wallet.getnewaddress('', 'bech32x')
            txid = wallet.sendtoaddress(private, 1)
            self.mine(new, 1, mining_address)
            assert wallet.gettransaction(txid)['confirmations'] >= 1
            self.log.info('Restore the upgraded wallet backup before spending Orchard funds')
            funded_snapshot = self.snapshot(wallet)
            assert_equal(wallet.getprivatebalance()['total_unspent'], 1)
            orchard_backup = backup_dir / (name + '-orchard.dat')
            wallet.backupwallet(str(orchard_backup))
            wallet.unloadwallet()
            spending_name = name + '-orchard-restored'
            new.restorewallet(spending_name, str(orchard_backup), False)
            wallet = new.get_wallet_rpc(spending_name)
            if password:
                wallet.walletpassphrase(password, 600)
            assert_equal(self.snapshot(wallet), funded_snapshot)
            assert_equal(wallet.dumpmnemonic(), mnemonic)
            assert_equal(wallet.getprivatebalance()['total_unspent'], 1)
            txid = wallet.sendprivate(receive, 0.1)
            if isinstance(txid, dict):
                txid = txid['txid']
            self.mine(new, 1, mining_address)
            assert wallet.gettransaction(txid)['confirmations'] >= 1
            wallet.unloadwallet()


if __name__ == '__main__':
    WalletV3MigrationTest().main()
