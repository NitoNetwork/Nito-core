#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Preserve public V3 transparent wallets and metadata when loading them in V4.

This complements wallet_v3_migration.py with watch-only, imported keys,
multisig, blank wallets, and fee replacement metadata. Old Bitcoin version
numbers are not used as Nito release identifiers.
"""

from pathlib import Path
import shutil

from test_framework.descriptors import descsum_create
from test_framework.previous_releases import add_v3_options, mine_blocks, v3_binaries
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import get_generate_key


class BackwardsCompatibilityTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)
        add_v3_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.wallet_names = [None, None]
        self.extra_args = [['-keypool=10'], ['-keypool=10']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
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
        names = ('regular', 'watch', 'imported', 'blank')
        for name in names:
            old.createwallet(wallet_name=name, descriptors=self.options.descriptors,
                             disable_private_keys=name == 'watch', blank=name != 'regular',
                             load_on_startup=False)
        regular = old.get_wallet_rpc('regular')
        address = regular.getnewaddress('original label')
        miner.sendtoaddress(address, 10, 'funding comment')
        mine_blocks(self, old, 1, mining_address)
        original = regular.sendtoaddress(mining_address, 1, 'replacement comment', '', False, True)
        replacement = regular.bumpfee(original)['txid']
        mine_blocks(self, old, 1, mining_address)

        imported = old.get_wallet_rpc('imported')
        watch = old.get_wallet_rpc('watch')
        key = get_generate_key()
        if self.options.descriptors:
            imported.importdescriptors([{'desc': descsum_create(f'wpkh({key.privkey})'), 'timestamp': 'now', 'label': 'imported key'}])
            watch.importdescriptors([{'desc': descsum_create(f'wpkh({key.pubkey})'), 'timestamp': 'now', 'label': 'watch key'}])
            imported_address = old.deriveaddresses(descsum_create(f'wpkh({key.pubkey})'))[0]
        else:
            imported.importprivkey(key.privkey, 'imported key', False)
            imported_address = key.p2pkh_addr
            watch.importaddress(imported_address, 'watch key', False)
        addresses = {'regular': [address], 'imported': [imported_address], 'watch': [imported_address], 'blank': []}
        multisig = None
        if not self.options.descriptors:
            pubkey = regular.getaddressinfo(address)['pubkey']
            multisig = regular.addmultisigaddress(1, [pubkey, key.pubkey], 'multisig', 'legacy')['address']
            assert regular.getaddressinfo(multisig)['solvable']
            addresses['regular'].append(multisig)
        miner.sendtoaddress(imported_address, 2)
        mine_blocks(self, old, 1, mining_address)

        def snapshot(wallet, known):
            info = wallet.getwalletinfo()
            result = {field: info[field] for field in (
                'format', 'descriptors', 'private_keys_enabled', 'keypoolsize', 'txcount')}
            result['balance'] = wallet.getbalance()
            result['labels'] = {label: wallet.getaddressesbylabel(label) for label in wallet.listlabels()}
            result['addresses'] = {addr: {field: wallet.getaddressinfo(addr).get(field)
                                         for field in ('ismine', 'iswatchonly', 'solvable', 'pubkey', 'hdkeypath')}
                                   for addr in known}
            return result

        snapshots = {}
        backup_dir = Path(self.options.tmpdir) / 'backups'
        backup_dir.mkdir()
        for name in names:
            wallet = old.get_wallet_rpc(name)
            snapshots[name] = snapshot(wallet, addresses[name])
            wallet.backupwallet(str(backup_dir / (name + '.dat')))
        # The backup precedes these calls so V4 must produce these exact next
        # addresses even after adding an unrelated Orchard recovery root.
        next_receive = regular.getnewaddress()
        next_change = regular.getrawchangeaddress()
        timestamp = old.getblockchaininfo()['time'] + 121
        self.stop_node(0)
        for dirname in ('blocks', 'chainstate'):
            shutil.copytree(old.chain_path / dirname, new.chain_path / dirname)
        self.start_node(1, extra_args=self.extra_args[1] + [f'-mocktime={timestamp}'])
        for name in names:
            new.restorewallet(name, str(backup_dir / (name + '.dat')))
            wallet = new.get_wallet_rpc(name)
            assert_equal(snapshot(wallet, addresses[name]), snapshots[name])
            assert_raises_rpc_error(-4, 'private keys' if name == 'watch' else 'Orchard', wallet.dumpmnemonic)
            if name == 'regular':
                first = wallet.gettransaction(original)
                second = wallet.gettransaction(replacement)
                assert_equal(first['replaced_by_txid'], replacement)
                assert_equal(first['confirmations'], -second['confirmations'])
                assert_equal(second['walletconflicts'], [original])
                assert second['confirmations'] > 0
                if multisig:
                    assert wallet.getaddressinfo(multisig)['solvable']
            if name == 'imported':
                if self.options.descriptors:
                    descriptors = wallet.listdescriptors(True)['descriptors']
                    assert any(key.privkey in desc['desc'] for desc in descriptors)
                else:
                    assert_equal(wallet.dumpprivkey(imported_address), key.privkey)
            wallet.unloadwallet()
            new.loadwallet(name)
            assert_equal(snapshot(new.get_wallet_rpc(name), addresses[name]), snapshots[name])

        self.log.info("A passphrase-protected Orchard upgrade preserves the V3 transparent wallet")
        regular = new.get_wallet_rpc('regular')
        before_upgrade = snapshot(regular, addresses['regular'])
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        upgrade = regular.upgradeorchardwallet(phrase, "V3 Orchard passphrase")
        assert_equal(upgrade['scope'], 'orchard_only')
        assert_equal(upgrade['bip39_passphrase_required'], True)
        assert Path(upgrade['backup']).is_file()
        assert_equal(snapshot(regular, addresses['regular']), before_upgrade)
        assert_equal(regular.getnewaddress(), next_receive)
        assert_equal(regular.getrawchangeaddress(), next_change)
        orchard_address = regular.getnewaddress('', 'bech32x')
        regular.unloadwallet()
        new.loadwallet('regular')
        regular = new.get_wallet_rpc('regular')
        assert_equal(regular.dumpmnemonic()['scope'], 'orchard_only')
        assert_equal(regular.dumpmnemonic()['bip39_passphrase_required'], True)
        assert_equal(regular.getaddressinfo(orchard_address)['ismine'], True)
        assert_equal(regular.getaddressinfo(address)['ismine'], True)

        # The automatic backup remains a genuine V3 transparent wallet.
        new.restorewallet('pre_upgrade', upgrade['backup'])
        pre_upgrade = new.get_wallet_rpc('pre_upgrade')
        assert_equal(snapshot(pre_upgrade, addresses['regular']), before_upgrade)
        assert_raises_rpc_error(-4, 'Orchard', pre_upgrade.dumpmnemonic)


if __name__ == '__main__':
    BackwardsCompatibilityTest().main()
