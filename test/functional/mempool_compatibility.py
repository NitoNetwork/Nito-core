#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Round-trip transparent mempool files between official Nito V3.0.1 and V4."""

import os
from pathlib import Path
import shutil
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import NitoTestFramework, SkipTest
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode


class MempoolCompatibilityTest(NitoTestFramework):
    def add_options(self, parser):
        parser.add_argument('--v3-bindir', default=os.getenv('NITO_V3_BINDIR'),
                            help='Directory containing official Nito V3.0.1 binaries')

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.wallet_names = [None, None]

    def skip_test_if_missing_module(self):
        if not self.options.v3_bindir:
            raise SkipTest('Specify --v3-bindir or NITO_V3_BINDIR for official V3.0.1 binaries')

    def setup_network(self):
        suffix = self.config['environment']['EXEEXT']
        old = Path(self.options.v3_bindir)
        self.add_nodes(self.num_nodes,
                       binary=[str(old / ('nitod' + suffix)), self.options.nitod],
                       binary_cli=[str(old / ('nito-cli' + suffix)), self.options.nitocli])
        self.start_node(0)
        assert_equal(self.nodes[0].getnetworkinfo()['version'], 30001)

    def run_test(self):
        old, new = self.nodes
        wallet = MiniWallet(old, mode=MiniWalletMode.RAW_P2PK)
        deadline = time.monotonic() + 300 * self.options.timeout_factor
        while old.getblockcount() < COINBASE_MATURITY + 1:
            assert time.monotonic() < deadline, 'Regtest mining timed out'
            old.setmocktime(max(int(time.time()), old.getblockchaininfo()['time'] + 121))
            self.generatetodescriptor(old, 1, wallet.get_descriptor(), maxtries=10_000_000,
                                      sync_fun=self.no_op)
        wallet.rescan_utxos()
        tip = old.getbestblockhash()
        timestamp = old.getblockchaininfo()['time'] + 121
        txid = wallet.send_self_transfer(from_node=old)['txid']
        assert old.getmempoolentry(txid)['unbroadcast']
        expected = {txid}
        self.stop_node(0)
        # Offline copying preserves V4's intentional rejection of V3 peers.
        for dirname in ('blocks', 'chainstate'):
            shutil.copytree(old.chain_path / dirname, new.chain_path / dirname)
        old_file = old.chain_path / 'mempool.dat'
        new_file = new.chain_path / 'mempool.dat'

        for persist_v1 in (False, True):
            self.log.info('Round-trip transparent mempool with persistmempoolv1=%s', persist_v1)
            shutil.copyfile(old_file, new_file)
            self.start_node(1, extra_args=[f'-mocktime={timestamp}', f'-persistmempoolv1={int(persist_v1)}'])
            assert_equal(new.getbestblockhash(), tip)
            assert_equal(set(new.getrawmempool()), expected)
            for item in expected:
                assert new.getmempoolentry(item)['unbroadcast']
            current_wallet = MiniWallet(new, mode=MiniWalletMode.RAW_P2PK)
            child = current_wallet.send_self_transfer(from_node=new)['txid']
            assert new.getmempoolentry(child)['unbroadcast']
            expected.add(child)
            self.stop_node(1)
            shutil.copyfile(new_file, old_file)
            self.start_node(0, extra_args=[f'-mocktime={timestamp}'])
            assert_equal(set(old.getrawmempool()), expected)
            for item in expected:
                assert old.getmempoolentry(item)['unbroadcast']
            self.stop_node(0)


if __name__ == '__main__':
    MempoolCompatibilityTest().main()
