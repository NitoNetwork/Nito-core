#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject unreadable recovery metadata instead of treating it as absent."""

from contextlib import closing
import struct
try:
    import sqlite3
except ImportError:
    pass

from test_framework.messages import ser_string, ser_uint256
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_raises_rpc_error


class WalletRecoveryCorruptionTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)
        parser.add_argument('--record', choices=['privatechain', 'privatenote', 'seedhistorystate'])
        parser.add_argument('--corruption', choices=['truncated', 'future-version', 'derivation', 'seed-scope'])

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        self.skip_if_no_py_sqlite3()

    def run_test(self):
        node = self.nodes[0]
        records = [self.options.record.encode('ascii')] if self.options.record else [b'privatechain', b'privatenote', b'seedhistorystate']
        for record in records:
            cases = ['truncated', 'future-version', 'derivation', 'seed-scope'] if record == b'privatechain' else ['truncated']
            if record == b'privatenote':
                cases = ['truncated', 'future-version', 'derivation']
            for corruption in cases:
                if self.options.corruption and self.options.corruption != corruption:
                    continue
                name = record.decode('ascii') + '-' + corruption
                node.createwallet(name, descriptors=True)
                node.unloadwallet(name)
                path = node.wallets_path / name / self.wallet_data_filename
                with closing(sqlite3.connect(path)) as connection:
                    with connection:
                        key = ser_string(record)
                        if record == b'privatenote':
                            key += ser_uint256(1)
                        if corruption == 'truncated':
                            value = b'\x02'
                        elif record == b'privatenote':
                            # An unconfirmed, undecrypted note with no spend authority.
                            version = 3 if corruption == 'future-version' else 2
                            derivation = 0 if corruption == 'derivation' else 1
                            value = (struct.pack('<i', version) + ser_uint256(1) + bytes(96)
                                     + struct.pack('<qiII?IQI??', 0, -1, derivation, 0, False, 0,
                                                   (1 << 64) - 1, 0, False, False) + bytes(6))
                        else:
                            value = connection.execute('SELECT value FROM main WHERE key = ?', (key,)).fetchone()[0]
                            assert struct.unpack('<i', value[:4])[0] == 7
                            if corruption == 'future-version':
                                value = struct.pack('<i', 8) + value[4:]
                            elif corruption == 'derivation':
                                value = value[:16] + struct.pack('<I', 0) + value[20:]
                            else:
                                value = value[:40] + b'\xff' + value[41:]
                        connection.execute('INSERT OR REPLACE INTO main VALUES (?, ?)', (key, value))
                self.log.info('Reject %s %s record', corruption, record.decode('ascii'))
                assert_raises_rpc_error(-4, 'corrupt', node.loadwallet, name)
                assert name not in node.listwallets()
                with closing(sqlite3.connect(path)) as connection:
                    assert connection.execute('SELECT value FROM main WHERE key = ?', (key,)).fetchone()[0] == value


if __name__ == '__main__':
    WalletRecoveryCorruptionTest().main()
