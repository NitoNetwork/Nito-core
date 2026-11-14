#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject obsolete per-transaction UTXO records and recover by reindexing.

The fixture inserts the obsolete 'c' key into an isolated stopped chainstate.
It exercises the inherited format guard without claiming that Bitcoin v0.14.3
was a Nito release or that V3.0.1 uses that obsolete database format.
"""

import struct

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def insert_obsolete_record(chainstate):
    # LevelDB log records: checksum, length, type, then a WriteBatch. A high
    # sequence number makes this fixture record newer than existing writes.
    key = b'c' + bytes(32)
    batch = struct.pack('<QI', 1 << 55, 1) + b'\x01' + bytes([len(key)]) + key + b'\x01\x00'
    checksum = crc32c(b'\x01' + batch)
    masked = (((checksum >> 15) | (checksum << 17)) + 0xa282ead8) & 0xffffffff
    record = struct.pack('<IHB', masked, len(batch), 1) + batch
    logs = list(chainstate.glob('[0-9]*.log'))
    assert logs, 'Stopped chainstate has no LevelDB write-ahead log'
    log = max(logs, key=lambda path: int(path.stem))
    with log.open('ab') as stream:
        remaining = 32768 - stream.tell() % 32768
        assert remaining >= len(record), 'Fixture record would cross a LevelDB log block'
        stream.write(record)


class UnsupportedUtxoDbTest(NitoTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.wallet_names = [None]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(crc32c(b'123456789'), 0xe3069283)
        block = self.generate(node, 1)[-1]
        expected = node.gettxoutsetinfo()
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), block)
        self.stop_node(0)
        insert_obsolete_record(node.chain_path / 'chainstate')
        node.assert_start_raises_init_error(expected_msg=(
            'Error: Unsupported chainstate database format found. '
            'Please restart with -reindex-chainstate. '
            'This will rebuild the chainstate database.'))
        self.start_node(0, extra_args=['-reindex-chainstate'])
        node.wait_until(lambda: node.getbestblockhash() == block)
        recovered = node.gettxoutsetinfo()
        for key in ('bestblock', 'txouts', 'total_amount', 'hash_serialized_3'):
            assert_equal(recovered[key], expected[key])


if __name__ == '__main__':
    UnsupportedUtxoDbTest().main()
