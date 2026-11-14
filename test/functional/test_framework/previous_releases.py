# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Official V3 binary selection and isolated serialized-wallet fixtures."""

import os
from pathlib import Path
import subprocess
import time

from .messages import hash256
from .test_framework import SkipTest


def add_v3_options(parser):
    parser.add_argument('--v3-bindir', default=os.getenv('NITO_V3_BINDIR'),
                        help='Directory containing official Nito V3.0.1 binaries')


def v3_binaries(test):
    directory = Path(test.options.v3_bindir) if test.options.v3_bindir else (
        Path(test.options.previous_releases_path) / 'v3.0.1' / 'bin')
    suffix = test.config['environment']['EXEEXT']
    binaries = [directory / (name + suffix) for name in ('nitod', 'nito-cli')]
    if not all(binary.is_file() for binary in binaries):
        if test.options.v3_bindir:
            raise FileNotFoundError(f'Missing V3.0.1 binaries in {directory}')
        raise SkipTest('Run test/get_previous_releases.py or specify --v3-bindir')
    return [str(binary) for binary in binaries]


def mine_blocks(test, node, count, address):
    """Advance each block's time to keep the Nito regtest difficulty bounded."""
    target = node.getblockcount() + count
    deadline = time.monotonic() + 300 * test.options.timeout_factor
    while node.getblockcount() < target:
        assert time.monotonic() < deadline, 'Regtest mining timed out'
        node.setmocktime(max(int(time.time()), node.getblockchaininfo()['time'] + 121))
        test.generatetoaddress(node, 1, address, maxtries=10_000_000, sync_fun=test.no_op)


def wallet_tool(test, node, name, dump, command):
    result = subprocess.run([
        test.options.nitowallet, f'-datadir={node.datadir_path}', f'-chain={test.chain}',
        f'-wallet={name}', f'-dumpfile={dump}', command,
    ], capture_output=True, text=True, timeout=60 * test.options.timeout_factor)
    assert result.returncode == 0, result.stderr


def read_wallet_records(test, node, name, label):
    """Read an unloaded fixture wallet through the supported wallet dump tool."""
    dump = Path(test.options.tmpdir) / (label + '.dump')
    wallet_tool(test, node, name, dump, 'dump')
    rows = [line.split(',') for line in dump.read_text(encoding='utf-8').splitlines()]
    assert rows[0] == ['BITCOIN_CORE_WALLET_DUMP', '1']
    assert rows[1] == ['format', 'bdb']
    return {bytes.fromhex(key): bytes.fromhex(value) for key, value in rows[2:-1]}


def create_wallet_records(test, node, name, records):
    """Create a new fixture; never edit a wallet that a node has loaded."""
    body = 'BITCOIN_CORE_WALLET_DUMP,1\nformat,bdb\n'
    body += ''.join(f'{key.hex()},{value.hex()}\n' for key, value in sorted(records.items()))
    dump = Path(test.options.tmpdir) / (name + '-fixture.dump')
    with dump.open('w', encoding='utf-8', newline='\n') as output:
        output.write(body + 'checksum,' + hash256(body.encode()).hex() + '\n')
    wallet_tool(test, node, name, dump, 'createfromdump')
