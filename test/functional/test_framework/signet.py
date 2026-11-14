#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Nito Signet fixture access and deterministic test-only proof-of-work reuse."""

import hashlib
import json
from pathlib import Path
import sys


def read_signet_fixture():
    return json.loads((Path(__file__).resolve().parents[1] / 'data/signet_block.json').read_text(encoding='utf-8'))


if __name__ == '__main__':
    # The miner must rebuild and sign the exact block before reusing its nonce.
    # This avoids an unbounded difficulty-one search on every functional run.
    fixture = read_signet_fixture()
    header = bytes.fromhex(sys.argv[1])
    expected = bytes.fromhex(fixture['block'])[:80]
    if len(header) != 80 or header[:76] != expected[:76]:
        sys.exit('Signet miner produced a different header from the signed fixture')
    digest = hashlib.sha256(hashlib.sha256(expected).digest()).digest()
    bits = int.from_bytes(expected[72:76], 'little')
    target = (bits & 0x007fffff) << (8 * ((bits >> 24) - 3))
    assert int.from_bytes(digest, 'little') <= target
    assert digest[::-1].hex() == fixture['hash']
    print(expected.hex())
