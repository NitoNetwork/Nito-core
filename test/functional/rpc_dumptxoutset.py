#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the generation of UTXO snapshots using `dumptxoutset`.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import CBlock, COutPoint, from_hex, hash256
from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    sha256sum_file,
)


class DumptxoutsetTest(NitoTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-privateactivationheight=101"]]

    def run_test(self):
        """Test a trivial usage of the dumptxoutset RPC command."""
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 121
        node.setmocktime(mocktime)
        block_hashes = self.generate(node, COINBASE_MATURITY)

        FILENAME = 'txoutset.dat'
        out = node.dumptxoutset(FILENAME)
        expected_path = node.datadir_path / self.chain / FILENAME

        assert expected_path.is_file()
        snapshot = expected_path.read_bytes()
        assert_equal(snapshot[:32][::-1].hex(), out['base_hash'])
        assert_equal(int.from_bytes(snapshot[32:40], 'little'), 100)

        assert_equal(out['coins_written'], 100)
        assert_equal(out['base_height'], 100)
        assert_equal(out['path'], str(expected_path))

        # Reconstruct the pre-activation UTXO commitment from the mined blocks
        # themselves. This is independent of the snapshot writer and confirms
        # every serialized coin represented by its metadata count.
        coins = []
        for height, block_hash in enumerate(block_hashes, start=1):
            block = from_hex(CBlock(), node.getblock(block_hash, False))
            coinbase = block.vtx[0]
            txid = int(coinbase.rehash(), 16)
            coins.append(
                COutPoint(txid, 0).serialize()
                + (height * 2 + 1).to_bytes(4, 'little')
                + coinbase.vout[0].serialize()
            )
        assert_equal(hash256(b''.join(sorted(coins)))[::-1].hex(), out['txoutset_hash'])
        # Blockhash should be deterministic based on mocked time.
        assert_equal(
            out['base_hash'],
            '2f8c8a2021c4f3b828d5630df16af356fbd8569ead23dfee980d4cd081582d0f')

        # UTXO snapshot hash should be deterministic based on mocked time.
        assert_equal(
            sha256sum_file(str(expected_path)).hex(),
            'cea6a90ab94a991dc80e9fd2085022cc67725524107eccd981ac117c4086f37c')

        assert_equal(
            out['txoutset_hash'], '38912826d19e7d7a3116cd562b721ce8d319ef96a59b3ecbde4c6bffa3802cc1')
        assert_equal(out['nchaintx'], 101)

        # A second pre-activation dump of the identical UTXO set must be byte
        # for byte identical, rather than merely reporting matching metadata.
        repeat_filename = 'txoutset-repeat.dat'
        repeat = node.dumptxoutset(repeat_filename)
        repeat_path = node.datadir_path / self.chain / repeat_filename
        assert_equal({key: value for key, value in out.items() if key != 'path'},
                     {key: value for key, value in repeat.items() if key != 'path'})
        assert_equal(sha256sum_file(str(expected_path)), sha256sum_file(str(repeat_path)))

        # Specifying a path to an existing or invalid file will fail.
        assert_raises_rpc_error(
            -8, '{} already exists'.format(FILENAME),  node.dumptxoutset, FILENAME)
        invalid_path = node.datadir_path / "invalid" / "path"
        assert_raises_rpc_error(
            -8, "Couldn't open file {}.incomplete for writing".format(invalid_path), node.dumptxoutset, invalid_path)

        # The transparent snapshot remains valid immediately before activation,
        # but V4 must refuse to write a partial snapshot once Orchard activates.
        self.generate(node, 1)
        post_activation = 'after-private-activation.dat'
        post_activation_path = node.datadir_path / self.chain / post_activation
        assert_raises_rpc_error(
            -1,
            'UTXO snapshots at or after Nito private transaction activation are disabled until the format authenticates Orchard consensus state',
            node.dumptxoutset,
            post_activation,
        )
        assert not post_activation_path.exists()
        assert not (node.datadir_path / self.chain / (post_activation + '.incomplete')).exists()


if __name__ == '__main__':
    DumptxoutsetTest().main()
