#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test UTXO set hash value calculation in gettxoutsetinfo."""

from test_framework.messages import (
    CBlock,
    COutPoint,
    from_hex,
    hash256,
)
from test_framework.crypto.muhash import MuHash3072
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

class UTXOSetHashTest(NitoTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def test_muhash_implementation(self):
        self.log.info("Test MuHash implementation consistency")

        node = self.nodes[0]
        wallet = MiniWallet(node)
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 121
        node.setmocktime(mocktime)

        # Generate 100 blocks and remove the first since we plan to spend its
        # coinbase
        block_hashes = self.generate(wallet, 1) + self.generate(node, 99)
        blocks = list(map(lambda block: from_hex(CBlock(), node.getblock(block, False)), block_hashes))
        blocks.pop(0)

        # Create a spending transaction and mine a block which includes it
        txid = wallet.send_self_transfer(from_node=node)['txid']
        tx_block = self.generateblock(node, output=wallet.get_address(), transactions=[txid])
        blocks.append(from_hex(CBlock(), node.getblock(tx_block['hash'], False)))

        # Serialize the outputs that should be in the UTXO set and add them to
        # a MuHash object
        muhash = MuHash3072()

        for height, block in enumerate(blocks):
            # The Genesis block coinbase is not part of the UTXO set and we
            # spent the first mined block
            height += 2

            for tx in block.vtx:
                for n, tx_out in enumerate(tx.vout):
                    coinbase = 1 if not tx.vin[0].prevout.hash else 0

                    # Skip witness commitment
                    if (coinbase and n > 0):
                        continue

                    data = COutPoint(int(tx.rehash(), 16), n).serialize()
                    data += (height * 2 + coinbase).to_bytes(4, "little")
                    data += tx_out.serialize()

                    muhash.insert(data)

        finalized = muhash.digest()
        node_muhash = node.gettxoutsetinfo("muhash")['muhash']

        assert_equal(finalized[::-1].hex(), node_muhash)

        # Independently reproduce hash_serialized_3 from the final UTXO set.
        # The database cursor orders outpoints by their serialized form.
        unspent = {}
        for height, block in enumerate(blocks, start=2):
            for tx in block.vtx:
                coinbase = not tx.vin[0].prevout.hash
                if not coinbase:
                    for txin in tx.vin:
                        unspent.pop((txin.prevout.hash, txin.prevout.n), None)
                txid = int(tx.rehash(), 16)
                for n, tx_out in enumerate(tx.vout):
                    if coinbase and n > 0:
                        continue
                    outpoint = COutPoint(txid, n)
                    unspent[(txid, n)] = (
                        outpoint.serialize()
                        + (height * 2 + coinbase).to_bytes(4, "little")
                        + tx_out.serialize()
                    )
        serialized = b"".join(unspent[key] for key in sorted(
            unspent, key=lambda key: COutPoint(*key).serialize()))
        assert_equal(hash256(serialized)[::-1].hex(), node.gettxoutsetinfo()['hash_serialized_3'])

        self.log.info("Test deterministic UTXO set hash results")
        assert_equal(node.gettxoutsetinfo()['hash_serialized_3'], "808a8513a57561355263eed5720cad0597e08e381f38e4f0e7442a3f698a80fe")
        assert_equal(node.gettxoutsetinfo("muhash")['muhash'], "86968486e3f734e8d7c1050cfdb58a981e43aef8c48419b6fa26519e7a6f5786")

    def run_test(self):
        self.test_muhash_implementation()


if __name__ == '__main__':
    UTXOSetHashTest().main()
