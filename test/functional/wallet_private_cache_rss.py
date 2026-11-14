#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Manual bounded-RSS stress test for private block connection.

This Linux-only benchmark is intentionally not registered in test_runner.py.
It combines the deterministic cache-accounting unit test with a process-level
measurement while constructing and connecting an Orchard-heavy block under a
small ``-dbcache`` setting.
"""

from decimal import Decimal
from pathlib import Path

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal

MAX_MINING_TRIES = 10_000_000
TX_COUNT = 16
OUTPUTS_PER_TX = 8
MAX_HWM_GROWTH_KIB = 768 * 1024


class WalletPrivateCacheRssTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        sender_args = [
            "-privateactivationheight=1",
            "-orchardindex=1",
            # The sender intentionally builds one large chain of unconfirmed
            # Orchard spends before mining it in a single block.
            "-limitancestorsize=1000",
            "-limitdescendantsize=1000",
        ]
        receiver_args = [
            "-dbcache=4",
            "-privateactivationheight=1",
            "-orchardindex=1",
        ]
        self.extra_args = [sender_args, receiver_args]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def process_memory_kib(self):
        status = Path(f"/proc/{self.nodes[1].process.pid}/status")
        if not status.exists():
            self.skip_test("Linux /proc process accounting is required")
        values = {}
        for line in status.read_text(encoding="utf8").splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                key, value, _unit = line.split()
                values[key.rstrip(":")] = int(value)
        return values

    def mine_to_height(self, wallet, height, *, sync=True):
        node = self.nodes[0]
        while node.getblockcount() < height:
            self.generatetoaddress(
                node,
                height - node.getblockcount(),
                wallet.getnewaddress(),
                MAX_MINING_TRIES,
                sync_fun=None if sync else (lambda: None),
            )
        assert_equal(node.getblockcount(), height)

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.mine_to_height(wallet, 101)
        self.sync_blocks()
        self.nodes[1].syncwithvalidationinterfacequeue()
        baseline = self.process_memory_kib()

        # Keep the receiving node away from proof construction and mempool
        # admission. It will only connect the final Orchard-heavy block.
        self.disconnect_nodes(0, 1)

        self.log.info(
            "Create %d private transactions with %d outputs each",
            TX_COUNT,
            OUTPUTS_PER_TX,
        )
        txids = set()
        for _ in range(TX_COUNT):
            outputs = {
                wallet.getnewaddress("", "bech32x"): Decimal("0.001")
                for _ in range(OUTPUTS_PER_TX)
            }
            result = wallet.send(outputs=outputs, options={"fee_rate": 1})
            assert_equal(result["complete"], True)
            txids.add(result["txid"])

        assert_equal(set(node.getrawmempool()), txids)
        self.mine_to_height(wallet, 102, sync=False)
        self.connect_nodes(0, 1)
        self.sync_blocks(timeout=600)
        self.nodes[1].syncwithvalidationinterfacequeue()
        assert_equal(self.nodes[1].getblockcount(), 102)

        measured = self.process_memory_kib()
        growth = measured["VmHWM"] - baseline["VmHWM"]
        self.log.info(
            "nitod RSS: baseline=%d KiB current=%d KiB high-water=%d KiB "
            "high-water-growth=%d KiB",
            baseline["VmRSS"],
            measured["VmRSS"],
            measured["VmHWM"],
            growth,
        )
        assert growth < MAX_HWM_GROWTH_KIB, (
            f"nitod high-water RSS grew by {growth} KiB; "
            f"limit is {MAX_HWM_GROWTH_KIB} KiB"
        )


if __name__ == "__main__":
    WalletPrivateCacheRssTest().main()
