#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Manual benchmark for private transaction construction.

This test is intentionally not listed in test_runner.py. It performs repeated
Orchard proof construction and is meant for before/after profiling of wallet
send performance, not for default CI coverage.
"""

from decimal import Decimal
from time import perf_counter

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal

MAX_MINING_TRIES = 10_000_000


class WalletPrivateSendBenchmark(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-privateactivationheight=1", "-orchardindex=1"]]
        self.rpc_timeout = 240

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to_height(self, node, wallet, height):
        while node.getblockcount() < height:
            self.generatetoaddress(
                node,
                height - node.getblockcount(),
                wallet.getnewaddress(),
                MAX_MINING_TRIES,
            )
        assert_equal(node.getblockcount(), height)

    def time_calls(self, label, count, fn):
        start = perf_counter()
        for _ in range(count):
            res = fn()
            assert_equal(res["complete"], True)
            assert "hex" in res
        elapsed = perf_counter() - start
        self.log.info(
            "%s count=%d total=%.3fs avg=%.3fs",
            label,
            count,
            elapsed,
            elapsed / count,
        )
        return elapsed

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info("Mine spendable transparent funds and activate private transactions")
        self.mine_to_height(node, wallet, 101)

        self.log.info("Create one confirmed private note for private-source benchmarks")
        private_source_addr = wallet.getnewaddress("", "bech32x")
        shield_txid = wallet.sendtoaddress(private_source_addr, Decimal("5"))
        self.mine_to_height(node, wallet, node.getblockcount() + 1)
        node.syncwithvalidationinterfacequeue()
        self.wait_until(lambda: wallet.gettransaction(shield_txid)["confirmations"] >= 1, timeout=240)
        self.wait_until(lambda: wallet.getprivatebalance()["spendable_notes"] >= 1, timeout=240)

        def transparent_to_private():
            return wallet.send(
                outputs={wallet.getnewaddress("", "bech32x"): Decimal("0.001")},
                options={"fee_rate": 1, "add_to_wallet": False},
            )

        def private_to_private():
            return wallet.send(
                outputs={wallet.getnewaddress("", "bech32x"): Decimal("0.001")},
                options={"fee_rate": 1, "private": True, "add_to_wallet": False},
            )

        self.log.info("Benchmark separate transparent-to-private transaction construction")
        for count in (1, 10, 50):
            self.time_calls("transparent_to_private_separate", count, transparent_to_private)

        self.log.info("Benchmark separate private-to-private transaction construction")
        for count in (1, 10, 50):
            self.time_calls("private_to_private_separate", count, private_to_private)

        self.log.info("Benchmark one multi-output private transaction per source type")
        transparent_multi_outputs = {
            wallet.getnewaddress("", "bech32x"): Decimal("0.001") for _ in range(10)
        }
        private_multi_outputs = {
            wallet.getnewaddress("", "bech32x"): Decimal("0.001") for _ in range(10)
        }
        self.time_calls(
            "transparent_to_private_multi_output_10",
            1,
            lambda: wallet.send(
                outputs=transparent_multi_outputs,
                options={"fee_rate": 1, "add_to_wallet": False},
            ),
        )
        self.time_calls(
            "private_to_private_multi_output_10",
            1,
            lambda: wallet.send(
                outputs=private_multi_outputs,
                options={"fee_rate": 1, "private": True, "add_to_wallet": False},
            ),
        )


if __name__ == "__main__":
    WalletPrivateSendBenchmark().main()
