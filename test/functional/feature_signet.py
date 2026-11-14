#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test basic signet functionality."""

from decimal import Decimal
from test_framework.signet import read_signet_fixture
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal


DEFAULT_SIGNET_CHALLENGE = '512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae'


class SignetBasicTest(NitoTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 6
        self.setup_clean_chain = True
        shared_args1 = ["-signetchallenge=51"]  # OP_TRUE
        # The fixed historical block must be relayable after initial sync.
        shared_args2 = ['-signetchallenge=' + read_signet_fixture()['challenge'], '-maxtipage=2147483647']
        shared_args3 = []  # Nito's default 1-of-2 challenge

        self.extra_args = [
            shared_args1, shared_args1,
            shared_args2, shared_args2,
            shared_args3, shared_args3,
        ]

    def setup_network(self):
        self.setup_nodes()

        # Setup three isolated signet networks.
        self.connect_nodes(0, 1)
        self.connect_nodes(2, 3)
        self.connect_nodes(4, 5)

    def run_test(self):
        self.log.info("basic tests using OP_TRUE challenge")

        self.log.info('getmininginfo')
        mining_info = self.nodes[0].getmininginfo()
        assert_equal(mining_info['blocks'], 0)
        assert_equal(mining_info['chain'], 'signet')
        assert 'currentblocktx' not in mining_info
        assert 'currentblockweight' not in mining_info
        assert_equal(mining_info['networkhashps'], Decimal('0'))
        assert_equal(mining_info['pooledtx'], 0)

        self.log.info("Nito signet challenges exposed through getblocktemplate")
        assert_equal(self.nodes[0].getblocktemplate({"rules": ["signet", "segwit"]})['signet_challenge'], '51')
        assert_equal(self.nodes[4].getblocktemplate({"rules": ["signet", "segwit"]})['signet_challenge'], DEFAULT_SIGNET_CHALLENGE)

        self.log.info("Validate a mined Nito block against matching and different signing challenges")
        fixture = read_signet_fixture()
        assert_equal(self.nodes[4].submitblock(fixture['block']), 'bad-signet-blksig')
        assert_equal(self.nodes[4].getblockcount(), 0)
        assert_equal(self.nodes[2].submitblock(fixture['block']), None)
        self.sync_blocks(self.nodes[2:4])
        assert_equal(self.nodes[2].getbestblockhash(), fixture['hash'])
        assert_equal(self.nodes[3].getblockcount(), 1)

        self.log.info("test that signet logs the network magic on node start")
        with self.nodes[0].assert_debug_log(["Signet derived magic (message start)"]):
            self.restart_node(0)
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(extra_args=["-signetchallenge=abc"], expected_msg="Error: -signetchallenge must be hex, not 'abc'.")
        self.nodes[0].assert_start_raises_init_error(extra_args=["-signetchallenge=abc"] * 2, expected_msg="Error: -signetchallenge cannot be multiple values.")


if __name__ == '__main__':
    SignetBasicTest().main()
