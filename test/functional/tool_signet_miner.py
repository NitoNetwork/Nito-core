#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test signet miner tool"""

import os.path
import importlib.machinery
import importlib.util
import shlex
import subprocess
import sys

from test_framework.key import ECKey
from test_framework.script_util import key_to_p2wpkh_script
from test_framework.signet import read_signet_fixture
from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import bytes_to_wif


CHALLENGE_PRIVATE_KEY = (42).to_bytes(32, 'big')


class SignetMinerTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.chain = "signet"
        self.setup_clean_chain = True
        self.num_nodes = 1

        # generate and specify signet challenge (simple p2wpkh script)
        privkey = ECKey()
        privkey.set(CHALLENGE_PRIVATE_KEY, True)
        pubkey = privkey.get_pubkey().get_bytes()
        challenge = key_to_p2wpkh_script(pubkey)
        self.extra_args = [[f'-signetchallenge={challenge.hex()}']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()
        self.skip_if_no_wallet()
        self.skip_if_no_nito_util()

    def run_test(self):
        node = self.nodes[0]
        fixture = read_signet_fixture()
        # import private key needed for signing block
        node.importprivkey(bytes_to_wif(CHALLENGE_PRIVATE_KEY))

        # generate block with signet miner tool
        base_dir = self.config["environment"]["SRCDIR"]
        signet_miner_path = os.path.join(base_dir, "contrib", "signet", "miner")
        loader = importlib.machinery.SourceFileLoader('signet_miner', signet_miner_path)
        spec = importlib.util.spec_from_loader(loader.name, loader)
        miner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(miner)
        target = miner.nbits_to_target(0x1d00ffff)
        assert_equal(miner.next_block_delta(0x1d00ffff, '00' * 32, target, False, 1800), 60)
        assert_equal(miner.next_block_delta(0x1d00ffff, '00' * 32, target * 10, False, 1800), 300)
        assert_equal(miner.next_block_delta(0x1d00ffff, '00' * 32, target // 10, False, 1800), 1)
        subprocess.run([
                sys.executable,
                signet_miner_path,
                '--cli=' + shlex.join([node.cli.binary, f'-datadir={node.cli.datadir}']),
                'generate',
                f'--address={fixture["reward_address"]}',
                '--grind-cmd=' + shlex.join([sys.executable, os.path.join(base_dir, 'test', 'functional', 'test_framework', 'signet.py')]),
                f'--set-block-time={fixture["blocktime"]}',
            ], check=True, stderr=subprocess.STDOUT)
        assert_equal(node.getblockcount(), 1)
        assert_equal(node.getbestblockhash(), fixture['hash'])


if __name__ == "__main__":
    SignetMinerTest().main()
