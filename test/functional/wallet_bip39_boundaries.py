#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject unrepresentable phrases without changing a blank wallet's authority."""

from test_framework.test_framework import NitoTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBIP39BoundariesTest(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-orchardindex=1", "-transparenthistoryindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("boundaries", blank=True, descriptors=True)
        wallet = node.get_wallet_rpc("boundaries")

        # Valid BIP39 checksums, but outside the scalar range used by the
        # persisted Nito seed metadata. Reject before initializing the wallet.
        for phrase in (" ".join(["abandon"] * 23 + ["art"]),
                       " ".join(["zoo"] * 23 + ["vote"])):
            assert_raises_rpc_error(-5, "not valid Nito HD seed key material", wallet.sethdseed, True, phrase)
            assert wallet.getwalletinfo()["blank"]

        # This valid 24-word entropy equals the encoded metadata of the
        # 12-word all-zero entropy. It must never select that other seed.
        ambiguous_phrase = (
            "exact enjoy because acoustic scale abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "ramp holiday sustain describe innocent liquid sustain universe"
        )
        assert_raises_rpc_error(-5, "reserved Nito seed metadata", wallet.sethdseed, True, ambiguous_phrase)
        assert wallet.getwalletinfo()["blank"]

        phrase = " ".join(["abandon"] * 11 + ["about"])

        # Enforce byte limits both before and after NFKD, without consuming
        # the blank wallet's one opportunity to initialize its authority.
        for passphrase in ("\u00e9" * 513, "\u00e9" * 342):
            assert_raises_rpc_error(-8, "maximum of 1024 UTF-8 bytes", wallet.sethdseed, True, phrase, passphrase)
            assert wallet.getwalletinfo()["blank"]

        # ASCII at the exact limit is accepted (the basic seed test covers
        # composed/decomposed equivalence and NUL rejection separately).
        node.createwallet("passphrase_limit", blank=True, descriptors=True)
        limit_wallet = node.get_wallet_rpc("passphrase_limit")
        limit_wallet.sethdseed(True, phrase, "x" * 1024)
        assert_equal(limit_wallet.dumpmnemonic()["bip39_passphrase_required"], True)

        self.generate(node, 1)

        # NFKD must not trim, case-fold, or collapse any passphrase spaces.
        transparent_authorities = set()
        orchard_authorities = set()
        for index, passphrase in enumerate(("Key", "key", " Key", "Key ", "K ey", "K  ey", " ")):
            name = f"passphrase_significant_{index}"
            node.createwallet(name, blank=True, descriptors=True)
            significant = node.get_wallet_rpc(name)
            significant.sethdseed(True, phrase, passphrase)
            assert_equal(significant.dumpmnemonic()["bip39_passphrase_required"], True)
            transparent_authorities.add(significant.getnewaddress())
            orchard_authorities.add(significant.getnewaddress("", "bech32x"))
        assert_equal(len(transparent_authorities), 7)
        assert_equal(len(orchard_authorities), 7)

        wallet.sethdseed(True, "  " + phrase.upper().replace(" ", "  ") + "  ")
        assert_equal(wallet.dumpmnemonic()["mnemonic"], phrase)
        assert_equal(wallet.dumpmnemonic()["words"], 12)


if __name__ == '__main__':
    WalletBIP39BoundariesTest().main()
