#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test nito-cli"""

from decimal import Decimal
import json
import os
import re
import signal

from test_framework.address import key_to_p2pkh
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.test_framework import NitoTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_process_error,
    assert_raises_rpc_error,
    get_auth_cookie,
)
from test_framework.wallet_util import generate_keypair
import time

# The block reward of coinbaseoutput.nValue (512) NITO/block matures after
# COINBASE_MATURITY (100) blocks. Therefore, after mining 101 blocks we expect
# node 0 to have a balance of (BLOCKS - COINBASE_MATURITY) * 512 NITO/block.
BLOCKS = COINBASE_MATURITY + 1
BALANCE = (BLOCKS - 100) * 512
MNEMONIC_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

JSON_PARSING_ERROR = 'error: Error parsing JSON: foo'
BLOCKS_VALUE_OF_ZERO = 'error: the first argument (number of blocks to generate, default: 1) must be an integer value greater than zero'
TOO_MANY_ARGS = 'error: too many arguments (maximum 2 for nblocks and maxtries)'
WALLET_NOT_LOADED = 'Requested wallet does not exist or is not loaded'
WALLET_NOT_SPECIFIED = 'Wallet file not specified'


def run_cli_pty(binary, datadir, arguments, exchanges, timeout=15):
    """Run nito-cli on a POSIX pseudo-terminal and answer expected prompts."""
    import errno
    import pty
    import select
    import subprocess
    import termios

    master_fd, slave_fd = pty.openpty()
    initial_echo = bool(termios.tcgetattr(slave_fd)[3] & termios.ECHO)
    process = subprocess.Popen(
        [binary, f'-datadir={datadir}', *arguments],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
    )
    transcript = bytearray()

    def read_once(wait):
        readable, _, _ = select.select([master_fd], [], [], wait)
        if not readable:
            return False
        try:
            data = os.read(master_fd, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                return False
            raise
        if not data:
            return False
        transcript.extend(data)
        return True

    try:
        for prompt, response in exchanges:
            deadline = time.monotonic() + timeout
            expected = prompt.encode()
            while expected not in transcript:
                if process.poll() is not None:
                    raise AssertionError(f'nito-cli exited before prompt {prompt!r}: {transcript!r}')
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not read_once(remaining):
                    raise AssertionError(f'timed out waiting for prompt {prompt!r}: {transcript!r}')
            if response is None:
                process.send_signal(signal.SIGINT)
                break
            os.write(master_fd, response.encode() + b'\n')

        deadline = time.monotonic() + timeout
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f'nito-cli did not exit: {transcript!r}')
            read_once(min(remaining, 0.1))
        while read_once(0):
            pass

        final_echo = bool(termios.tcgetattr(slave_fd)[3] & termios.ECHO)
        return process.returncode, transcript.decode(errors='replace'), initial_echo, final_echo
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master_fd)
        os.close(slave_fd)


def cli_get_info_string_to_dict(cli_get_info_string):
    """Helper method to convert human-readable -getinfo into a dictionary"""
    cli_get_info = {}
    lines = cli_get_info_string.splitlines()
    line_idx = 0
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    while line_idx < len(lines):
        # Remove ansi colour code
        line = ansi_escape.sub('', lines[line_idx])
        if "Balances" in line:
            # When "Balances" appears in a line, all of the following lines contain "balance: wallet" until an empty line
            cli_get_info["Balances"] = {}
            while line_idx < len(lines) and not (lines[line_idx + 1] == ''):
                line_idx += 1
                balance, wallet = lines[line_idx].strip().split(" ")
                # Remove right justification padding
                wallet = wallet.strip()
                if wallet == '""':
                    # Set default wallet("") to empty string
                    wallet = ''
                cli_get_info["Balances"][wallet] = balance.strip()
        elif ": " in line:
            key, value = line.split(": ")
            if key == 'Wallet' and value == '""':
                # Set default wallet("") to empty string
                value = ''
            if key == "Proxies" and value == "n/a":
                # Set N/A to empty string to represent no proxy
                value = ''
            cli_get_info[key.strip()] = value.strip()
        line_idx += 1
    return cli_get_info


class TestNitoCli(NitoTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-deprecatedrpc=create_bdb", "-blockfilterindex=1", "-orchardindex=1", "-transparenthistoryindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()

    def test_interactive_wallet_management(self):
        node = self.nodes[0]

        self.log.info("Test createwallet only offers BIP39 protection when it is applicable")
        watch_name = "cli_interactive_watch_only"
        watch_result = node.cli(
            "-interactive",
            input="n\nunexpected second prompt\n",
        ).createwallet(wallet_name=watch_name, disable_private_keys=True, descriptors=True)
        assert_equal(watch_result["name"], watch_name)
        watch_wallet = node.get_wallet_rpc(watch_name)
        assert_equal(watch_wallet.getwalletinfo()["private_keys_enabled"], False)
        watch_wallet.unloadwallet()

        legacy_name = "cli_interactive_legacy_create"
        legacy_result = node.cli(
            "-interactive",
            input="n\nunexpected second prompt\n",
        ).createwallet(wallet_name=legacy_name, descriptors=False)
        assert_equal(legacy_result["name"], legacy_name)
        legacy_wallet = node.get_wallet_rpc(legacy_name)
        assert_equal(legacy_wallet.getwalletinfo()["descriptors"], False)
        legacy_wallet.unloadwallet()

        assert_raises_process_error(
            1,
            "external_signer=true requires disable_private_keys=true and descriptors=true",
            node.cli("-interactive", input="").createwallet,
            wallet_name="cli_interactive_invalid_signer",
            external_signer=True,
            disable_private_keys=False,
            descriptors=True,
        )

        self.log.info("Test guided legacy-wallet migration")
        cancelled_name = "cli_interactive_migration_cancelled"
        node.createwallet(wallet_name=cancelled_name, blank=True, descriptors=False)
        cancelled = node.get_wallet_rpc(cancelled_name)
        assert_raises_process_error(
            1,
            "Wallet migration cancelled before any change",
            node.cli("-named", "-interactive", f"-rpcwallet={cancelled_name}", input="n\n").migratewallet,
        )
        assert_equal(cancelled.getwalletinfo()["descriptors"], False)
        cancelled.unloadwallet()

        migration_name = "cli_interactive_migration"
        migration_secret = "legacy migration secret"
        migration_wif, _ = generate_keypair(wif=True)
        node.createwallet(wallet_name=migration_name, blank=True, descriptors=False)
        migrated = node.get_wallet_rpc(migration_name)
        migrated.sethdseed(True, migration_wif)
        pre_migration_address = migrated.getnewaddress()
        migrated.encryptwallet(migration_secret)
        migration_result = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={migration_name}",
            input=f"y\ny\n{migration_secret}\n",
        ).migratewallet()
        assert_equal(migration_result["wallet_name"], migration_name)
        assert_equal(migrated.getwalletinfo()["descriptors"], True)
        assert_equal(migrated.getaddressinfo(pre_migration_address)["ismine"], True)
        migrated.unloadwallet()

        self.log.info("Test guided Orchard upgrade with generated and restored phrases")
        generated_name = "cli_interactive_orchard_generated"
        generated_wif, _ = generate_keypair(wif=True)
        node.createwallet(wallet_name=generated_name, blank=True, descriptors=False)
        generated = node.get_wallet_rpc(generated_name)
        generated.sethdseed(True, generated_wif)
        generated_result = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={generated_name}",
            input="n\nn\ny\n",
        ).upgradeorchardwallet()
        assert_equal(generated_result["scope"], "orchard_only")
        assert_equal(generated_result["bip39_passphrase_required"], False)
        assert_equal(len(generated_result["mnemonic"].split()), 24)
        generated.unloadwallet()

        restored_name = "cli_interactive_orchard_restored"
        orchard_bip39 = "Orchard BIP39 secret"
        restored_wif, _ = generate_keypair(wif=True)
        node.createwallet(wallet_name=restored_name, blank=True, descriptors=False)
        restored = node.get_wallet_rpc(restored_name)
        restored.sethdseed(True, restored_wif)
        assert_raises_process_error(
            1,
            "Orchard recovery phrases do not match",
            node.cli(
                "-named",
                "-interactive",
                f"-rpcwallet={restored_name}",
                input=f"y\n{MNEMONIC_12}\ndifferent phrase\n",
            ).upgradeorchardwallet,
        )
        assert_raises_process_error(
            1,
            "Orchard wallet upgrade cancelled before any change",
            node.cli("-named", "-interactive", f"-rpcwallet={restored_name}", input="n\nn\nn\n").upgradeorchardwallet,
        )
        restored_result = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={restored_name}",
            input=f"y\n{MNEMONIC_12}\n{MNEMONIC_12}\ny\n{orchard_bip39}\n{orchard_bip39}\ny\n",
        ).upgradeorchardwallet()
        assert_equal(restored_result["mnemonic"], MNEMONIC_12)
        assert_equal(restored_result["bip39_passphrase_required"], True)
        restored.unloadwallet()

        self.log.info("Test the complete guided encrypted V4 recovery path")
        recovery_name = "cli_interactive_v4_restore"
        wallet_secret = "restored wallet encryption secret"
        recovery_bip39 = "Recovery BIP39 secret"
        create_result = node.cli(
            "-interactive",
            input=f"y\n{wallet_secret}\n{wallet_secret}\n",
        ).createwallet(wallet_name=recovery_name, blank=True, descriptors=True)
        assert_equal(create_result["name"], recovery_name)
        recovered = node.get_wallet_rpc(recovery_name)
        assert_equal(recovered.getwalletinfo()["blank"], True)
        recovered.walletpassphrase(wallet_secret, 300)
        assert_raises_process_error(
            1,
            "BIP39 recovery phrases do not match",
            node.cli(
                "-interactive",
                f"-rpcwallet={recovery_name}",
                input=f"y\nn\n{MNEMONIC_12}\ndifferent phrase\n",
            ).sethdseed,
            newkeypool=True,
        )
        assert_equal(recovered.getwalletinfo()["blank"], True)
        assert_raises_process_error(
            1,
            "Wallet recovery cancelled before any change",
            node.cli(
                "-interactive",
                f"-rpcwallet={recovery_name}",
                input=f"y\nn\n{MNEMONIC_12}\n{MNEMONIC_12}\nn\nn\n",
            ).sethdseed,
            newkeypool=True,
        )
        assert_equal(recovered.getwalletinfo()["blank"], True)
        node.cli(
            "-interactive",
            f"-rpcwallet={recovery_name}",
            input=f"y\nn\n{MNEMONIC_12}\n{MNEMONIC_12}\ny\n{recovery_bip39}\n{recovery_bip39}\ny\n",
        ).sethdseed(newkeypool=True)
        assert_equal(recovered.getwalletinfo()["blank"], False)
        mnemonic_info = recovered.dumpmnemonic()
        assert_equal(mnemonic_info["mnemonic"], MNEMONIC_12)
        assert_equal(mnemonic_info["bip39_passphrase_required"], True)
        recovered.walletlock()
        recovered.unloadwallet()

        self.log.info("Test guided sethdseed preserves random BIP39 and legacy WIF modes")
        random_seed_name = "cli_interactive_random_seed"
        node.createwallet(wallet_name=random_seed_name, blank=True, descriptors=True)
        random_seed_wallet = node.get_wallet_rpc(random_seed_name)
        node.cli(
            "-interactive",
            f"-rpcwallet={random_seed_name}",
            input="n\nn\ny\n",
        ).sethdseed(newkeypool=True)
        assert_equal(random_seed_wallet.getwalletinfo()["blank"], False)
        assert_equal(len(random_seed_wallet.dumpmnemonic()["mnemonic"].split()), 24)
        random_seed_wallet.unloadwallet()

        legacy_seed_name = "cli_interactive_legacy_seed"
        legacy_seed_wif, _ = generate_keypair(wif=True)
        node.createwallet(wallet_name=legacy_seed_name, blank=True, descriptors=False)
        legacy_seed_wallet = node.get_wallet_rpc(legacy_seed_name)
        node.cli(
            "-interactive",
            f"-rpcwallet={legacy_seed_name}",
            input=f"y\ny\n{legacy_seed_wif}\n{legacy_seed_wif}\ny\n",
        ).sethdseed(newkeypool=True)
        assert_equal(legacy_seed_wallet.getwalletinfo()["blank"], False)
        assert legacy_seed_wallet.getnewaddress()
        legacy_seed_wallet.unloadwallet()

        self.log.info("Test guided encryption and passphrase change")
        encryption_name = "cli_interactive_encryption_lifecycle"
        old_secret = "old wallet encryption secret"
        new_secret = "new wallet encryption secret"
        node.createwallet(wallet_name=encryption_name, descriptors=True)
        encrypted = node.get_wallet_rpc(encryption_name)
        assert_raises_process_error(
            1,
            "Wallet encryption cancelled before any change",
            node.cli("-named", "-interactive", f"-rpcwallet={encryption_name}", input="n\n").encryptwallet,
        )
        assert_raises_rpc_error(-15, "unencrypted wallet", encrypted.walletpassphrase, old_secret, 1)
        assert_raises_process_error(
            1,
            "New wallet encryption passphrases do not match",
            node.cli(
                "-named",
                "-interactive",
                f"-rpcwallet={encryption_name}",
                input=f"y\n{old_secret}\ndifferent confirmation\n",
            ).encryptwallet,
        )
        assert_raises_rpc_error(-15, "unencrypted wallet", encrypted.walletpassphrase, old_secret, 1)
        node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={encryption_name}",
            input=f"y\n{old_secret}\n{old_secret}\n",
        ).encryptwallet()
        encrypted.walletpassphrase(old_secret, 60)
        encrypted.walletlock()
        assert_raises_process_error(
            1,
            "New wallet encryption passphrases do not match",
            node.cli(
                "-named",
                "-interactive",
                f"-rpcwallet={encryption_name}",
                input=f"{old_secret}\n{new_secret}\ndifferent confirmation\n",
            ).walletpassphrasechange,
        )
        encrypted.walletpassphrase(old_secret, 60)
        encrypted.walletlock()
        assert_raises_process_error(
            1,
            "Wallet passphrase change cancelled before any change",
            node.cli(
                "-named",
                "-interactive",
                f"-rpcwallet={encryption_name}",
                input=f"{old_secret}\n{new_secret}\n{new_secret}\nn\n",
            ).walletpassphrasechange,
        )
        encrypted.walletpassphrase(old_secret, 60)
        encrypted.walletlock()
        node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={encryption_name}",
            input=f"{old_secret}\n{new_secret}\n{new_secret}\ny\n",
        ).walletpassphrasechange()
        assert_raises_rpc_error(-14, "passphrase entered was incorrect", encrypted.walletpassphrase, old_secret, 1)
        encrypted.walletpassphrase(new_secret, 60)
        encrypted.walletlock()
        encrypted.unloadwallet()

        self.log.info("Test interactive secrets are rejected on the command line")
        secret_argument_cases = [
            ("migratewallet", "passphrase", "exposed"),
            ("upgradeorchardwallet", "mnemonic", MNEMONIC_12),
            ("upgradeorchardwallet", "bip39_passphrase", "exposed"),
            ("sethdseed", "seed", MNEMONIC_12),
            ("sethdseed", "bip39_passphrase", "exposed"),
            ("encryptwallet", "passphrase", "exposed"),
            ("walletpassphrase", "passphrase", "exposed"),
            ("walletpassphrasechange", "oldpassphrase", "exposed"),
            ("walletpassphrasechange", "newpassphrase", "exposed"),
            ("importprivkey", "privkey", "exposed"),
            ("importmulti", "requests", "[]"),
            ("importdescriptors", "requests", "[]"),
            ("signmessagewithprivkey", "privkey", "exposed"),
            ("signrawtransactionwithkey", "privkeys", ["exposed"]),
            ("descriptorprocesspsbt", "descriptors", ["exposed"]),
            ("getdescriptorinfo", "descriptor", "exposed"),
            ("deriveaddresses", "descriptor", "exposed"),
            ("utxoupdatepsbt", "descriptors", ["exposed"]),
            ("scantxoutset", "scanobjects", ["exposed"]),
            ("scanblocks", "scanobjects", ["exposed"]),
            ("generatetodescriptor", "descriptor", "exposed"),
            ("generateblock", "output", "exposed"),
            ("fundrawtransaction", "options", {}),
            ("send", "options", {}),
            ("sendall", "options", {}),
            ("walletcreatefundedpsbt", "options", {}),
            ("checkprivatenoteproof", "proof", "00"),
            ("listdescriptors", "private", True),
            ("getprivatekeymaninfo", "include_private", True),
        ]
        for command, argument_name, argument_value in secret_argument_cases:
            if argument_name == "output":
                assert_raises_process_error(
                    1,
                    "Do not provide output on the command line with -interactive",
                    node.cli("-named", "-interactive", command, "output=exposed", input="").send_cli,
                )
                continue
            assert_raises_process_error(
                1,
                f"Do not provide {argument_name} on the command line with -interactive",
                node.cli("-interactive", input="").send_cli,
                command,
                **{argument_name: argument_value},
            )

        self.log.info("Test interactive conflicts and built-in safe examples")
        assert_raises_process_error(
            1,
            "-interactive cannot be combined with -stdin or -stdinwalletpassphrase",
            node.cli("-named", "-interactive", "-stdinwalletpassphrase", input="").send_cli,
            "encryptwallet",
        )
        for command in (
            "createwallet",
            "migratewallet",
            "upgradeorchardwallet",
            "sethdseed",
            "encryptwallet",
            "walletpassphrase",
            "walletpassphrasechange",
            "importprivkey",
            "importmulti",
            "importdescriptors",
            "signmessagewithprivkey",
            "signrawtransactionwithkey",
            "descriptorprocesspsbt",
            "getdescriptorinfo",
            "deriveaddresses",
            "utxoupdatepsbt",
            "scantxoutset",
            "scanblocks",
            "generatetodescriptor",
            "generateblock",
            "pruneblockchain",
            "preciousblock",
            "invalidateblock",
            "reconsiderblock",
            "loadtxoutset",
            "signmessage",
            "signrawtransactionwithwallet",
            "walletprocesspsbt",
            "fundrawtransaction",
            "send",
            "sendall",
            "walletcreatefundedpsbt",
            "dumpprivkey",
            "dumpmnemonic",
            "getprivateviewkey",
            "getprivatenoteproof",
            "checkprivatenoteproof",
            "listdescriptors",
            "getprivatekeymaninfo",
            "dumpwallet",
            "backupwallet",
            "importwallet",
            "restorewallet",
            "upgradewallet",
            "newkeypool",
            "keypoolrefill",
            "addmultisigaddress",
            "importaddress",
            "importpubkey",
        ):
            assert "nito-cli -named -interactive" in node.help(command)
        assert 'walletpassphrasechange "old one" "new one"' not in node.help("walletpassphrasechange")
        assert 'encryptwallet "my pass phrase"' not in node.help("encryptwallet")
        assert 'walletpassphrase "my pass phrase"' not in node.help("walletpassphrase")

    def test_interactive_private_material(self):
        node = self.nodes[0]

        self.log.info("Test guided wallet unlock and preserve -stdinwalletpassphrase")
        wallet_name = "cli_interactive_private_material"
        wallet_secret = "interactive private material wallet secret"
        node.createwallet(wallet_name=wallet_name, passphrase=wallet_secret, descriptors=True)
        wallet = node.get_wallet_rpc(wallet_name)
        assert_raises_process_error(
            1,
            "Wallet encryption passphrase must not be empty",
            node.cli("-interactive", f"-rpcwallet={wallet_name}", input="\n").walletpassphrase,
            timeout=60,
        )
        assert_raises_process_error(
            1,
            "timeout must be a non-negative integer with -interactive walletpassphrase",
            node.cli("-interactive", f"-rpcwallet={wallet_name}", input=wallet_secret).walletpassphrase,
            timeout=-1,
        )
        node.cli(
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input=f"{wallet_secret}\n",
        ).walletpassphrase(timeout=600)
        assert wallet.getwalletinfo()["unlocked_until"] > 0
        wallet.walletlock()
        node.cli(
            "-stdinwalletpassphrase",
            f"-rpcwallet={wallet_name}",
            input=f"{wallet_secret}\n",
        ).walletpassphrase(600)
        assert wallet.getwalletinfo()["unlocked_until"] > 0
        if os.name == "posix":
            wallet.walletlock()
            returncode, transcript, initial_echo, final_echo = run_cli_pty(
                node.cli.binary,
                node.datadir_path,
                [
                    "-named",
                    "-interactive",
                    f"-rpcwallet={wallet_name}",
                    "walletpassphrase",
                    "timeout=60",
                ],
                [("Wallet encryption passphrase> ", wallet_secret)],
            )
            assert_equal(returncode, 0)
            assert wallet_secret not in transcript
            assert_equal(initial_echo, True)
            assert_equal(final_echo, True)
            wallet.walletlock()
            node.cli(
                "-stdinwalletpassphrase",
                f"-rpcwallet={wallet_name}",
                input=f"{wallet_secret}\n",
            ).walletpassphrase(600)

        funding_address = wallet.getnewaddress()
        node.generatetoaddress(COINBASE_MATURITY + 1, funding_address, invalid_call=False)

        self.log.info("Test guided descriptor import with hidden JSON")
        descriptor_wif, descriptor_pubkey = generate_keypair(wif=True)
        descriptor = descsum_create(f"wpkh({descriptor_wif})")
        descriptor_address = node.deriveaddresses(descriptor)[0]
        descriptor_requests = json.dumps([
            {"desc": descriptor, "timestamp": "now", "active": False},
        ], separators=(",", ":"))
        assert_raises_process_error(
            1,
            "Descriptor import cancelled before any change",
            node.cli(
                "-named",
                "-interactive",
                f"-rpcwallet={wallet_name}",
                input=f"{descriptor_requests}\nn\n",
            ).importdescriptors,
        )
        assert_equal(wallet.getaddressinfo(descriptor_address)["ismine"], False)
        descriptor_result = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input=f"{descriptor_requests}\ny\n",
        ).importdescriptors()
        assert_equal(descriptor_result[0]["success"], True)
        assert_equal(wallet.getaddressinfo(descriptor_address)["ismine"], True)

        self.log.info("Test guided recovery-authority disclosures")
        assert_raises_process_error(
            1,
            "Recovery-phrase disclosure cancelled",
            node.cli("-named", "-interactive", f"-rpcwallet={wallet_name}", input="n\n").dumpmnemonic,
        )
        mnemonic_info = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="y\n",
        ).dumpmnemonic()
        assert_equal(len(mnemonic_info["mnemonic"].split()), 24)

        orchard_address = wallet.getnewaddress("", "bech32x")
        assert_raises_process_error(
            1,
            "cmx must be a 64-character hexadecimal private note commitment",
            node.cli("-interactive", f"-rpcwallet={wallet_name}", input="").getprivatenoteproof,
            cmx="not-a-note-commitment",
        )
        assert_raises_process_error(
            1,
            "Viewing-key disclosure cancelled",
            node.cli("-interactive", f"-rpcwallet={wallet_name}", input="n\n").getprivateviewkey,
            address=orchard_address,
        )
        view_key = node.cli(
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="y\n",
        ).getprivateviewkey(address=orchard_address)
        assert view_key

        wallet.sendtoaddress(orchard_address, Decimal("0.01"))
        self.generate(node, 1)
        private_notes = wallet.listprivateunspent()
        assert private_notes
        note_cmx = private_notes[0]["cmx"]
        assert_raises_process_error(
            1,
            "Private-note proof disclosure cancelled",
            node.cli("-interactive", f"-rpcwallet={wallet_name}", input="n\n").getprivatenoteproof,
            cmx=note_cmx,
        )
        note_proof = node.cli(
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="y\n",
        ).getprivatenoteproof(cmx=note_cmx)
        assert_equal(note_proof["details"]["cmx"], note_cmx)
        checked_note = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input=f"{note_proof['proof']}\n",
        ).checkprivatenoteproof()
        assert_equal(checked_note["valid"], True)
        assert_equal(checked_note["details"]["cmx"], note_cmx)

        public_descriptors = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="n\n",
        ).listdescriptors()
        private_descriptors = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="y\n",
        ).listdescriptors()
        assert public_descriptors["descriptors"]
        assert private_descriptors["descriptors"]
        assert all(not node.getdescriptorinfo(entry["desc"])["hasprivatekeys"] for entry in public_descriptors["descriptors"])
        assert any(node.getdescriptorinfo(entry["desc"])["hasprivatekeys"] for entry in private_descriptors["descriptors"])

        public_keyman = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="n\n",
        ).getprivatekeymaninfo()
        private_keyman = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="y\n",
        ).getprivatekeymaninfo()
        assert public_keyman
        assert private_keyman
        assert "external_descriptor" not in public_keyman
        assert "change_descriptor" not in public_keyman
        assert "external_descriptor" in private_keyman
        assert "change_descriptor" in private_keyman

        backup_path = str(node.datadir_path / "interactive-private-material-backup.dat")
        assert_raises_process_error(
            1,
            "Wallet backup cancelled before any file was written",
            node.cli("-interactive", f"-rpcwallet={wallet_name}", input="n\n").backupwallet,
            destination=backup_path,
        )
        assert not os.path.exists(backup_path)
        node.cli("-interactive", f"-rpcwallet={wallet_name}", input="y\n").backupwallet(destination=backup_path)
        assert os.path.isfile(backup_path)

        self.log.info("Test guided legacy private-key imports and exports")
        legacy_name = "cli_interactive_private_imports"
        node.createwallet(wallet_name=legacy_name, blank=True, descriptors=False)
        legacy_wallet = node.get_wallet_rpc(legacy_name)
        import_wif, import_pubkey = generate_keypair(wif=True)
        import_address = key_to_p2pkh(import_pubkey)
        assert_raises_process_error(
            1,
            "Private-key import cancelled before any change",
            node.cli(
                "-interactive",
                f"-rpcwallet={legacy_name}",
                input=f"{import_wif}\nn\n",
            ).importprivkey,
            label="interactive import",
            rescan=False,
        )
        assert_equal(legacy_wallet.getaddressinfo(import_address)["ismine"], False)
        node.cli(
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input=f"{import_wif}\ny\n",
        ).importprivkey(label="interactive import", rescan=False)
        assert_equal(legacy_wallet.getaddressinfo(import_address)["ismine"], True)

        multi_wif, multi_pubkey = generate_keypair(wif=True)
        multi_address = key_to_p2pkh(multi_pubkey)
        multi_requests = json.dumps([
            {
                "scriptPubKey": {"address": multi_address},
                "timestamp": "now",
                "keys": [multi_wif],
            },
        ], separators=(",", ":"))
        assert_raises_process_error(
            1,
            "Multi-import cancelled before any change",
            node.cli(
                "-interactive",
                f"-rpcwallet={legacy_name}",
                input=f"{multi_requests}\nn\n",
            ).importmulti,
            options={"rescan": False},
        )
        assert_equal(legacy_wallet.getaddressinfo(multi_address)["ismine"], False)
        multi_result = node.cli(
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input=f"{multi_requests}\ny\n",
        ).importmulti(options={"rescan": False})
        assert_equal(multi_result[0]["success"], True)
        assert_equal(legacy_wallet.getaddressinfo(multi_address)["ismine"], True)

        assert_raises_process_error(
            1,
            "Private-key disclosure cancelled",
            node.cli("-interactive", f"-rpcwallet={legacy_name}", input="n\n").dumpprivkey,
            address=import_address,
        )
        exported_wif = node.cli(
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input="y\n",
        ).dumpprivkey(address=import_address)
        assert_equal(exported_wif, import_wif)

        dump_path = str(node.datadir_path / "interactive-legacy-wallet.dump")
        assert_raises_process_error(
            1,
            "Wallet dump cancelled before any file was written",
            node.cli("-interactive", f"-rpcwallet={legacy_name}", input="n\n").dumpwallet,
            filename=dump_path,
        )
        assert not os.path.exists(dump_path)
        node.cli("-interactive", f"-rpcwallet={legacy_name}", input="y\n").dumpwallet(filename=dump_path)
        assert os.path.isfile(dump_path)

        self.log.info("Test guided private-key signing")
        message = "Nito interactive signing test"
        assert_raises_process_error(
            1,
            "Message signing cancelled before any signature was created",
            node.cli("-interactive", input=f"{import_wif}\nn\n").signmessagewithprivkey,
            message=message,
        )
        signature = node.cli(
            "-interactive",
            input=f"{import_wif}\ny\n",
        ).signmessagewithprivkey(message=message)
        assert_equal(node.verifymessage(import_address, signature, message), True)

        wallet.sendtoaddress(import_address, Decimal("1"))
        self.generate(node, 1)
        wallet.walletlock()
        wallet.unloadwallet()
        signing_utxo = next(utxo for utxo in legacy_wallet.listunspent() if utxo["address"] == import_address)
        raw_tx = node.createrawtransaction(
            [{"txid": signing_utxo["txid"], "vout": signing_utxo["vout"]}],
            {funding_address: Decimal("0.999")},
        )
        incomplete_tx = node.cli(
            "-interactive",
            input="\ny\n",
        ).signrawtransactionwithkey(hexstring=raw_tx)
        assert_equal(incomplete_tx["complete"], False)
        assert_raises_process_error(
            1,
            "Transaction signing cancelled before any signature was created",
            node.cli("-interactive", input=f"{import_wif}\n\nn\n").signrawtransactionwithkey,
            hexstring=raw_tx,
        )
        signed_tx = node.cli(
            "-interactive",
            input=f"{import_wif}\n\ny\n",
        ).signrawtransactionwithkey(hexstring=raw_tx)
        assert_equal(signed_tx["complete"], True)
        legacy_wallet.unloadwallet()

        empty_signature = node.cli(
            "-interactive",
            input=f"{import_wif}\ny\n",
        ).signmessagewithprivkey(message="")
        assert_equal(node.verifymessage(import_address, empty_signature, ""), True)

    def test_interactive_extended_sensitive_operations(self):
        node = self.nodes[0]

        self.log.info("Test hidden descriptor input, scans, and mining")
        descriptor_wif, _ = generate_keypair(wif=True)
        descriptor = descsum_create(f"wpkh({descriptor_wif})")
        descriptor_info = node.cli(
            "-named",
            "-interactive",
            input=f"{descriptor}\n",
        ).getdescriptorinfo()
        assert_equal(descriptor_info["hasprivatekeys"], True)
        derived_addresses = node.cli(
            "-named",
            "-interactive",
            input=f"{descriptor}\n",
        ).deriveaddresses()
        assert_equal(len(derived_addresses), 1)

        scan_objects = json.dumps([descriptor], separators=(",", ":"))
        utxo_scan = node.cli(
            "-interactive",
            input=f"{scan_objects}\n",
        ).scantxoutset(action="start")
        assert_equal(utxo_scan["success"], True)
        self.wait_until(lambda: all(index["synced"] for index in node.getindexinfo().values()))
        block_scan = node.cli(
            "-interactive",
            input=f"{scan_objects}\n",
        ).scanblocks(action="start")
        assert_equal(block_scan["completed"], True)

        height_before_mining = node.getblockcount()
        assert_raises_process_error(
            1,
            "Descriptor mining cancelled before any block was generated",
            node.cli("-interactive", input=f"{descriptor}\nn\n").generatetodescriptor,
            num_blocks=1,
        )
        assert_equal(node.getblockcount(), height_before_mining)
        mined = node.cli(
            "-interactive",
            input=f"{descriptor}\ny\n",
        ).generatetodescriptor(num_blocks=1)
        assert_equal(len(mined), 1)
        assert_equal(node.getblockcount(), height_before_mining + 1)

        self.log.info("Test guided high-impact local chainstate operations")
        active_tip = node.getbestblockhash()
        previous_tip = node.getblockheader(active_tip)["previousblockhash"]
        assert_raises_process_error(
            1,
            "Precious-block selection cancelled before chainstate changed",
            node.cli("-interactive", input="n\n").preciousblock,
            blockhash=active_tip,
        )
        node.cli("-interactive", input="y\n").preciousblock(blockhash=active_tip)
        assert_equal(node.getbestblockhash(), active_tip)

        assert_raises_process_error(
            1,
            "Block invalidation cancelled before chainstate changed",
            node.cli("-interactive", input="n\n").invalidateblock,
            blockhash=active_tip,
        )
        assert_equal(node.getbestblockhash(), active_tip)
        node.cli("-interactive", input="y\n").invalidateblock(blockhash=active_tip)
        assert_equal(node.getbestblockhash(), previous_tip)

        assert_raises_process_error(
            1,
            "Block reconsideration cancelled before chainstate changed",
            node.cli("-interactive", input="n\n").reconsiderblock,
            blockhash=active_tip,
        )
        assert_equal(node.getbestblockhash(), previous_tip)
        node.cli("-interactive", input="y\n").reconsiderblock(blockhash=active_tip)
        assert_equal(node.getbestblockhash(), active_tip)

        assert_raises_process_error(
            1,
            "Blockchain pruning cancelled before any block file was deleted",
            node.cli("-interactive", input="n\n").pruneblockchain,
            height=1,
        )
        assert_raises_rpc_error(
            -1,
            "Cannot prune blocks because node is not in prune mode",
            node.cli("-interactive", input="y\n").pruneblockchain,
            height=1,
        )
        assert_raises_process_error(
            1,
            "UTXO snapshot loading cancelled before chainstate changed",
            node.cli("-interactive", input="n\n").loadtxoutset,
            path="missing-interactive-snapshot.dat",
        )
        assert_raises_rpc_error(
            -8,
            "Couldn't open file",
            node.cli("-interactive", input="y\n").loadtxoutset,
            path="missing-interactive-snapshot.dat",
        )
        generated = node.cli(
            "-interactive",
            input=f"{descriptor}\ny\n",
        ).generateblock(transactions=[], submit=False)
        assert "hash" in generated
        assert "hex" in generated
        assert_equal(node.getblockcount(), height_before_mining + 1)

        self.log.info("Test guided wallet signing, PSBT processing, and hidden funding options")
        wallet_name = "cli_interactive_private_material"
        wallet_secret = "interactive private material wallet secret"
        node.loadwallet(wallet_name)
        wallet = node.get_wallet_rpc(wallet_name)
        wallet.walletpassphrase(wallet_secret, 600)
        message_address = wallet.getnewaddress("", "legacy")
        message = "Nito guided wallet signing"
        assert_raises_process_error(
            1,
            "Wallet message signing cancelled before any signature was created",
            node.cli("-interactive", f"-rpcwallet={wallet_name}", input="n\n").signmessage,
            address=message_address,
            message=message,
        )
        wallet_signature = node.cli(
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="y\n",
        ).signmessage(address=message_address, message=message)
        assert_equal(node.verifymessage(message_address, wallet_signature, message), True)

        destination = wallet.getnewaddress()
        unsigned_raw = node.createrawtransaction([], {destination: Decimal("0.01")})
        funded_raw = node.cli(
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="true\ny\n",
        ).fundrawtransaction(hexstring=unsigned_raw)
        assert "hex" in funded_raw
        assert_raises_process_error(
            1,
            "Wallet transaction signing cancelled before any signature was created",
            node.cli("-interactive", f"-rpcwallet={wallet_name}", input="n\n").signrawtransactionwithwallet,
            hexstring=funded_raw["hex"],
        )
        signed_raw = node.cli(
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="y\n",
        ).signrawtransactionwithwallet(hexstring=funded_raw["hex"])
        assert_equal(signed_raw["complete"], True)

        psbt_destination = wallet.getnewaddress()
        funded_psbt = node.cli(
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="{}\ny\n",
        ).walletcreatefundedpsbt(inputs=[], outputs={psbt_destination: Decimal("0.01")})
        assert funded_psbt["psbt"]
        updated_psbt = node.cli(
            "-interactive",
            input=f"{json.dumps([descriptor], separators=(',', ':'))}\n",
        ).utxoupdatepsbt(psbt=funded_psbt["psbt"])
        assert updated_psbt
        descriptor_processed = node.cli(
            "-interactive",
            input=f"{json.dumps([descriptor], separators=(',', ':'))}\ny\n",
        ).descriptorprocesspsbt(psbt=updated_psbt, finalize=False)
        assert descriptor_processed["psbt"]
        wallet_processed = node.cli(
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input="y\n",
        ).walletprocesspsbt(psbt=funded_psbt["psbt"], finalize=False)
        assert wallet_processed["psbt"]

        send_destination = wallet.getnewaddress()
        assert_raises_process_error(
            1,
            "Wallet payment cancelled before any transaction was created",
            node.cli("-interactive", f"-rpcwallet={wallet_name}", input="{}\nn\n").send,
            outputs={send_destination: Decimal("0.01")},
        )
        send_result = node.cli(
            "-interactive",
            f"-rpcwallet={wallet_name}",
            input='{"fee_rate":1}\ny\n',
        ).send(outputs={send_destination: Decimal("0.01")})
        assert send_result["txid"]

        self.log.info("Test guided send-all without risking the primary test wallet")
        sendall_name = "cli_interactive_sendall"
        node.createwallet(wallet_name=sendall_name, descriptors=True)
        sendall_wallet = node.get_wallet_rpc(sendall_name)
        wallet.sendtoaddress(sendall_wallet.getnewaddress(), Decimal("1"))
        self.generate(node, 1)
        sendall_balance = sendall_wallet.getbalance()
        assert_greater_than_or_equal(sendall_balance, Decimal("1"))
        sendall_destination = wallet.getnewaddress()
        assert_raises_process_error(
            1,
            "Wallet send-all cancelled before any transaction was created",
            node.cli("-interactive", f"-rpcwallet={sendall_name}", input="{}\nn\n").sendall,
            recipients=[sendall_destination],
        )
        assert_equal(sendall_wallet.getbalance(), sendall_balance)
        sendall_result = node.cli(
            "-interactive",
            f"-rpcwallet={sendall_name}",
            input="{}\ny\n",
        ).sendall(recipients=[sendall_destination])
        assert sendall_result["txid"]
        sendall_wallet.unloadwallet()
        wallet.walletlock()
        wallet.unloadwallet()

        self.log.info("Test guided wallet restore, dump import, version, keypool, and watch-only mutations")
        backup_path = str(node.datadir_path / "interactive-private-material-backup.dat")
        restored_name = "cli_interactive_restored_backup"
        assert_raises_process_error(
            1,
            "Wallet restore cancelled before any wallet was created",
            node.cli("-interactive", input="n\n").restorewallet,
            wallet_name=restored_name,
            backup_file=backup_path,
            load_on_startup=False,
        )
        assert restored_name not in node.listwallets()
        restored_result = node.cli(
            "-interactive",
            input="y\n",
        ).restorewallet(wallet_name=restored_name, backup_file=backup_path, load_on_startup=False)
        assert_equal(restored_result["name"], restored_name)
        node.get_wallet_rpc(restored_name).unloadwallet()

        legacy_name = "cli_interactive_lifecycle_legacy"
        node.createwallet(wallet_name=legacy_name, blank=False, descriptors=False)
        legacy_wallet = node.get_wallet_rpc(legacy_name)
        dump_path = str(node.datadir_path / "interactive-legacy-wallet.dump")
        assert_raises_process_error(
            1,
            "Wallet dump import cancelled before any wallet change",
            node.cli("-interactive", f"-rpcwallet={legacy_name}", input="n\n").importwallet,
            filename=dump_path,
        )
        node.cli(
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input="y\n",
        ).importwallet(filename=dump_path)

        assert_raises_process_error(
            1,
            "Wallet version upgrade cancelled before any change",
            node.cli("-named", "-interactive", f"-rpcwallet={legacy_name}", input="n\n").upgradewallet,
        )
        upgrade_result = node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input="y\n",
        ).upgradewallet()
        assert "current_version" in upgrade_result

        assert_raises_process_error(
            1,
            "Keypool regeneration cancelled before any change",
            node.cli("-named", "-interactive", f"-rpcwallet={legacy_name}", input="n\n").newkeypool,
        )
        node.cli(
            "-named",
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input="y\n",
        ).newkeypool()
        assert legacy_wallet.getnewaddress()
        keypool_target = legacy_wallet.getwalletinfo()["keypoolsize"] + 1
        assert_raises_process_error(
            1,
            "Keypool refill cancelled before any change",
            node.cli("-interactive", f"-rpcwallet={legacy_name}", input="n\n").keypoolrefill,
            newsize=keypool_target,
        )
        node.cli(
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input="y\n",
        ).keypoolrefill(newsize=keypool_target)
        assert_greater_than_or_equal(legacy_wallet.getwalletinfo()["keypoolsize"], keypool_target)

        multisig_key_1, multisig_pubkey_1 = generate_keypair(wif=True)
        multisig_key_2, multisig_pubkey_2 = generate_keypair(wif=True)
        del multisig_key_1, multisig_key_2
        multisig_pubkey_1 = multisig_pubkey_1.hex()
        multisig_pubkey_2 = multisig_pubkey_2.hex()
        assert_raises_process_error(
            1,
            "Multisignature-address creation cancelled before any wallet change",
            node.cli("-interactive", f"-rpcwallet={legacy_name}", input="n\n").addmultisigaddress,
            nrequired=1,
            keys=[multisig_pubkey_1, multisig_pubkey_2],
        )
        multisig = node.cli(
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input="y\n",
        ).addmultisigaddress(nrequired=1, keys=[multisig_pubkey_1, multisig_pubkey_2])
        assert multisig["address"]

        _, watch_address_pubkey = generate_keypair(wif=True)
        watch_address = key_to_p2pkh(watch_address_pubkey)
        assert_raises_process_error(
            1,
            "Watch-only address import cancelled before any wallet change",
            node.cli("-interactive", f"-rpcwallet={legacy_name}", input="n\n").importaddress,
            address=watch_address,
            rescan=False,
        )
        node.cli(
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input="y\n",
        ).importaddress(address=watch_address, rescan=False)
        assert_equal(legacy_wallet.getaddressinfo(watch_address)["iswatchonly"], True)

        _, watch_pubkey = generate_keypair(wif=True)
        watch_pubkey_address = key_to_p2pkh(watch_pubkey)
        watch_pubkey = watch_pubkey.hex()
        assert_raises_process_error(
            1,
            "Public-key import cancelled before any wallet change",
            node.cli("-interactive", f"-rpcwallet={legacy_name}", input="n\n").importpubkey,
            pubkey=watch_pubkey,
            rescan=False,
        )
        node.cli(
            "-interactive",
            f"-rpcwallet={legacy_name}",
            input="y\n",
        ).importpubkey(pubkey=watch_pubkey, rescan=False)
        assert_equal(legacy_wallet.getaddressinfo(watch_pubkey_address)["iswatchonly"], True)
        legacy_wallet.unloadwallet()

    def run_test(self):
        """Main test logic"""
        self.generate(self.nodes[0], BLOCKS)

        self.log.info("Compare responses from getblockchaininfo RPC and `nito-cli getblockchaininfo`")
        cli_response = self.nodes[0].cli.getblockchaininfo()
        rpc_response = self.nodes[0].getblockchaininfo()
        assert_equal(cli_response, rpc_response)

        self.log.info("Test named arguments")
        assert_equal(self.nodes[0].cli.echo(0, 1, arg3=3, arg5=5), ['0', '1', None, '3', None, '5'])
        assert_raises_rpc_error(-8, "Parameter arg1 specified twice both as positional and named argument", self.nodes[0].cli.echo, 0, 1, arg1=1)
        assert_raises_rpc_error(-8, "Parameter arg1 specified twice both as positional and named argument", self.nodes[0].cli.echo, 0, None, 2, arg1=1)

        self.log.info("Test that later cli named arguments values silently overwrite earlier ones")
        assert_equal(self.nodes[0].cli("-named", "echo", "arg0=0", "arg1=1", "arg2=2", "arg1=3").send_cli(), ['0', '3', '2'])
        assert_raises_rpc_error(-8, "Parameter args specified multiple times", self.nodes[0].cli("-named", "echo", "args=[0,1,2,3]", "4", "5", "6", ).send_cli)

        user, password = get_auth_cookie(self.nodes[0].datadir_path, self.chain)

        self.log.info("Test -stdinrpcpass option")
        assert_equal(BLOCKS, self.nodes[0].cli(f'-rpcuser={user}', '-stdinrpcpass', input=password).getblockcount())
        assert_raises_process_error(1, 'Incorrect rpcuser or rpcpassword', self.nodes[0].cli(f'-rpcuser={user}', '-stdinrpcpass', input='foo').echo)

        self.log.info("Test -stdin and -stdinrpcpass")
        assert_equal(['foo', 'bar'], self.nodes[0].cli(f'-rpcuser={user}', '-stdin', '-stdinrpcpass', input=f'{password}\nfoo\nbar').echo())
        assert_raises_process_error(1, 'Incorrect rpcuser or rpcpassword', self.nodes[0].cli(f'-rpcuser={user}', '-stdin', '-stdinrpcpass', input='foo').echo)

        if self.is_specified_wallet_compiled():
            self.log.info("Test a BIP39 passphrase can be supplied as a named stdin argument")
            result = self.nodes[0].cli(
                '-stdin',
                input='bip39_passphrase=TREZOR\n',
            ).createwallet(wallet_name='cli_bip39_stdin', descriptors=True)
            assert_equal(result['name'], 'cli_bip39_stdin')
            cli_bip39_wallet = self.nodes[0].get_wallet_rpc('cli_bip39_stdin')
            assert_equal(cli_bip39_wallet.getwalletinfo()['bip39_passphrase_enabled'], True)
            assert_equal(cli_bip39_wallet.dumpmnemonic()['bip39_passphrase_required'], True)
            cli_bip39_wallet.unloadwallet()

            self.log.info("Test interactive wallet creation covers all protection combinations")
            result = self.nodes[0].cli(
                '-interactive',
                input=' NO \n N \n',
            ).createwallet(wallet_name='cli_interactive_plain', descriptors=True)
            assert_equal(result['name'], 'cli_interactive_plain')
            plain_wallet = self.nodes[0].get_wallet_rpc('cli_interactive_plain')
            assert_equal(plain_wallet.getwalletinfo()['bip39_passphrase_enabled'], False)
            assert_equal(plain_wallet.dumpmnemonic()['bip39_passphrase_required'], False)
            plain_wallet.unloadwallet()

            result = self.nodes[0].cli(
                '-interactive',
                input='y\nwallet secret\nwallet secret\nn\n',
            ).createwallet(wallet_name='cli_interactive_encrypted', descriptors=True)
            assert_equal(result['name'], 'cli_interactive_encrypted')
            encrypted_wallet = self.nodes[0].get_wallet_rpc('cli_interactive_encrypted')
            assert_equal(encrypted_wallet.getwalletinfo()['bip39_passphrase_enabled'], False)
            encrypted_wallet.walletpassphrase('wallet secret', 60)
            assert_equal(encrypted_wallet.dumpmnemonic()['bip39_passphrase_required'], False)
            encrypted_wallet.walletlock()
            encrypted_wallet.unloadwallet()

            result = self.nodes[0].cli(
                '-interactive',
                input='n\ny\nBIP39 secret\nBIP39 secret\n',
            ).createwallet(wallet_name='cli_interactive_bip39', descriptors=True)
            assert_equal(result['name'], 'cli_interactive_bip39')
            bip39_wallet = self.nodes[0].get_wallet_rpc('cli_interactive_bip39')
            assert_equal(bip39_wallet.getwalletinfo()['bip39_passphrase_enabled'], True)
            assert_equal(bip39_wallet.dumpmnemonic()['bip39_passphrase_required'], True)
            bip39_wallet.unloadwallet()

            result = self.nodes[0].cli(
                '-interactive',
                input='y\nwallet secret\nwallet secret\ny\nBIP39 secret\nBIP39 secret\n',
            ).createwallet(wallet_name='cli_bip39_interactive', descriptors=True)
            assert_equal(result['name'], 'cli_bip39_interactive')
            interactive_wallet = self.nodes[0].get_wallet_rpc('cli_bip39_interactive')
            assert_equal(interactive_wallet.getwalletinfo()['bip39_passphrase_enabled'], True)
            interactive_wallet.walletpassphrase('wallet secret', 60)
            assert_equal(interactive_wallet.dumpmnemonic()['bip39_passphrase_required'], True)
            interactive_wallet.walletlock()
            interactive_wallet.unloadwallet()

            result = self.nodes[0].cli(
                '-interactive',
                input='invalid\nn\nn\n',
            ).createwallet(wallet_name='cli_interactive_choice_retry', descriptors=True)
            assert_equal(result['name'], 'cli_interactive_choice_retry')
            self.nodes[0].get_wallet_rpc('cli_interactive_choice_retry').unloadwallet()

            self.log.info("Test interactive wallet creation rejects missing and mismatched secrets")
            assert_raises_process_error(
                1,
                'Wallet encryption passphrase must not be empty when encryption is selected',
                self.nodes[0].cli('-interactive', input='y\n\n\n').createwallet,
                wallet_name='cli_interactive_empty',
                descriptors=True,
            )
            assert_raises_process_error(
                1,
                'Wallet encryption passphrases do not match',
                self.nodes[0].cli('-interactive', input='y\nfirst\nsecond\n').createwallet,
                wallet_name='cli_interactive_mismatch',
                descriptors=True,
            )
            assert_raises_process_error(
                1,
                'BIP39 passphrases do not match',
                self.nodes[0].cli('-interactive', input='n\ny\nfirst\nsecond\n').createwallet,
                wallet_name='cli_interactive_bip39_mismatch',
                descriptors=True,
            )
            assert_raises_process_error(
                1,
                'BIP39 passphrase must not be empty when BIP39 protection is selected',
                self.nodes[0].cli('-interactive', input='n\ny\n\n\n').createwallet,
                wallet_name='cli_interactive_bip39_empty',
                descriptors=True,
            )
            assert_raises_process_error(
                1,
                '-interactive cannot be combined with -stdin or -stdinwalletpassphrase',
                self.nodes[0].cli('-interactive', '-stdin', input='').createwallet,
                wallet_name='cli_interactive_conflict',
                descriptors=True,
            )
            assert_raises_process_error(
                1,
                'Do not provide passphrase on the command line with -interactive',
                self.nodes[0].cli('-interactive', input='').createwallet,
                wallet_name='cli_interactive_exposed_secret',
                descriptors=True,
                passphrase='must-not-be-accepted',
            )
            assert_raises_process_error(
                1,
                'Do not provide bip39_passphrase on the command line with -interactive',
                self.nodes[0].cli('-interactive', input='').createwallet,
                wallet_name='cli_interactive_exposed_bip39',
                descriptors=True,
                bip39_passphrase='must-not-be-accepted',
            )
            assert_raises_process_error(
                1,
                '-interactive failed to read from standard input',
                self.nodes[0].cli('-interactive', input='').createwallet,
                wallet_name='cli_interactive_missing',
                descriptors=True,
            )

            wallets_on_disk = {entry['name'] for entry in self.nodes[0].listwalletdir()['wallets']}
            for rejected_name in (
                'cli_interactive_empty',
                'cli_interactive_mismatch',
                'cli_interactive_bip39_mismatch',
                'cli_interactive_bip39_empty',
                'cli_interactive_conflict',
                'cli_interactive_exposed_secret',
                'cli_interactive_exposed_bip39',
                'cli_interactive_missing',
            ):
                assert rejected_name not in wallets_on_disk

            if os.name == 'posix':
                self.log.info("Test interactive prompts, no echo, and terminal restoration through a PTY")
                wallet_secret = 'pty wallet secret'
                bip39_secret = 'pty BIP39 secret'
                returncode, transcript, initial_echo, final_echo = run_cli_pty(
                    self.nodes[0].cli.binary,
                    self.nodes[0].datadir_path,
                    [
                        '-named',
                        '-interactive',
                        'createwallet',
                        'wallet_name=cli_bip39_interactive_pty',
                        'descriptors=true',
                    ],
                    [
                        ('Encrypt wallet.dat with a passphrase? [y/N] ', 'y'),
                        ('Wallet encryption passphrase> ', wallet_secret),
                        ('Confirm wallet encryption passphrase> ', wallet_secret),
                        ('Protect the recovery phrase with a BIP39 passphrase? [y/N] ', 'y'),
                        ('BIP39 passphrase (distinct and never stored)> ', bip39_secret),
                        ('Confirm BIP39 passphrase> ', bip39_secret),
                    ],
                )
                assert_equal(returncode, 0)
                assert '"name": "cli_bip39_interactive_pty"' in transcript
                assert wallet_secret not in transcript
                assert bip39_secret not in transcript
                assert_equal(initial_echo, True)
                assert_equal(final_echo, True)
                self.nodes[0].get_wallet_rpc('cli_bip39_interactive_pty').unloadwallet()

                mismatch_secret = 'pty mismatch secret'
                returncode, transcript, initial_echo, final_echo = run_cli_pty(
                    self.nodes[0].cli.binary,
                    self.nodes[0].datadir_path,
                    [
                        '-named',
                        '-interactive',
                        'createwallet',
                        'wallet_name=cli_interactive_pty_mismatch',
                        'descriptors=true',
                    ],
                    [
                        ('Encrypt wallet.dat with a passphrase? [y/N] ', 'y'),
                        ('Wallet encryption passphrase> ', mismatch_secret),
                        ('Confirm wallet encryption passphrase> ', 'different confirmation'),
                    ],
                )
                assert_equal(returncode, 1)
                assert 'Wallet encryption passphrases do not match' in transcript
                assert mismatch_secret not in transcript
                assert_equal(initial_echo, True)
                assert_equal(final_echo, True)

                returncode, transcript, initial_echo, final_echo = run_cli_pty(
                    self.nodes[0].cli.binary,
                    self.nodes[0].datadir_path,
                    [
                        '-named',
                        '-interactive',
                        'createwallet',
                        'wallet_name=cli_interactive_interrupted',
                        'descriptors=true',
                    ],
                    [
                        ('Encrypt wallet.dat with a passphrase? [y/N] ', 'y'),
                        ('Wallet encryption passphrase> ', None),
                    ],
                )
                assert_equal(returncode, -signal.SIGINT)
                assert_equal(initial_echo, True)
                assert_equal(final_echo, True)

                returncode, transcript, initial_echo, final_echo = run_cli_pty(
                    self.nodes[0].cli.binary,
                    self.nodes[0].datadir_path,
                    [
                        '-rpcport=1',
                        '-named',
                        '-interactive',
                        'createwallet',
                        'wallet_name=cli_interactive_unreachable',
                        'descriptors=true',
                    ],
                    [],
                )
                assert_equal(returncode, 1)
                assert 'Could not connect to the server' in transcript
                assert 'Encrypt wallet.dat with a passphrase?' not in transcript
                assert 'Wallet encryption passphrase>' not in transcript
                assert_equal(initial_echo, True)
                assert_equal(final_echo, True)

            self.test_interactive_wallet_management()
            self.test_interactive_private_material()
            self.test_interactive_extended_sensitive_operations()

        self.log.info("Test interactive mode rejects unsupported commands")
        assert_raises_process_error(
            1,
            '-interactive requires -named and a supported RPC',
            self.nodes[0].cli('-interactive', input='').getblockcount,
        )
        assert_raises_process_error(
            1,
            '-interactive requires -named and a supported RPC',
            self.nodes[0].cli('-interactive', input='').createwallet,
            'cli_interactive_without_named',
        )
        assert_raises_process_error(
            1,
            '-interactive is not supported for this RPC; use it only with a documented sensitive or high-impact RPC',
            self.nodes[0].cli('-named', '-interactive', input='').getblockcount,
        )

        self.log.info("Test connecting to a non-existing server")
        assert_raises_process_error(1, "Could not connect to the server", self.nodes[0].cli('-rpcport=1').echo)

        self.log.info("Test connecting with non-existing RPC cookie file")
        assert_raises_process_error(1, "Could not locate RPC credentials", self.nodes[0].cli('-rpccookiefile=does-not-exist', '-rpcpassword=').echo)

        self.log.info("Test -getinfo with arguments fails")
        assert_raises_process_error(1, "-getinfo takes no arguments", self.nodes[0].cli('-getinfo').help)

        self.log.info("Test -getinfo with -color=never does not return ANSI escape codes")
        assert "\u001b[0m" not in self.nodes[0].cli('-getinfo', '-color=never').send_cli()

        self.log.info("Test -getinfo with -color=always returns ANSI escape codes")
        assert "\u001b[0m" in self.nodes[0].cli('-getinfo', '-color=always').send_cli()

        self.log.info("Test -getinfo with invalid value for -color option")
        assert_raises_process_error(1, "Invalid value for -color option. Valid values: always, auto, never.", self.nodes[0].cli('-getinfo', '-color=foo').send_cli)

        self.log.info("Test -getinfo returns expected network and blockchain info")
        if self.is_specified_wallet_compiled():
            self.import_deterministic_coinbase_privkeys()
            initial_wallet_balance = self.nodes[0].getbalance()
            self.nodes[0].encryptwallet(password)
        cli_get_info_string = self.nodes[0].cli('-getinfo').send_cli()
        cli_get_info = cli_get_info_string_to_dict(cli_get_info_string)

        network_info = self.nodes[0].getnetworkinfo()
        blockchain_info = self.nodes[0].getblockchaininfo()
        assert_equal(int(cli_get_info['Version']), network_info['version'])
        assert_equal(cli_get_info['Verification progress'], "%.4f%%" % (blockchain_info['verificationprogress'] * 100))
        assert_equal(int(cli_get_info['Blocks']), blockchain_info['blocks'])
        assert_equal(int(cli_get_info['Headers']), blockchain_info['headers'])
        assert_equal(int(cli_get_info['Time offset (s)']), network_info['timeoffset'])
        expected_network_info = f"in {network_info['connections_in']}, out {network_info['connections_out']}, total {network_info['connections']}"
        assert_equal(cli_get_info["Network"], expected_network_info)
        assert_equal(cli_get_info['Proxies'], network_info['networks'][0]['proxy'])
        assert_equal(Decimal(cli_get_info['Difficulty']), blockchain_info['difficulty'])
        assert_equal(cli_get_info['Chain'], blockchain_info['chain'])

        self.log.info("Test -getinfo and nito-cli return all proxies")
        self.restart_node(0, extra_args=["-proxy=127.0.0.1:9050", "-i2psam=127.0.0.1:7656"])
        network_info = self.nodes[0].getnetworkinfo()
        cli_get_info_string = self.nodes[0].cli('-getinfo').send_cli()
        cli_get_info = cli_get_info_string_to_dict(cli_get_info_string)
        assert_equal(cli_get_info["Proxies"], "127.0.0.1:9050 (ipv4, ipv6, onion, cjdns), 127.0.0.1:7656 (i2p)")

        if self.is_specified_wallet_compiled():
            self.log.info("Test -getinfo and nito-cli getwalletinfo return expected wallet info")
            # Explicitly set the output type in order to have consistent tx vsize / fees
            # for both legacy and descriptor wallets (disables the change address type detection algorithm)
            self.restart_node(0, extra_args=["-addresstype=bech32", "-changetype=bech32"])
            assert_equal(Decimal(cli_get_info['Balance']), initial_wallet_balance)
            assert 'Balances' not in cli_get_info_string
            wallet_info = self.nodes[0].getwalletinfo()
            assert_equal(int(cli_get_info['Keypool size']), wallet_info['keypoolsize'])
            assert_equal(int(cli_get_info['Unlocked until']), wallet_info['unlocked_until'])
            assert_equal(Decimal(cli_get_info['Transaction fee rate (-paytxfee) (NITO/kvB)']), wallet_info['paytxfee'])
            assert_equal(Decimal(cli_get_info['Min tx relay fee rate (NITO/kvB)']), network_info['relayfee'])
            assert_equal(self.nodes[0].cli.getwalletinfo(), wallet_info)

            # Setup to test -getinfo, -generate, and -rpcwallet= with multiple wallets.
            wallets = [self.default_wallet_name, 'Encrypted', 'secret']
            transfer_amounts = [Decimal(9), Decimal(31)]
            self.nodes[0].createwallet(wallet_name=wallets[1])
            self.nodes[0].createwallet(wallet_name=wallets[2])
            w1 = self.nodes[0].get_wallet_rpc(wallets[0])
            w2 = self.nodes[0].get_wallet_rpc(wallets[1])
            w3 = self.nodes[0].get_wallet_rpc(wallets[2])
            rpcwallet2 = f'-rpcwallet={wallets[1]}'
            rpcwallet3 = f'-rpcwallet={wallets[2]}'
            w1.walletpassphrase(password, self.rpc_timeout)
            w2.encryptwallet(password)
            w1.sendtoaddress(w2.getnewaddress(), transfer_amounts[0])
            w1.sendtoaddress(w3.getnewaddress(), transfer_amounts[1])

            # Mine a block to confirm the transfers, then record the actual balances.
            self.generate(self.nodes[0], 1)
            amounts = [w1.getbalance(), w2.getbalance(), w3.getbalance()]

            self.log.info("Test -getinfo with multiple wallets and -rpcwallet returns specified wallet balance")
            for i in range(len(wallets)):
                cli_get_info_string = self.nodes[0].cli('-getinfo', f'-rpcwallet={wallets[i]}').send_cli()
                cli_get_info = cli_get_info_string_to_dict(cli_get_info_string)
                assert 'Balances' not in cli_get_info_string
                assert_equal(cli_get_info["Wallet"], wallets[i])
                assert_equal(Decimal(cli_get_info['Balance']), amounts[i])

            self.log.info("Test -getinfo with multiple wallets and -rpcwallet=non-existing-wallet returns no balances")
            cli_get_info_string = self.nodes[0].cli('-getinfo', '-rpcwallet=does-not-exist').send_cli()
            assert 'Balance' not in cli_get_info_string
            assert 'Balances' not in cli_get_info_string

            self.log.info("Test -getinfo with multiple wallets returns all loaded wallet names and balances")
            assert_equal(set(self.nodes[0].listwallets()), set(wallets))
            cli_get_info_string = self.nodes[0].cli('-getinfo').send_cli()
            cli_get_info = cli_get_info_string_to_dict(cli_get_info_string)
            assert 'Balance' not in cli_get_info
            for k, v in zip(wallets, amounts):
                assert_equal(Decimal(cli_get_info['Balances'][k]), v)

            # Unload the default wallet and re-verify.
            self.nodes[0].unloadwallet(wallets[0])
            assert wallets[0] not in self.nodes[0].listwallets()
            cli_get_info_string = self.nodes[0].cli('-getinfo').send_cli()
            cli_get_info = cli_get_info_string_to_dict(cli_get_info_string)
            assert 'Balance' not in cli_get_info
            assert 'Balances' in cli_get_info_string
            for k, v in zip(wallets[1:], amounts[1:]):
                assert_equal(Decimal(cli_get_info['Balances'][k]), v)
            assert wallets[0] not in cli_get_info

            self.log.info("Test -getinfo after unloading all wallets except a non-default one returns its balance")
            self.nodes[0].unloadwallet(wallets[2])
            assert_equal(self.nodes[0].listwallets(), [wallets[1]])
            cli_get_info_string = self.nodes[0].cli('-getinfo').send_cli()
            cli_get_info = cli_get_info_string_to_dict(cli_get_info_string)
            assert 'Balances' not in cli_get_info_string
            assert_equal(cli_get_info['Wallet'], wallets[1])
            assert_equal(Decimal(cli_get_info['Balance']), amounts[1])

            self.log.info("Test -getinfo with -rpcwallet=remaining-non-default-wallet returns only its balance")
            cli_get_info_string = self.nodes[0].cli('-getinfo', rpcwallet2).send_cli()
            cli_get_info = cli_get_info_string_to_dict(cli_get_info_string)
            assert 'Balances' not in cli_get_info_string
            assert_equal(cli_get_info['Wallet'], wallets[1])
            assert_equal(Decimal(cli_get_info['Balance']), amounts[1])

            self.log.info("Test -getinfo with -rpcwallet=unloaded wallet returns no balances")
            cli_get_info_string = self.nodes[0].cli('-getinfo', rpcwallet3).send_cli()
            cli_get_info_keys = cli_get_info_string_to_dict(cli_get_info_string)
            assert 'Balance' not in cli_get_info_keys
            assert 'Balances' not in cli_get_info_string

            # Test nito-cli -generate.
            n1 = 3
            n2 = 4
            w2.walletpassphrase(password, self.rpc_timeout)
            blocks = self.nodes[0].getblockcount()

            self.log.info('Test -generate with no args')
            generate = self.nodes[0].cli('-generate').send_cli()
            assert_equal(set(generate.keys()), {'address', 'blocks'})
            assert_equal(len(generate["blocks"]), 1)
            assert_equal(self.nodes[0].getblockcount(), blocks + 1)

            self.log.info('Test -generate with bad args')
            assert_raises_process_error(1, JSON_PARSING_ERROR, self.nodes[0].cli('-generate', 'foo').echo)
            assert_raises_process_error(1, BLOCKS_VALUE_OF_ZERO, self.nodes[0].cli('-generate', 0).echo)
            assert_raises_process_error(1, TOO_MANY_ARGS, self.nodes[0].cli('-generate', 1, 2, 3).echo)

            self.log.info('Test -generate with nblocks')
            generate = self.nodes[0].cli('-generate', n1).send_cli()
            assert_equal(set(generate.keys()), {'address', 'blocks'})
            assert_equal(len(generate["blocks"]), n1)
            assert_equal(self.nodes[0].getblockcount(), blocks + 1 + n1)

            self.log.info('Test -generate with nblocks and maxtries')
            generate = self.nodes[0].cli('-generate', n2, 1000000).send_cli()
            assert_equal(set(generate.keys()), {'address', 'blocks'})
            assert_equal(len(generate["blocks"]), n2)
            assert_equal(self.nodes[0].getblockcount(), blocks + 1 + n1 + n2)

            self.log.info('Test -generate -rpcwallet in single-wallet mode')
            generate = self.nodes[0].cli(rpcwallet2, '-generate').send_cli()
            assert_equal(set(generate.keys()), {'address', 'blocks'})
            assert_equal(len(generate["blocks"]), 1)
            assert_equal(self.nodes[0].getblockcount(), blocks + 2 + n1 + n2)

            self.log.info('Test -generate -rpcwallet=unloaded wallet raises RPC error')
            assert_raises_rpc_error(-18, WALLET_NOT_LOADED, self.nodes[0].cli(rpcwallet3, '-generate').echo)
            assert_raises_rpc_error(-18, WALLET_NOT_LOADED, self.nodes[0].cli(rpcwallet3, '-generate', 'foo').echo)
            assert_raises_rpc_error(-18, WALLET_NOT_LOADED, self.nodes[0].cli(rpcwallet3, '-generate', 0).echo)
            assert_raises_rpc_error(-18, WALLET_NOT_LOADED, self.nodes[0].cli(rpcwallet3, '-generate', 1, 2, 3).echo)

            # Test nito-cli -generate with -rpcwallet in multiwallet mode.
            self.nodes[0].loadwallet(wallets[2])
            n3 = 4
            n4 = 10
            blocks = self.nodes[0].getblockcount()

            self.log.info('Test -generate -rpcwallet with no args')
            generate = self.nodes[0].cli(rpcwallet2, '-generate').send_cli()
            assert_equal(set(generate.keys()), {'address', 'blocks'})
            assert_equal(len(generate["blocks"]), 1)
            assert_equal(self.nodes[0].getblockcount(), blocks + 1)

            self.log.info('Test -generate -rpcwallet with bad args')
            assert_raises_process_error(1, JSON_PARSING_ERROR, self.nodes[0].cli(rpcwallet2, '-generate', 'foo').echo)
            assert_raises_process_error(1, BLOCKS_VALUE_OF_ZERO, self.nodes[0].cli(rpcwallet2, '-generate', 0).echo)
            assert_raises_process_error(1, TOO_MANY_ARGS, self.nodes[0].cli(rpcwallet2, '-generate', 1, 2, 3).echo)

            self.log.info('Test -generate -rpcwallet with nblocks')
            generate = self.nodes[0].cli(rpcwallet2, '-generate', n3).send_cli()
            assert_equal(set(generate.keys()), {'address', 'blocks'})
            assert_equal(len(generate["blocks"]), n3)
            assert_equal(self.nodes[0].getblockcount(), blocks + 1 + n3)

            self.log.info('Test -generate -rpcwallet with nblocks and maxtries')
            generate = self.nodes[0].cli(rpcwallet2, '-generate', n4, 1000000).send_cli()
            assert_equal(set(generate.keys()), {'address', 'blocks'})
            assert_equal(len(generate["blocks"]), n4)
            assert_equal(self.nodes[0].getblockcount(), blocks + 1 + n3 + n4)

            self.log.info('Test -generate without -rpcwallet in multiwallet mode raises RPC error')
            assert_raises_rpc_error(-19, WALLET_NOT_SPECIFIED, self.nodes[0].cli('-generate').echo)
            assert_raises_rpc_error(-19, WALLET_NOT_SPECIFIED, self.nodes[0].cli('-generate', 'foo').echo)
            assert_raises_rpc_error(-19, WALLET_NOT_SPECIFIED, self.nodes[0].cli('-generate', 0).echo)
            assert_raises_rpc_error(-19, WALLET_NOT_SPECIFIED, self.nodes[0].cli('-generate', 1, 2, 3).echo)
        else:
            self.log.info("*** Wallet not compiled; cli getwalletinfo and -getinfo wallet tests skipped")
            self.generate(self.nodes[0], 25)  # maintain block parity with the wallet_compiled conditional branch

        expected_blocks_after_cli_tests = self.nodes[0].getblockcount()
        self.log.info("Test -version with node stopped")
        self.stop_node(0)
        cli_response = self.nodes[0].cli('-version').send_cli()
        assert f"{self.config['environment']['PACKAGE_NAME']} RPC client version" in cli_response

        self.log.info("Test -rpcwait option successfully waits for RPC connection")
        self.nodes[0].start()  # start node without RPC connection
        self.nodes[0].wait_for_cookie_credentials()  # ensure cookie file is available to avoid race condition
        blocks = self.nodes[0].cli('-rpcwait').send_cli('getblockcount')
        self.nodes[0].wait_for_rpc_connection()
        assert_equal(blocks, expected_blocks_after_cli_tests)

        self.log.info("Test -rpcwait option waits at most -rpcwaittimeout seconds for startup")
        self.stop_node(0)  # stop the node so we time out
        start_time = time.monotonic()
        assert_raises_process_error(1, "Could not connect to the server", self.nodes[0].cli('-rpcwait', '-rpcwaittimeout=5').echo)
        assert_greater_than_or_equal(time.monotonic(), start_time + 5)


if __name__ == '__main__':
    TestNitoCli().main()
