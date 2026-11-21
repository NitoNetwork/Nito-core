#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

'''
This checks if all command line args are documented.
Return value is 0 to indicate no error.

Author: @MarcoFalke
'''

from pathlib import Path
import re
from subprocess import PIPE, run

FOLDER_GREP = 'src'
FOLDER_TEST = 'src/test/'
REGEX_ARG = r'\b(?:GetArg|GetArgs|GetBoolArg|GetIntArg|GetPathArg|IsArgSet|get_net)\("(-[^"]+)"'
REGEX_DOC = r'AddArg\("(-[^"=]+?)(?:=|")'
ROOT = Path(__file__).resolve().parents[2]
# List intentionally hidden, unsupported, deprecated and duplicate arguments
# that do not belong in the generated command-line help.
SET_DOC_OPTIONAL = set([
    '-h', '-help', '-dbcrashratio', '-forcecompactdb',
    '-qtkeepwalletsclosed',
])


def git_grep(*args):
    result = run(
        ['git', 'grep', *args], cwd=ROOT, stdout=PIPE, stderr=PIPE,
        check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.decode('utf8'))
    return result.stdout.decode('utf8').strip()


def lint_missing_argument_documentation():
    used = git_grep(
        '--perl-regexp', REGEX_ARG, '--', FOLDER_GREP,
        ':(exclude){}'.format(FOLDER_TEST))
    docd = git_grep('--perl-regexp', REGEX_DOC, '--', FOLDER_GREP)

    args_used = set(re.findall(re.compile(REGEX_ARG), used))
    args_docd = set(re.findall(re.compile(REGEX_DOC), docd)).union(SET_DOC_OPTIONAL)
    args_need_doc = args_used.difference(args_docd)
    args_unknown = args_docd.difference(args_used)

    print("Args used        : {}".format(len(args_used)))
    print("Args documented  : {}".format(len(args_docd)))
    print("Args undocumented: {}".format(len(args_need_doc)))
    print(args_need_doc)
    print("Args unknown     : {}".format(len(args_unknown)))
    print(args_unknown)

    assert 0 == len(args_need_doc), "Please document the following arguments: {}".format(args_need_doc)


def lint_missing_hidden_wallet_args():
    wallet_args = git_grep(
        '--function-context', 'void WalletInit::AddWalletOptions', '--',
        FOLDER_GREP)
    wallet_args = '\n'.join(
        line for line in wallet_args.splitlines() if 'AddArg' in line)
    wallet_hidden_args = git_grep(
        '--function-context', 'void DummyWalletInit::AddWalletOptions', '--',
        FOLDER_GREP)

    wallet_args = set(re.findall(re.compile(REGEX_DOC), wallet_args))
    wallet_hidden_args = set(re.findall(re.compile(r'    "([^"=]+)'), wallet_hidden_args))

    hidden_missing = wallet_args.difference(wallet_hidden_args)
    if hidden_missing:
        assert 0, "Please add {} to the hidden args in DummyWalletInit::AddWalletOptions".format(hidden_missing)


def main():
    lint_missing_argument_documentation()
    lint_missing_hidden_wallet_args()


if __name__ == "__main__":
    main()
