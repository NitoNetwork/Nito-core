// Copyright (c) 2018 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPAT_STDIN_H
#define BITCOIN_COMPAT_STDIN_H

struct NoechoInst {
    NoechoInst();
    ~NoechoInst();

    NoechoInst(const NoechoInst&) = delete;
    NoechoInst& operator=(const NoechoInst&) = delete;

private:
    bool m_terminal;
    bool m_echo_enabled;
    bool m_signal_handlers_installed;
};

#define NO_STDIN_ECHO() NoechoInst _no_echo

bool StdinTerminal();
bool StdinReady();

#endif // BITCOIN_COMPAT_STDIN_H
