// Copyright (c) 2018-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/stdin.h>

#include <cstdio>

#ifdef WIN32
#include <windows.h>
#include <io.h>
#else
#include <array>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <poll.h>
#endif

// https://stackoverflow.com/questions/1413445/reading-a-password-from-stdcin
void SetStdinEcho(bool enable)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    if (!enable) {
        mode &= ~ENABLE_ECHO_INPUT;
    } else {
        mode |= ENABLE_ECHO_INPUT;
    }
    SetConsoleMode(hStdin, mode);
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

bool GetStdinEcho()
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode{0};
    return GetConsoleMode(hStdin, &mode) && (mode & ENABLE_ECHO_INPUT) != 0;
#else
    struct termios tty;
    return tcgetattr(STDIN_FILENO, &tty) == 0 && (tty.c_lflag & ECHO) != 0;
#endif
}

namespace {

#ifdef WIN32
volatile LONG g_noecho_handler_active{0};
volatile LONG g_noecho_restore_enabled{0};

BOOL WINAPI NoechoConsoleCtrlHandler(DWORD)
{
    if (InterlockedCompareExchange(&g_noecho_handler_active, 0, 1) == 1) {
        SetStdinEcho(InterlockedCompareExchange(&g_noecho_restore_enabled, 0, 0) != 0);
    }
    return FALSE;
}

bool InstallNoechoSignalHandlers(bool echo_enabled)
{
    if (InterlockedCompareExchange(&g_noecho_handler_active, 1, 0) != 0) return false;
    InterlockedExchange(&g_noecho_restore_enabled, echo_enabled ? 1 : 0);
    if (!SetConsoleCtrlHandler(NoechoConsoleCtrlHandler, TRUE)) {
        InterlockedExchange(&g_noecho_handler_active, 0);
        return false;
    }
    return true;
}

void RemoveNoechoSignalHandlers()
{
    InterlockedExchange(&g_noecho_handler_active, 0);
    SetConsoleCtrlHandler(NoechoConsoleCtrlHandler, FALSE);
}
#else
constexpr std::array<int, 4> NOECHO_SIGNALS{SIGINT, SIGTERM, SIGHUP, SIGQUIT};
std::array<struct sigaction, NOECHO_SIGNALS.size()> g_noecho_previous_actions{};
std::array<bool, NOECHO_SIGNALS.size()> g_noecho_action_installed{};
volatile sig_atomic_t g_noecho_handler_active{0};
volatile sig_atomic_t g_noecho_restore_enabled{0};

void NoechoSignalHandler(int signal)
{
    if (g_noecho_handler_active != 0) {
        SetStdinEcho(g_noecho_restore_enabled != 0);
    }
    for (std::size_t index = 0; index < NOECHO_SIGNALS.size(); ++index) {
        if (g_noecho_action_installed[index]) {
            sigaction(NOECHO_SIGNALS[index], &g_noecho_previous_actions[index], nullptr);
        }
    }
    g_noecho_handler_active = 0;
    kill(getpid(), signal);
}

bool InstallNoechoSignalHandlers(bool echo_enabled)
{
    if (g_noecho_handler_active != 0) return false;
    g_noecho_restore_enabled = echo_enabled ? 1 : 0;
    g_noecho_handler_active = 1;

    struct sigaction action{};
    action.sa_handler = NoechoSignalHandler;
    sigemptyset(&action.sa_mask);
    for (const int signal : NOECHO_SIGNALS) sigaddset(&action.sa_mask, signal);

    bool installed{false};
    for (std::size_t index = 0; index < NOECHO_SIGNALS.size(); ++index) {
        const int signal{NOECHO_SIGNALS[index]};
        if (sigaction(signal, nullptr, &g_noecho_previous_actions[index]) != 0 ||
            g_noecho_previous_actions[index].sa_handler == SIG_IGN) {
            continue;
        }
        g_noecho_action_installed[index] = true;
        if (sigaction(signal, &action, nullptr) != 0) {
            g_noecho_action_installed[index] = false;
            continue;
        }
        installed = true;
    }
    if (!installed) g_noecho_handler_active = 0;
    return installed;
}

void RemoveNoechoSignalHandlers()
{
    for (std::size_t index = 0; index < NOECHO_SIGNALS.size(); ++index) {
        if (g_noecho_action_installed[index]) {
            sigaction(NOECHO_SIGNALS[index], &g_noecho_previous_actions[index], nullptr);
            g_noecho_action_installed[index] = false;
        }
    }
    g_noecho_handler_active = 0;
}
#endif

} // namespace

bool StdinTerminal()
{
#ifdef WIN32
    return _isatty(_fileno(stdin));
#else
    return isatty(fileno(stdin));
#endif
}

bool StdinReady()
{
    if (!StdinTerminal()) {
        return true;
    }
#ifdef WIN32
    return false;
#else
    struct pollfd fds;
    fds.fd = STDIN_FILENO;
    fds.events = POLLIN;
    return poll(&fds, 1, 0) == 1;
#endif
}

NoechoInst::NoechoInst()
    : m_terminal{StdinTerminal()},
      m_echo_enabled{m_terminal && GetStdinEcho()},
      m_signal_handlers_installed{m_terminal && InstallNoechoSignalHandlers(m_echo_enabled)}
{
    if (m_terminal) SetStdinEcho(false);
}

NoechoInst::~NoechoInst()
{
    if (!m_terminal) return;
    SetStdinEcho(m_echo_enabled);
    if (m_signal_handlers_installed) RemoveNoechoSignalHandlers();
}
