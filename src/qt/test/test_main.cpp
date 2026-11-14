// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/nito-config.h>
#endif

#include <interfaces/init.h>
#include <interfaces/node.h>
#include <qt/guiconstants.h>
#include <qt/nito.h>
#include <qt/test/apptests.h>
#include <qt/test/optiontests.h>
#include <qt/test/rpcnestedtests.h>
#include <qt/test/uritests.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#ifdef ENABLE_WALLET
#include <qt/test/addressbooktests.h>
#include <qt/test/wallettests.h>
#endif // ENABLE_WALLET

#include <QApplication>
#include <QDebug>
#include <QObject>
#include <QTest>

#include <cstdlib>
#include <functional>
#include <string>

#if defined(QT_STATICPLUGIN)
#include <QtPlugin>
#if defined(QT_QPA_PLATFORM_MINIMAL)
Q_IMPORT_PLUGIN(QMinimalIntegrationPlugin);
#endif
#if defined(QT_QPA_PLATFORM_XCB)
Q_IMPORT_PLUGIN(QXcbIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_WINDOWS)
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_COCOA)
Q_IMPORT_PLUGIN(QCocoaIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_ANDROID)
Q_IMPORT_PLUGIN(QAndroidPlatformIntegrationPlugin)
#endif
#endif

const std::function<void(const std::string&)> G_TEST_LOG_FUN{};

const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS{};

// This is all you need to run all the tests
int main(int argc, char* argv[])
{
    // Initialize persistent globals with the testing setup state for sanity.
    // E.g. -datadir in gArgs is set to a temp directory dummy value (instead
    // of defaulting to the default datadir), or globalChainParams is set to
    // regtest params.
    //
    // All tests must use their own testing setup (if needed).
    fs::create_directories([] {
        BasicTestingSetup dummy{ChainType::REGTEST};
        return gArgs.GetDataDirNet() / "blocks";
    }());

    std::unique_ptr<interfaces::Init> init = interfaces::MakeGuiInit(argc, argv);
    gArgs.ForceSetArg("-listen", "0");
    gArgs.ForceSetArg("-listenonion", "0");
    gArgs.ForceSetArg("-discover", "0");
    gArgs.ForceSetArg("-dnsseed", "0");
    gArgs.ForceSetArg("-fixedseeds", "0");
    gArgs.ForceSetArg("-upnp", "0");
    gArgs.ForceSetArg("-natpmp", "0");

    std::string error;
    if (!gArgs.ReadConfigFiles(error, true)) qWarning("%s", error.c_str());

    // Prefer the "minimal" platform for the test instead of the normal default
    // platform ("xcb", "windows", or "cocoa") so tests can't unintentionally
    // interfere with any background GUIs and don't require extra resources.
    #if defined(WIN32)
        if (getenv("QT_QPA_PLATFORM") == nullptr) _putenv_s("QT_QPA_PLATFORM", "minimal");
    #else
        setenv("QT_QPA_PLATFORM", "minimal", 0 /* overwrite */);
    #endif

    NitoApplication app;
    app.setOrganizationName(QAPP_ORG_NAME);
    app.setOrganizationDomain(QAPP_ORG_DOMAIN);
    app.setApplicationName("Nito-Qt-test");
    app.createNode(*init);

    int num_test_failures{0};
    const char* only_suite = std::getenv("NITO_QT_TEST_SUITE");
    auto run_test = [&](QObject& test, const char* suite_name) {
        if (only_suite && std::string{only_suite} != suite_name) return 0;
        return QTest::qExec(&test, argc, argv);
    };

    AppTests app_tests(app);
    num_test_failures += run_test(app_tests, "AppTests");

    OptionTests options_tests(app.node());
    num_test_failures += run_test(options_tests, "OptionTests");

    URITests test1;
    num_test_failures += run_test(test1, "URITests");

    RPCNestedTests test3(app.node());
    num_test_failures += run_test(test3, "RPCNestedTests");

#ifdef ENABLE_WALLET
    WalletTests test5(app.node());
    num_test_failures += run_test(test5, "WalletTests");

    AddressBookTests test6(app.node());
    num_test_failures += run_test(test6, "AddressBookTests");
#endif

    if (num_test_failures) {
        qWarning("\nFailed tests: %d\n", num_test_failures);
    } else {
        qDebug("\nAll tests passed.\n");
    }
    return num_test_failures;
}
