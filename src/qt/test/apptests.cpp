// Copyright (c) 2018-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/apptests.h>

#include <chainparams.h>
#include <key.h>
#include <logging.h>
#include <qt/nito.h>
#include <qt/nitogui.h>
#include <qt/networkstyle.h>
#include <qt/rpcconsole.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <QAction>
#include <QByteArray>
#include <QColor>
#include <QLineEdit>
#include <QPalette>
#include <QPushButton>
#include <QRegularExpression>
#include <QScopedPointer>
#include <QSignalSpy>
#include <QStyleOptionButton>
#include <QString>
#include <QTest>
#include <QTextEdit>
#include <QtGlobal>
#include <QtTest/QtTestWidgets>
#include <QtTest/QtTestGui>

#include <algorithm>
#include <array>
#include <cmath>

namespace {
class ApplicationStyleRestorer
{
public:
    explicit ApplicationStyleRestorer(QApplication& app)
        : m_app{app}, m_palette{app.palette()}, m_style_sheet{app.styleSheet()}
    {
    }

    ~ApplicationStyleRestorer()
    {
        m_app.setStyleSheet(m_style_sheet);
        m_app.setPalette(m_palette);
    }

private:
    QApplication& m_app;
    const QPalette m_palette;
    const QString m_style_sheet;
};

double LinearizedColorChannel(double channel)
{
    return channel <= 0.04045 ? channel / 12.92 : std::pow((channel + 0.055) / 1.055, 2.4);
}

double RelativeLuminance(const QColor& color)
{
    return 0.2126 * LinearizedColorChannel(color.redF()) +
           0.7152 * LinearizedColorChannel(color.greenF()) +
           0.0722 * LinearizedColorChannel(color.blueF());
}

double ContrastRatio(const QColor& first, const QColor& second)
{
    const double first_luminance{RelativeLuminance(first)};
    const double second_luminance{RelativeLuminance(second)};
    const double lighter{std::max(first_luminance, second_luminance)};
    const double darker{std::min(first_luminance, second_luminance)};
    return (lighter + 0.05) / (darker + 0.05);
}

//! Regex find a string group inside of the console output
QString FindInConsole(const QString& output, const QString& pattern)
{
    const QRegularExpression re(pattern);
    return re.match(output).captured(1);
}

//! Call getblockchaininfo RPC and check first field of JSON output.
void TestRpcCommand(RPCConsole* console)
{
    QTextEdit* messagesWidget = console->findChild<QTextEdit*>("messagesWidget");
    QLineEdit* lineEdit = console->findChild<QLineEdit*>("lineEdit");
    QSignalSpy mw_spy(messagesWidget, &QTextEdit::textChanged);
    QVERIFY(mw_spy.isValid());
    QTest::keyClicks(lineEdit, "getblockchaininfo");
    QTest::keyClick(lineEdit, Qt::Key_Return);
    QVERIFY(mw_spy.wait(1000));
    QCOMPARE(mw_spy.count(), 4);
    const QString output = messagesWidget->toPlainText();
    const QString pattern = QStringLiteral("\"chain\": \"(\\w+)\"");
    QCOMPARE(FindInConsole(output, pattern), QString("regtest"));
}
} // namespace

//! Verify that Nito's light theme is independent of the system palette.
void AppTests::paletteTests()
{
    ApplicationStyleRestorer restore_style{m_app};

    // Reproduce the failure mode: a dark system theme supplies white text,
    // while Nito replaces the surfaces with light colors.
    QPalette hostile_palette{m_app.palette()};
    hostile_palette.setColor(QPalette::Window, QColor{"#101010"});
    hostile_palette.setColor(QPalette::Base, QColor{"#181818"});
    hostile_palette.setColor(QPalette::AlternateBase, QColor{"#202020"});
    hostile_palette.setColor(QPalette::Button, QColor{"#282828"});
    hostile_palette.setColor(QPalette::WindowText, QColor{"#ffffff"});
    hostile_palette.setColor(QPalette::Text, QColor{"#ffffff"});
    hostile_palette.setColor(QPalette::ButtonText, QColor{"#ffffff"});
    hostile_palette.setColor(QPalette::PlaceholderText, QColor{"#d0d0d0"});
    hostile_palette.setColor(QPalette::Link, QColor{"#7ab8ff"});
    hostile_palette.setColor(QPalette::LinkVisited, QColor{"#d0a0ff"});
    m_app.setStyleSheet(QString{});
    m_app.setPalette(hostile_palette);

    ApplyNitoAccentStyle(m_app);
    const QPalette palette{m_app.palette()};

    const QColor normal_text{"#102a43"};
    const QColor placeholder_text{"#52677a"};
    const QColor disabled_text{"#5b6f82"};
    const QColor disabled_button_background{"#edf3f9"};
    const QColor window{"#f3f8fd"};
    const QColor base{"#ffffff"};
    const QColor alternate_base{"#eaf4ff"};
    const QColor button{"#f8fbff"};
    const QColor link{"#006bbf"};
    const QColor visited_link{"#5b4bb7"};
    const QColor highlight{"#0073cf"};
    const QColor white{"#ffffff"};
    const QColor tooltip_base{"#0b1d2e"};

    for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive}) {
        QCOMPARE(palette.color(group, QPalette::WindowText), normal_text);
        QCOMPARE(palette.color(group, QPalette::Text), normal_text);
        QCOMPARE(palette.color(group, QPalette::ButtonText), normal_text);
        QCOMPARE(palette.color(group, QPalette::PlaceholderText), placeholder_text);
        QCOMPARE(palette.color(group, QPalette::Link), link);
        QCOMPARE(palette.color(group, QPalette::LinkVisited), visited_link);
        QCOMPARE(palette.color(group, QPalette::Window), window);
        QCOMPARE(palette.color(group, QPalette::Base), base);
        QCOMPARE(palette.color(group, QPalette::AlternateBase), alternate_base);
        QCOMPARE(palette.color(group, QPalette::Button), button);
        QCOMPARE(palette.color(group, QPalette::Highlight), highlight);
        QCOMPARE(palette.color(group, QPalette::HighlightedText), white);
        QCOMPARE(palette.color(group, QPalette::ToolTipBase), tooltip_base);
        QCOMPARE(palette.color(group, QPalette::ToolTipText), white);
    }

    QCOMPARE(palette.color(QPalette::Disabled, QPalette::WindowText), disabled_text);
    QCOMPARE(palette.color(QPalette::Disabled, QPalette::Text), disabled_text);
    QCOMPARE(palette.color(QPalette::Disabled, QPalette::ButtonText), disabled_text);
    QCOMPARE(palette.color(QPalette::Disabled, QPalette::PlaceholderText), disabled_text);
    QCOMPARE(palette.color(QPalette::Disabled, QPalette::Link), disabled_text);
    QCOMPARE(palette.color(QPalette::Disabled, QPalette::LinkVisited), disabled_text);
    QCOMPARE(palette.color(QPalette::Disabled, QPalette::Button), disabled_button_background);

    struct ContrastExpectation {
        QPalette::ColorRole foreground;
        QPalette::ColorRole background;
        const char* description;
    };
    const std::array contrast_expectations{
        ContrastExpectation{QPalette::WindowText, QPalette::Window, "window text"},
        ContrastExpectation{QPalette::Text, QPalette::Base, "input text"},
        ContrastExpectation{QPalette::Text, QPalette::AlternateBase, "alternate-row text"},
        ContrastExpectation{QPalette::ButtonText, QPalette::Button, "button text"},
        ContrastExpectation{QPalette::PlaceholderText, QPalette::Base, "placeholder text"},
        ContrastExpectation{QPalette::Link, QPalette::Base, "link"},
        ContrastExpectation{QPalette::LinkVisited, QPalette::Base, "visited link"},
        ContrastExpectation{QPalette::HighlightedText, QPalette::Highlight, "selection text"},
        ContrastExpectation{QPalette::ToolTipText, QPalette::ToolTipBase, "tooltip text"},
    };

    for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive, QPalette::Disabled}) {
        for (const ContrastExpectation& expectation : contrast_expectations) {
            const QColor foreground{palette.color(group, expectation.foreground)};
            const QColor background{palette.color(group, expectation.background)};
            const double ratio{ContrastRatio(foreground, background)};
            const QByteArray message{QStringLiteral("Palette group %1 %2 contrast is %3:1; expected at least 4.5:1")
                                         .arg(static_cast<int>(group))
                                         .arg(QString::fromLatin1(expectation.description))
                                         .arg(ratio, 0, 'f', 2)
                                         .toUtf8()};
            QVERIFY2(ratio >= 4.5, message.constData());
        }
    }

    // Exercise the real style-sheet path as well: disabled buttons use the
    // disabled palette foreground on their styled background.
    QPushButton disabled_button{QStringLiteral("Disabled")};
    disabled_button.setEnabled(false);
    disabled_button.ensurePolished();
    QStyleOptionButton option;
    option.initFrom(&disabled_button);
    QCOMPARE(option.palette.color(QPalette::Disabled, QPalette::ButtonText), disabled_text);
    QCOMPARE(option.palette.color(QPalette::Disabled, QPalette::Button), disabled_button_background);
    const double disabled_button_contrast{
        ContrastRatio(option.palette.color(QPalette::Disabled, QPalette::ButtonText),
                      option.palette.color(QPalette::Disabled, QPalette::Button))};
    QVERIFY2(disabled_button_contrast >= 4.5, "Styled disabled button contrast must be at least 4.5:1");
}

//! Entry point for NitoApplication tests.
void AppTests::appTests()
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        qWarning("Skipping AppTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
                 "with 'QT_QPA_PLATFORM=cocoa test_nito-qt' on mac, or else use a linux or windows build.");
        return;
    }
#endif

    qRegisterMetaType<interfaces::BlockAndHeaderTipInfo>("interfaces::BlockAndHeaderTipInfo");
    m_app.parameterSetup();
    QVERIFY(m_app.createOptionsModel(/*resetSettings=*/true));
    QScopedPointer<const NetworkStyle> style(NetworkStyle::instantiate(Params().GetChainType()));
    m_app.setupPlatformStyle();
    m_app.createWindow(style.data());
    connect(&m_app, &NitoApplication::windowShown, this, &AppTests::guiTests);
    expectCallback("guiTests");
    m_app.baseInitialize();
    m_app.requestInitialize();
    m_app.exec();
    m_app.requestShutdown();
    m_app.exec();

    // Reset global state to avoid interfering with later tests.
    LogInstance().DisconnectTestLogger();
}

//! Entry point for NitoGUI tests.
void AppTests::guiTests(NitoGUI* window)
{
    HandleCallback callback{"guiTests", *this};
    connect(window, &NitoGUI::consoleShown, this, &AppTests::consoleTests);
    expectCallback("consoleTests");
    QAction* action = window->findChild<QAction*>("openRPCConsoleAction");
    action->activate(QAction::Trigger);
}

//! Entry point for RPCConsole tests.
void AppTests::consoleTests(RPCConsole* console)
{
    HandleCallback callback{"consoleTests", *this};
    TestRpcCommand(console);
}

//! Destructor to shut down after the last expected callback completes.
AppTests::HandleCallback::~HandleCallback()
{
    auto& callbacks = m_app_tests.m_callbacks;
    auto it = callbacks.find(m_callback);
    assert(it != callbacks.end());
    callbacks.erase(it);
    if (callbacks.empty()) {
        m_app_tests.m_app.exit(0);
    }
}
