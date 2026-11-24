// Copyright (c) 2018-2022 The Bitcoin Core developers
// Copyright (c) 2024-2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/apptests.h>

#include <chainparams.h>
#include <key.h>
#include <logging.h>
#include <qt/nito.h>
#include <qt/nitogui.h>
#include <qt/networkstyle.h>
#include <qt/nitotheme.h>
#include <qt/rpcconsole.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <validation.h>

#include <QAction>
#include <QByteArray>
#include <QColor>
#include <QImage>
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
#include <utility>
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

//! Verify Nito's themes: every network, light and dark, is independent of the
//! system palette and keeps all text readable.
void AppTests::paletteTests()
{
    ApplicationStyleRestorer restore_style{m_app};

    // Mainnet in light mode keeps Nito's established blue.
    QCOMPARE(MakeNitoTheme(ChainType::MAIN, /*dark=*/false).accent, QColor{"#0073cf"});

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

    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::SIGNET, ChainType::REGTEST}) {
        for (const bool dark : {false, true}) {
            const NitoTheme theme{MakeNitoTheme(chain, dark)};
            const QString name{QStringLiteral("%1 %2").arg(QString::fromStdString(ChainTypeToString(chain)), dark ? "dark" : "light")};

            // Reproduce the original failure mode: a system palette of the
            // opposite brightness must not leak into Nito's theme.
            const QColor hostile_background{dark ? "#ffffff" : "#101010"};
            const QColor hostile_text{dark ? "#000000" : "#ffffff"};
            QPalette hostile_palette{m_app.palette()};
            for (const QPalette::ColorRole role : {QPalette::Window, QPalette::Base, QPalette::AlternateBase, QPalette::Button}) {
                hostile_palette.setColor(role, hostile_background);
            }
            for (const QPalette::ColorRole role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText, QPalette::PlaceholderText, QPalette::Link, QPalette::LinkVisited}) {
                hostile_palette.setColor(role, hostile_text);
            }
            m_app.setStyleSheet(QString{});
            m_app.setPalette(hostile_palette);

            ApplyNitoTheme(m_app, theme);
            const QPalette palette{m_app.palette()};

            for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive}) {
                QCOMPARE(palette.color(group, QPalette::Window), theme.window);
                QCOMPARE(palette.color(group, QPalette::Base), theme.base);
                QCOMPARE(palette.color(group, QPalette::Button), theme.button);
                QCOMPARE(palette.color(group, QPalette::WindowText), theme.text);
                QCOMPARE(palette.color(group, QPalette::Text), theme.text);
                QCOMPARE(palette.color(group, QPalette::ButtonText), theme.text);
                QCOMPARE(palette.color(group, QPalette::Highlight), theme.accent);
            }
            QCOMPARE(palette.color(QPalette::Disabled, QPalette::ButtonText), theme.text_disabled);
            QCOMPARE(palette.color(QPalette::Disabled, QPalette::Button), theme.button_disabled);
            QVERIFY2((theme.window.lightness() < 128) == dark, qPrintable(name + ": window brightness doesn't match the mode"));

            for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive, QPalette::Disabled}) {
                for (const ContrastExpectation& expectation : contrast_expectations) {
                    const double ratio{ContrastRatio(palette.color(group, expectation.foreground), palette.color(group, expectation.background))};
                    const QByteArray message{QStringLiteral("%1: palette group %2 %3 contrast is %4:1; expected at least 4.5:1")
                                                 .arg(name)
                                                 .arg(static_cast<int>(group))
                                                 .arg(QString::fromLatin1(expectation.description))
                                                 .arg(ratio, 0, 'f', 2)
                                                 .toUtf8()};
                    QVERIFY2(ratio >= 4.5, message.constData());
                }
            }

            // Colours used only by the style sheet.
            const std::array<std::pair<std::pair<QColor, QColor>, const char*>, 7> sheet_contrasts{{
                {{theme.on_accent, theme.progress_trough}, "progress bar text on the empty part"},
                {{theme.on_accent, theme.accent}, "progress bar text on the filled part"},
                {{theme.accent_strong, theme.accent_soft}, "selected tool button"},
                {{theme.accent_strong, theme.surface}, "selected tab and group title"},
                {{theme.text_muted, theme.window}, "unselected tab"},
                {{theme.on_accent, theme.accent}, "checked button and network badge"},
                {{theme.text, theme.header}, "table header"},
            }};
            for (const auto& [colors, description] : sheet_contrasts) {
                const double ratio{ContrastRatio(colors.first, colors.second)};
                QVERIFY2(ratio >= 4.5, qPrintable(QStringLiteral("%1: %2 contrast is %3:1; expected at least 4.5:1").arg(name, description).arg(ratio, 0, 'f', 2)));
            }

            // Warning icons are graphics, so they need WCAG's 3:1 for non-text contrast.
            const double warning_ratio{ContrastRatio(NitoWarningColor(palette), theme.window)};
            QVERIFY2(warning_ratio >= 3.0, qPrintable(QStringLiteral("%1: warning icon contrast is %2:1; expected at least 3:1").arg(name).arg(warning_ratio, 0, 'f', 2)));

            // Every colour placeholder in the style sheet was filled in.
            QVERIFY2(!m_app.styleSheet().contains(QRegularExpression{QStringLiteral("\\{[a-z_]+\\}")}), qPrintable(name + ": unfilled style sheet colour"));

            // Exercise the real style-sheet path as well: disabled buttons use
            // the disabled palette foreground on their styled background.
            QPushButton disabled_button{QStringLiteral("Disabled")};
            disabled_button.setEnabled(false);
            disabled_button.ensurePolished();
            QStyleOptionButton option;
            option.initFrom(&disabled_button);
            const double disabled_button_contrast{
                ContrastRatio(option.palette.color(QPalette::Disabled, QPalette::ButtonText),
                              option.palette.color(QPalette::Disabled, QPalette::Button))};
            QVERIFY2(disabled_button_contrast >= 4.5, qPrintable(QStringLiteral("%1: styled disabled button contrast is %2:1 (%3 on %4); expected at least 4.5:1")
                                                                     .arg(name)
                                                                     .arg(disabled_button_contrast, 0, 'f', 2)
                                                                     .arg(option.palette.color(QPalette::Disabled, QPalette::ButtonText).name(),
                                                                          option.palette.color(QPalette::Disabled, QPalette::Button).name())));
        }
    }

    // The mainnet logo inside the app keeps its original colors and framing.
    const QScopedPointer<const NetworkStyle> main_style{NetworkStyle::instantiate(ChainType::MAIN)};
    QVERIFY(main_style);
    const QPixmap official_logo{QStringLiteral(":/icons/nito")};
    QVERIFY(!official_logo.isNull());
    QCOMPARE(main_style->getAppIcon().pixmap(official_logo.size()).toImage(),
             QIcon{official_logo}.pixmap(official_logo.size()).toImage());

#if !defined(Q_OS_MACOS) && !defined(Q_OS_WIN)
    const QSize main_icon_size{256, 256};
    const QIcon expected_main_icon{official_logo.scaled(main_icon_size)};
    QCOMPARE(main_style->getTrayAndWindowIcon().pixmap(main_icon_size).toImage(),
             expected_main_icon.pixmap(main_icon_size).toImage());
#endif

#ifdef Q_OS_MACOS
    // On macOS the Dock icon sits in a rounded square in a dark shade of the
    // network's colour: transparent outside the square, opaque inside it.
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::SIGNET, ChainType::REGTEST}) {
        const QScopedPointer<const NetworkStyle> style{NetworkStyle::instantiate(chain)};
        QVERIFY(style);
        const QImage icon{style->getTrayAndWindowIcon().pixmap(QSize{1024, 1024}).toImage().convertToFormat(QImage::Format_ARGB32)};
        QCOMPARE(icon.size(), QSize(1024, 1024));
        const QString name{QString::fromStdString(ChainTypeToString(chain))};
        QVERIFY2(qAlpha(icon.pixel(20, 20)) == 0, qPrintable(name + ": icon corner should be transparent"));
        QVERIFY2(qAlpha(icon.pixel(512, 512)) == 255, qPrintable(name + ": icon centre should be opaque"));
        // Inside the square, left of the N: the background.
        const QColor background{icon.pixel(150, 512)};
        QVERIFY2(background.lightnessF() < 0.25f, qPrintable(name + ": icon background should be dark, is " + background.name()));
        const float hue_gap{std::abs(background.hslHueF() - NitoNetworkAccent(chain).hslHueF())};
        QVERIFY2(std::min(hue_gap, 1.0f - hue_gap) < 0.05f, qPrintable(name + ": icon background should be a shade of the network colour, is " + background.name()));
    }
#else
    // Windows and the non-mainnet window icons outside macOS use a tighter crop.
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::SIGNET, ChainType::REGTEST}) {
#ifndef Q_OS_WIN
        if (chain == ChainType::MAIN) continue;
#endif
        const QScopedPointer<const NetworkStyle> style{NetworkStyle::instantiate(chain)};
        QVERIFY(style);
        const QImage icon{style->getTrayAndWindowIcon().pixmap(QSize{256, 256}).toImage().convertToFormat(QImage::Format_ARGB32)};
        int top{icon.height()}, bottom{-1};
        for (int y = 0; y < icon.height(); ++y) {
            for (int x = 0; x < icon.width(); ++x) {
                if (qAlpha(icon.pixel(x, y)) < 24) continue;
                top = std::min(top, y);
                bottom = std::max(bottom, y);
            }
        }
        const QString name{QString::fromStdString(ChainTypeToString(chain))};
        QVERIFY2(bottom - top + 1 >= icon.height() * 9 / 10, qPrintable(name + ": icon should fill at least 90% of its height"));
    }
#endif
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
