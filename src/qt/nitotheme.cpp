// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/nitotheme.h>

#include <common/args.h>

#include <QApplication>
#include <QGuiApplication>
#include <QPalette>
#include <QStyle>
#include <QStyleFactory>
#include <QStyleHints>

#include <algorithm>
#include <cmath>
#include <utility>
#include <vector>

namespace {

double Channel(double c)
{
    return c <= 0.03928 ? c / 12.92 : std::pow((c + 0.055) / 1.055, 2.4);
}

double Luminance(const QColor& color)
{
    return 0.2126 * Channel(color.redF()) + 0.7152 * Channel(color.greenF()) + 0.0722 * Channel(color.blueF());
}

/** An 8-bit RGB colour, as drawn and as written in the style sheet, so that contrast checks see the exact colour. */
QColor Rgb(const QColor& color)
{
    return QColor{color.rgb()};
}

QColor Hsl(double hue, double saturation, double lightness)
{
    return Rgb(QColor::fromHslF(static_cast<float>(hue), static_cast<float>(saturation), static_cast<float>(lightness)));
}

/** Move a foreground colour's lightness away from its background until the contrast is at least `ratio`. */
QColor WithContrast(QColor foreground, const QColor& background, double ratio = 4.5)
{
    foreground = Rgb(foreground);
    const bool darken{Luminance(background) > 0.18};
    for (int step = 0; step < 100 && NitoContrastRatio(foreground, background) < ratio; ++step) {
        float h, s, l, a;
        foreground.getHslF(&h, &s, &l, &a);
        l = darken ? std::max(0.0f, l - 0.01f) : std::min(1.0f, l + 0.01f);
        foreground = Rgb(QColor::fromHslF(std::max(h, 0.0f), s, l, a));
    }
    return foreground;
}

/** The same colour, darkened until white text on it has at least `ratio` contrast. */
QColor ForWhiteText(QColor color, double ratio = 4.5)
{
    color = Rgb(color);
    for (int step = 0; step < 100 && NitoContrastRatio(Qt::white, color) < ratio; ++step) {
        float h, s, l, a;
        color.getHslF(&h, &s, &l, &a);
        color = Rgb(QColor::fromHslF(std::max(h, 0.0f), s, std::max(0.0f, l - 0.01f), a));
    }
    return color;
}

struct ThemeState {
    ChainType chain{ChainType::MAIN};
    bool following_system{false};
};

ThemeState& State()
{
    static ThemeState state;
    return state;
}

} // namespace

double NitoContrastRatio(const QColor& a, const QColor& b)
{
    const double la{Luminance(a)};
    const double lb{Luminance(b)};
    return (std::max(la, lb) + 0.05) / (std::min(la, lb) + 0.05);
}

QColor NitoNetworkAccent(ChainType chain)
{
    switch (chain) {
    case ChainType::TESTNET: return QColor{"#1b8f55"};
    case ChainType::SIGNET: return QColor{"#6a3fb5"};
    case ChainType::REGTEST: return QColor{"#992b26"};
    case ChainType::MAIN: break;
    }
    return QColor{"#0073cf"};
}

QColor NitoWarningColor(const QPalette& palette)
{
    const bool dark{palette.color(QPalette::Window).lightnessF() < 0.5};
    return dark ? QColor{"#f2b63c"} : QColor{"#b06a00"};
}

bool NitoSystemPrefersDark()
{
    return QGuiApplication::styleHints()->colorScheme() == Qt::ColorScheme::Dark;
}

namespace {
/** Light or dark, from -guitheme (auto follows the system). */
bool UseDarkTheme()
{
    const std::string mode{gArgs.GetArg("-guitheme", "auto")};
    if (mode == "light") return false;
    if (mode == "dark") return true;
    return NitoSystemPrefersDark();
}
} // namespace

NitoTheme MakeNitoTheme(ChainType chain, bool dark)
{
    NitoTheme t;
    t.dark = dark;
    t.chain = chain;

    const QColor network_accent{NitoNetworkAccent(chain)};
    const double h{std::max(0.0f, network_accent.hslHueF())};
    // Mainnet's surfaces are tinted with Nito blue. On the test networks the
    // surfaces stay close to neutral and only the accents carry the colour.
    const double tint{chain == ChainType::MAIN ? 1.0 : 0.45};
    const auto T = [tint](double saturation) { return saturation * tint; };

    if (!dark) {
        t.window = Hsl(h, T(0.65), 0.97);
        t.surface = Hsl(h, T(0.70), 0.99);
        t.base = QColor{"#ffffff"};
        t.alternate_base = Hsl(h, T(0.75), 0.955);
        t.button = Hsl(h, T(0.70), 0.985);
        t.button_disabled = Hsl(h, T(0.40), 0.94);
        t.header = Hsl(h, T(0.80), 0.945);
        t.border = Hsl(h, T(0.55), 0.86);
        t.border_strong = Hsl(h, T(0.50), 0.78);
        t.accent_soft = Hsl(h, 0.85, 0.93);

        t.accent = ForWhiteText(network_accent);
        t.on_accent = QColor{"#ffffff"};
        t.progress_trough = Rgb(t.accent.darker(165));
        t.accent_strong = WithContrast(t.accent.darker(125), t.accent_soft);
        t.text = Hsl(h, T(0.60), 0.16);
        t.text_muted = WithContrast(Hsl(h, T(0.20), 0.38), t.alternate_base);
        t.text_disabled = WithContrast(Hsl(h, T(0.17), 0.43), t.button_disabled);
        t.link = WithContrast(network_accent, t.base);
        t.link_visited = WithContrast(QColor{"#5b4bb7"}, t.base);
        t.tooltip_base = Hsl(h, T(0.60), 0.11);
        t.tooltip_text = QColor{"#ffffff"};
    } else {
        t.window = Hsl(h, T(0.20), 0.12);
        t.surface = Hsl(h, T(0.20), 0.15);
        t.base = Hsl(h, T(0.22), 0.09);
        t.alternate_base = Hsl(h, T(0.18), 0.13);
        t.button = Hsl(h, T(0.18), 0.19);
        t.button_disabled = Hsl(h, T(0.12), 0.15);
        t.header = Hsl(h, T(0.20), 0.17);
        t.border = Hsl(h, T(0.16), 0.27);
        t.border_strong = Hsl(h, T(0.16), 0.36);
        t.accent_soft = Hsl(h, 0.35, 0.24);

        t.accent = ForWhiteText(network_accent);
        t.on_accent = QColor{"#ffffff"};
        t.progress_trough = Rgb(t.accent.darker(165));
        t.accent_strong = WithContrast(Hsl(h, 0.75, 0.72), t.accent_soft);
        t.text = Hsl(h, T(0.25), 0.92);
        t.text_muted = WithContrast(Hsl(h, T(0.12), 0.70), t.button);
        t.text_disabled = WithContrast(Hsl(h, T(0.10), 0.55), t.button_disabled);
        t.link = WithContrast(Hsl(h, 0.85, 0.72), t.alternate_base);
        t.link_visited = WithContrast(QColor{"#b9a8ff"}, t.alternate_base);
        t.tooltip_base = Hsl(h, T(0.20), 0.22);
        t.tooltip_text = t.text;
    }
    return t;
}

QString NitoThemeStyleSheet(const NitoTheme& t)
{
    QString css{QStringLiteral(
        "QMainWindow, QDialog { background-color: {window}; }"
        "QToolTip { color: {tooltip_text}; background-color: {tooltip_base}; border: 1px solid {border_strong}; padding: 4px; }"
        "QMenuBar { background-color: {surface}; border-bottom: 1px solid {border}; }"
        "QMenuBar::item { padding: 5px 9px; background: transparent; }"
        "QMenuBar::item:selected { color: {accent_strong}; background-color: {accent_soft}; }"
        "QMenu { background-color: {base}; border: 1px solid {border_strong}; }"
        "QMenu::item:selected { color: {on_accent}; background-color: {accent}; }"
        "QMenu::separator { height: 1px; background: {border}; margin: 4px 8px; }"
        "QToolBar { background-color: {surface}; border: 0; border-bottom: 1px solid {border}; spacing: 4px; padding: 4px 8px; }"
        "QToolButton { color: {text}; border: 1px solid transparent; border-radius: 6px; padding: 4px 8px; }"
        "QToolButton:hover { border-color: {border_strong}; background-color: {accent_soft}; }"
        "QToolButton:pressed, QToolButton:checked { color: {accent_strong}; background-color: {accent_soft}; border-color: {accent}; }"
        "QGroupBox { border: 1px solid {border}; border-radius: 8px; margin-top: 10px; padding-top: 12px; background-color: {surface}; }"
        "QGroupBox::title { color: {accent_strong}; subcontrol-origin: margin; left: 10px; padding: 0 4px; }"
        "QFrame[frameShape=\"4\"], QFrame[frameShape=\"6\"] { border-color: {border}; }"
        "QPushButton { color: {text}; border: 1px solid {border_strong}; border-radius: 5px; padding: 5px 12px; background-color: {button}; }"
        "QPushButton:hover { border-color: {accent}; background-color: {accent_soft}; }"
        "QPushButton:pressed, QPushButton:checked { color: {on_accent}; background-color: {accent}; border-color: {accent_strong}; }"
        "QPushButton:default { border-color: {accent}; }"
        "QPushButton:disabled { color: {text_disabled}; background-color: {button_disabled}; border-color: {border}; }"
        "QPushButton:flat { background: transparent; border: 1px solid transparent; }"
        "QPushButton:flat:hover { background-color: {accent_soft}; border-color: {border}; }"
        "QPushButton:flat:disabled { background: transparent; border-color: transparent; }"
        // Style the tab page as well as the tabs, so that they always line up.
        "QTabWidget::pane { border: 1px solid {border}; border-radius: 6px; background-color: {surface}; top: -1px; }"
        "QTabBar::tab { color: {text_muted}; background-color: {window}; border: 1px solid {border}; border-top-left-radius: 6px; border-top-right-radius: 6px; padding: 6px 14px; margin-right: 3px; }"
        "QTabBar::tab:!selected { margin-top: 2px; }"
        "QTabBar::tab:selected { color: {accent_strong}; background-color: {surface}; border-top: 2px solid {accent}; border-bottom-color: {surface}; }"
        "QTabBar::tab:hover:!selected { color: {text}; background-color: {accent_soft}; }"
        "QHeaderView::section { color: {text}; background-color: {header}; border: 0; border-right: 1px solid {border}; border-bottom: 1px solid {border}; padding: 4px 6px; }"
        "QTableView, QTreeView, QListView { gridline-color: {border}; alternate-background-color: {alternate_base}; selection-background-color: {accent}; selection-color: {on_accent}; }"
        "QLineEdit, QTextEdit, QPlainTextEdit { color: {text}; background-color: {base}; border: 1px solid {border_strong}; border-radius: 4px; padding: 2px 4px; }"
        // Line edits inside spin boxes and combo boxes are drawn by their parent.
        "QAbstractSpinBox > QLineEdit, QComboBox > QLineEdit { border: 0; padding: 0; background: transparent; }"
        "QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border: 1px solid {accent}; }"
        "QCheckBox, QRadioButton { spacing: 6px; }"
        // White text on the whole bar: the empty part is a dark shade of the accent.
        "QProgressBar { color: {on_accent}; border: 1px solid {progress_trough}; border-radius: 4px; background-color: {progress_trough}; text-align: center; }"
        "QProgressBar::chunk { background-color: {accent}; border-radius: 3px; }"
        "QStatusBar { background-color: {surface}; border-top: 1px solid {border}; }"
        "QStatusBar::item { border: 0; }"
        // Branding in the main window's tool bar.
        "QLabel#nitoBrandName { color: {text}; font-size: 15px; font-weight: 600; padding: 0 6px 0 2px; }"
        // Client name and version in the Overview page's bottom left corner.
        "QLabel#nitoAboutLinks { color: {text_muted}; }"
        "QLabel#nitoNetworkBadge { color: {on_accent}; background-color: {accent}; min-height: 20px; max-height: 20px; border-radius: 10px; padding: 0 10px; font-size: 11px; font-weight: 700; }")};

    const std::vector<std::pair<QString, QColor>> colors{
        {"accent", t.accent}, {"accent_strong", t.accent_strong}, {"accent_soft", t.accent_soft},
        {"on_accent", t.on_accent}, {"progress_trough", t.progress_trough}, {"window", t.window}, {"surface", t.surface}, {"base", t.base},
        {"alternate_base", t.alternate_base}, {"button", t.button}, {"button_disabled", t.button_disabled},
        {"header", t.header}, {"border", t.border}, {"border_strong", t.border_strong}, {"text", t.text},
        {"text_muted", t.text_muted}, {"text_disabled", t.text_disabled}, {"tooltip_base", t.tooltip_base},
        {"tooltip_text", t.tooltip_text},
    };
    for (const auto& [name, color] : colors) {
        css.replace(QLatin1Char('{') + name + QLatin1Char('}'), color.name());
    }
    return css;
}

void ApplyNitoTheme(QApplication& app, const NitoTheme& t)
{
    QPalette palette;

    // Define the complete palette, foregrounds as well as backgrounds, so that
    // nothing from the system palette (light or dark) is mixed in.
    for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive, QPalette::Disabled}) {
        palette.setColor(group, QPalette::WindowText, t.text);
        palette.setColor(group, QPalette::Text, t.text);
        palette.setColor(group, QPalette::ButtonText, t.text);
        palette.setColor(group, QPalette::BrightText, QColor{"#ffffff"});
        palette.setColor(group, QPalette::PlaceholderText, t.text_muted);
        palette.setColor(group, QPalette::Link, t.link);
        palette.setColor(group, QPalette::LinkVisited, t.link_visited);
        palette.setColor(group, QPalette::Highlight, t.accent);
        palette.setColor(group, QPalette::HighlightedText, t.on_accent);
        palette.setColor(group, QPalette::Window, t.window);
        palette.setColor(group, QPalette::Base, t.base);
        palette.setColor(group, QPalette::AlternateBase, t.alternate_base);
        palette.setColor(group, QPalette::Button, t.button);
        palette.setColor(group, QPalette::ToolTipBase, t.tooltip_base);
        palette.setColor(group, QPalette::ToolTipText, t.tooltip_text);
        // Bevels and frames drawn by the Fusion style.
        palette.setColor(group, QPalette::Light, t.dark ? t.button.lighter(130) : QColor{"#ffffff"});
        palette.setColor(group, QPalette::Midlight, t.dark ? t.button.lighter(115) : t.window);
        palette.setColor(group, QPalette::Mid, t.border_strong);
        palette.setColor(group, QPalette::Dark, t.dark ? t.base.darker(130) : t.border_strong.darker(120));
        palette.setColor(group, QPalette::Shadow, t.dark ? QColor{"#000000"} : t.border_strong.darker(160));
    }

    for (const QPalette::ColorRole role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText,
                                           QPalette::PlaceholderText, QPalette::Link, QPalette::LinkVisited}) {
        palette.setColor(QPalette::Disabled, role, t.text_disabled);
    }
    palette.setColor(QPalette::Disabled, QPalette::Button, t.button_disabled);

    app.setPalette(palette);
    app.setStyleSheet(NitoThemeStyleSheet(t));
}

void SetupNitoTheme(QApplication& app, ChainType chain)
{
    ThemeState& state{State()};
    state.chain = chain;

    if (!state.following_system) {
        state.following_system = true;
        // Qt's native macOS and Windows styles ignore parts of a custom palette
        // (and of style sheets), so the same theme looked different, or broken,
        // on each platform. Fusion draws exactly what the theme asks for.
        if (QStyle* fusion = QStyleFactory::create(QStringLiteral("Fusion"))) {
            app.setStyle(fusion);
        }
        QObject::connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged, &app, [&app](Qt::ColorScheme) {
            ApplyNitoTheme(app, MakeNitoTheme(State().chain, UseDarkTheme()));
        });
    }

    ApplyNitoTheme(app, MakeNitoTheme(chain, UseDarkTheme()));
}
