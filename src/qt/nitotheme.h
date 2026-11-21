// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_NITOTHEME_H
#define BITCOIN_QT_NITOTHEME_H

#include <util/chaintype.h>

#include <QColor>
#include <QString>

class QApplication;
class QPalette;

/**
 * Nito's application theme. Every network has its own accent colour (mainnet
 * blue, testnet green, signet purple, regtest red), and each has a light and a
 * dark variant. All colours are derived from the accent, and every text colour
 * is adjusted until it has at least WCAG AA contrast (4.5:1) on its background.
 */
struct NitoTheme {
    bool dark{false};
    ChainType chain{ChainType::MAIN};

    QColor accent;        //!< selection, checked controls, progress
    QColor accent_strong; //!< group titles, selected tab text, strong borders
    QColor accent_soft;   //!< hover and selected backgrounds
    QColor on_accent;     //!< text on the accent colour
    QColor progress_trough; //!< empty part of progress bars, under on_accent text

    QColor window;          //!< window background
    QColor surface;         //!< group boxes, tab pages, tool bar
    QColor base;            //!< input fields, tables
    QColor alternate_base;  //!< alternate table rows
    QColor button;          //!< button background
    QColor button_disabled; //!< disabled button background
    QColor header;          //!< table headers

    QColor border;
    QColor border_strong;

    QColor text;
    QColor text_muted;
    QColor text_disabled;
    QColor link;
    QColor link_visited;

    QColor tooltip_base;
    QColor tooltip_text;
};

/** The accent colour of a network, as used for its icon and theme. */
QColor NitoNetworkAccent(ChainType chain);

/** The colour for warning icons: amber, darker on a light window than on a dark one. */
QColor NitoWarningColor(const QPalette& palette);

/** Whether the operating system currently asks applications for a dark appearance. */
bool NitoSystemPrefersDark();

/** Build the theme for a network in light or dark mode. */
NitoTheme MakeNitoTheme(ChainType chain, bool dark);

/** The application style sheet for a theme. */
QString NitoThemeStyleSheet(const NitoTheme& theme);

/** Apply a theme's palette and style sheet to the application. */
void ApplyNitoTheme(QApplication& app, const NitoTheme& theme);

/**
 * Use the Fusion style on every platform, apply the theme for this network
 * and the current system appearance, and follow the system when it switches
 * between light and dark. Can be called again when the network is known.
 */
void SetupNitoTheme(QApplication& app, ChainType chain);

/** Contrast ratio between two colours, as defined by WCAG 2. */
double NitoContrastRatio(const QColor& a, const QColor& b);

#endif // BITCOIN_QT_NITOTHEME_H
