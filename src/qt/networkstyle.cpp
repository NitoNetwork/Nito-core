// Copyright (c) 2014-2021 The Bitcoin Core developers
// Copyright (c) 2024-2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/networkstyle.h>

#include <qt/guiconstants.h>
#include <qt/nitotheme.h>

#include <tinyformat.h>
#include <util/chaintype.h>

#include <QApplication>
#include <QColor>
#include <QImage>
#include <QLinearGradient>
#include <QPainter>
#include <QPainterPath>

#include <algorithm>

static const struct {
    const ChainType networkId;
    const char *appName;
} network_styles[] = {
    {ChainType::MAIN, QAPP_APP_NAME_DEFAULT},
    {ChainType::TESTNET, QAPP_APP_NAME_TESTNET},
    {ChainType::SIGNET, QAPP_APP_NAME_SIGNET},
    {ChainType::REGTEST, QAPP_APP_NAME_REGTEST},
};

namespace {
/**
 * Recolour the blue of Nito's icon to a network's accent colour and leave the
 * yellow alone. The icon's main blue becomes exactly the accent colour; lighter
 * and darker blues keep their shading, so the 3D look is preserved.
 */
void RecolourIcon(QImage& img, const QColor& accent)
{
    const QColor main_blue{"#0878f8"};
    const float main_l{main_blue.lightnessF()};
    const float main_s{main_blue.hslSaturationF()};
    const float target_h{std::max(0.0f, accent.hslHueF())};
    const float target_l{accent.lightnessF()};
    const float target_s{accent.hslSaturationF()};

    img = img.convertToFormat(QImage::Format_ARGB32);
    for (int y = 0; y < img.height(); ++y) {
        QRgb* line = reinterpret_cast<QRgb*>(img.scanLine(y));
        for (int x = 0; x < img.width(); ++x) {
            const int alpha{qAlpha(line[x])};
            if (alpha == 0) continue;
            float h, s, l, a;
            QColor(line[x]).getHslF(&h, &s, &l, &a);
            // Blues: hue 170-270 degrees
            if (h < 170.0f / 360.0f || h > 270.0f / 360.0f) continue;
            float new_l = l <= main_l ? l * target_l / main_l
                                      : target_l + (l - main_l) * (1.0f - target_l) / (1.0f - main_l);
            float new_s = std::min(1.0f, s * target_s / main_s);
            if (new_l > target_l) {
                // Soften and desaturate the highlights so they look metallic
                // rather than glowing (bright, saturated red reads as neon).
                const float t{(new_l - target_l) / (1.0f - target_l)};
                new_l = target_l + (new_l - target_l) * 0.75f;
                new_s *= 1.0f - 0.55f * t;
            }
            QColor recoloured{QColor::fromHslF(target_h, new_s, std::clamp(new_l, 0.0f, 1.0f))};
            recoloured.setAlpha(alpha);
            line[x] = recoloured.rgba();
        }
    }
}
#ifndef Q_OS_MACOS
/**
 * Crop the empty margin around the icon, keeping it square with a little
 * padding, so it fills the taskbar and title bar like other apps' icons.
 */
QPixmap TrimmedIcon(const QPixmap& pixmap)
{
    const QImage img{pixmap.toImage().convertToFormat(QImage::Format_ARGB32)};
    int left{img.width()}, top{img.height()}, right{-1}, bottom{-1};
    for (int y = 0; y < img.height(); ++y) {
        const QRgb* line = reinterpret_cast<const QRgb*>(img.constScanLine(y));
        for (int x = 0; x < img.width(); ++x) {
            if (qAlpha(line[x]) < 24) continue;
            left = std::min(left, x);
            right = std::max(right, x);
            top = std::min(top, y);
            bottom = std::max(bottom, y);
        }
    }
    if (right < left) return pixmap;
    const QRect box{QPoint{left, top}, QPoint{right, bottom}};
    const int content{std::max(box.width(), box.height())};
    const int side{content + content / 25};
    QImage out(side, side, QImage::Format_ARGB32_Premultiplied);
    out.fill(Qt::transparent);
    QPainter p(&out);
    p.drawImage(QPoint{(side - box.width()) / 2, (side - box.height()) / 2}, img, box);
    p.end();
    return QPixmap::fromImage(out);
}
#endif

#ifdef Q_OS_MACOS
/**
 * Put the icon in a rounded square on Apple's 1024 px app icon grid (an
 * 824 px square with 100 px margins and a soft shadow), so the Dock shows it
 * like other Mac apps. Windows and Linux keep the plain icon.
 */
QPixmap MacAppIcon(const QPixmap& glyph, const QColor& accent)
{
    constexpr int canvas{1024}, side{824}, margin{(canvas - side) / 2};
    constexpr qreal radius{side * 0.2237};
    // A dark shade of the network's colour, so the N and its yellow stand out,
    // and each network is recognisable even at small sizes.
    const float hue{std::max(0.0f, accent.hslHueF())};
    const QColor top{QColor::fromHslF(hue, 0.45f, 0.17f)};
    const QColor bottom{QColor::fromHslF(hue, 0.55f, 0.07f)};

    QImage img(canvas, canvas, QImage::Format_ARGB32_Premultiplied);
    img.fill(Qt::transparent);
    QPainter p(&img);
    p.setRenderHints(QPainter::Antialiasing | QPainter::SmoothPixmapTransform);
    const QRectF square(margin, margin, side, side);

    // Soft shadow: layered translucent squares, a little lower than the icon.
    p.setPen(Qt::NoPen);
    for (int i = 12; i >= 1; --i) {
        QPainterPath shadow;
        shadow.addRoundedRect(square.adjusted(-i, -i + 10, i, i + 10), radius + i, radius + i);
        p.setBrush(QColor(0, 0, 0, 7));
        p.drawPath(shadow);
    }

    QPainterPath path;
    path.addRoundedRect(square, radius, radius);
    QLinearGradient fill(square.topLeft(), square.bottomLeft());
    fill.setColorAt(0, top);
    fill.setColorAt(1, bottom);
    p.fillPath(path, fill);
    // Glass rim, as on macOS 26 icons: a thin bright edge just inside the
    // square, strongest at the top left and bottom right.
    constexpr qreal rim{11};
    const QRectF rim_rect{square.adjusted(rim / 2, rim / 2, -rim / 2, -rim / 2)};
    QPainterPath rim_path;
    rim_path.addRoundedRect(rim_rect, radius - rim / 2, radius - rim / 2);
    QLinearGradient shine(square.topLeft(), square.bottomRight());
    shine.setColorAt(0.0, QColor(255, 255, 255, 150));
    shine.setColorAt(0.3, QColor(255, 255, 255, 40));
    shine.setColorAt(0.7, QColor(255, 255, 255, 30));
    shine.setColorAt(1.0, QColor(255, 255, 255, 110));
    p.setPen(QPen(QBrush(shine), rim));
    p.setBrush(Qt::NoBrush);
    p.drawPath(rim_path);
    // A fine dark outline outside the rim keeps the edge crisp on light Docks.
    p.setPen(QPen(QColor(0, 0, 0, 90), 2));
    p.drawPath(path);

    const int glyph_side{qRound(side * 0.92)};
    const QPixmap scaled{glyph.scaled(glyph_side, glyph_side, Qt::KeepAspectRatio, Qt::SmoothTransformation)};
    p.drawPixmap(QPointF(canvas - scaled.width(), canvas - scaled.height()) / 2, scaled);
    p.end();
    return QPixmap::fromImage(img);
}
#endif
} // namespace

// titleAddText needs to be const char* for tr()
NetworkStyle::NetworkStyle(const QString &_appName, const ChainType _chain, const char *_titleAddText):
    appName(_appName),
    titleAddText(qApp->translate("SplashScreen", _titleAddText)),
    chain(_chain),
    accent(NitoNetworkAccent(_chain))
{
    // load pixmap
    QPixmap pixmap(":/icons/nito");

    if (chain != ChainType::MAIN) {
        QImage img = pixmap.toImage();
        RecolourIcon(img, accent);
        pixmap = QPixmap::fromImage(img);
    }

    appIcon = QIcon(pixmap);
#ifdef Q_OS_MACOS
    trayAndWindowIcon = QIcon(MacAppIcon(pixmap, accent));
#else
#ifndef Q_OS_WIN
    if (chain == ChainType::MAIN) {
        trayAndWindowIcon = QIcon(pixmap.scaled(QSize{256, 256}));
        return;
    }
#endif
    trayAndWindowIcon = QIcon(TrimmedIcon(pixmap).scaled(QSize{256, 256}, Qt::KeepAspectRatio, Qt::SmoothTransformation));
#endif
}

const NetworkStyle* NetworkStyle::instantiate(const ChainType networkId)
{
    std::string titleAddText = networkId == ChainType::MAIN ? "" : strprintf("[%s]", ChainTypeToString(networkId));
    for (const auto& network_style : network_styles) {
        if (networkId == network_style.networkId) {
            return new NetworkStyle(
                    network_style.appName,
                    network_style.networkId,
                    titleAddText.c_str());
        }
    }
    return nullptr;
}
