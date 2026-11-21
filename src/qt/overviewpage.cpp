// Copyright (c) 2011-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/nito-config.h>
#endif

#include <qt/overviewpage.h>
#include <qt/forms/ui_overviewpage.h>

#include <clientversion.h>

#include <qt/nitounits.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactionoverviewwidget.h>
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>

#include <QAbstractItemDelegate>
#include <QApplication>
#include <QDateTime>
#include <QHBoxLayout>
#include <QImage>
#include <QLabel>
#include <QPainter>
#include <QStatusTipEvent>
#include <QStringList>
#include <QVBoxLayout>

#include <algorithm>
#include <map>

#define DECORATION_SIZE 54
#define NUM_ITEMS 5

Q_DECLARE_METATYPE(interfaces::WalletBalances)

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit TxViewDelegate(const PlatformStyle* _platformStyle, QObject* parent = nullptr)
        : QAbstractItemDelegate(parent), platformStyle(_platformStyle)
    {
        connect(this, &TxViewDelegate::width_changed, this, &TxViewDelegate::sizeHintChanged);
    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const override
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon = platformStyle->SingleColorIcon(icon);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        if (index.data(TransactionTableModel::WatchonlyRole).toBool()) {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(addressRect.left(), addressRect.top(), 16, addressRect.height());
            iconWatchonly = platformStyle->TextColorIcon(iconWatchonly);
            iconWatchonly.paint(painter, watchonlyRect);
            addressRect.setLeft(addressRect.left() + watchonlyRect.width() + 5);
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter, address, &boundingRect);

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText = NitoUnits::formatWithUnit(unit, amount, true, NitoUnits::SeparatorStyle::ALWAYS);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }

        QRect amount_bounding_rect;
        painter->drawText(amountRect, Qt::AlignRight | Qt::AlignVCenter, amountText, &amount_bounding_rect);

        painter->setPen(option.palette.color(QPalette::Text));
        QRect date_bounding_rect;
        painter->drawText(amountRect, Qt::AlignLeft | Qt::AlignVCenter, GUIUtil::dateTimeStr(date), &date_bounding_rect);

        // 0.4*date_bounding_rect.width() is used to visually distinguish a date from an amount.
        const int minimum_width = 1.4 * date_bounding_rect.width() + amount_bounding_rect.width();
        const auto search = m_minimum_width.find(index.row());
        if (search == m_minimum_width.end() || search->second != minimum_width) {
            m_minimum_width[index.row()] = minimum_width;
            Q_EMIT width_changed(index);
        }

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        const auto search = m_minimum_width.find(index.row());
        const int minimum_text_width = search == m_minimum_width.end() ? 0 : search->second;
        return {DECORATION_SIZE + 8 + minimum_text_width, DECORATION_SIZE};
    }

    NitoUnit unit{NitoUnit::BTC};

Q_SIGNALS:
    //! An intermediate signal for emitting from the `paint() const` member function.
    void width_changed(const QModelIndex& index) const;

private:
    const PlatformStyle* platformStyle;
    mutable std::map<int, int> m_minimum_width;
};

#include <qt/overviewpage.moc>

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    m_platform_style{platformStyle},
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    ui->setupUi(this);

    updateStatusIcons();
    setupAboutPanel();

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, &TransactionOverviewWidget::clicked, this, &OverviewPage::handleTransactionClicked);

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, &QPushButton::clicked, this, &OverviewPage::outOfSyncWarningClicked);
    connect(ui->labelTransactionsStatus, &QPushButton::clicked, this, &OverviewPage::outOfSyncWarningClicked);
}

void OverviewPage::setupAboutPanel()
{
    auto* panel = new QWidget(this);
    m_about_panel = panel;
    panel->setObjectName(QStringLiteral("nitoAboutPanel"));
    auto* layout = new QHBoxLayout(panel);
    layout->setContentsMargins(14, 0, 0, 14);

    auto* text = new QVBoxLayout;
    text->setSpacing(0);
    m_about_links = new QLabel(panel);
    m_about_links->setObjectName(QStringLiteral("nitoAboutLinks"));
    m_about_links->setTextFormat(Qt::RichText);
    m_about_links->setOpenExternalLinks(true);
    connect(m_about_links, &QLabel::linkHovered, this, [this](const QString& link) {
        m_hovered_link = link;
        updateAboutLinks();
    });
    text->addStretch();
    text->addWidget(m_about_links);
    layout->addLayout(text);
    layout->addStretch();

    // Below the balances, pushed to the bottom by the column's spacer.
    ui->verticalLayout_2->addWidget(panel);
    updateAboutPanel();
}

void OverviewPage::updateAboutPanel()
{
    if (!m_about_links) return;

    // The flat Nito N in the theme's accent colour, faint enough to sit behind text.
    QImage image{QStringLiteral(":/icons/nito_watermark")};
    image = image.convertToFormat(QImage::Format_ARGB32);
    const QColor accent{palette().color(QPalette::Highlight)};
    const bool dark{palette().color(QPalette::Window).lightnessF() < 0.5};
    const double opacity{dark ? 0.10 : 0.07};
    for (int y = 0; y < image.height(); ++y) {
        for (int x = 0; x < image.width(); ++x) {
            const int alpha{static_cast<int>(qAlpha(image.pixel(x, y)) * opacity)};
            image.setPixel(x, y, qRgba(accent.red(), accent.green(), accent.blue(), alpha));
        }
    }
    m_watermark = QPixmap::fromImage(image);
    update();

    updateAboutLinks();
}

void OverviewPage::updateAboutLinks()
{
    if (!m_about_links) return;
    // Version and links on one quiet line in the muted text colour. A link
    // turns to the normal text colour while the mouse is over it.
    const QString muted{palette().color(QPalette::PlaceholderText).name()};
    const QString hover{palette().color(QPalette::WindowText).name()};
    auto link = [&](const QString& url, const QString& text) {
        return QStringLiteral("<a href=\"%1\" style=\"color: %2; text-decoration: none;\">%3</a>")
            .arg(url, url == m_hovered_link ? hover : muted, text);
    };
    const QString separator{QStringLiteral(" &nbsp;&middot;&nbsp; ")};
    m_about_links->setText(
        QStringLiteral("<span style=\"font-size: 11px; color: %1;\">").arg(muted) +
        QString::fromStdString(FormatFullVersion()).toHtmlEscaped() + separator +
        link(QStringLiteral("https://github.com/NitoNetwork/Nito-core"), tr("GitHub")) + separator +
        link(QStringLiteral("https://github.com/NitoNetwork/Nito-core/releases"), tr("Releases")) +
        QStringLiteral("</span>"));
}

void OverviewPage::paintEvent(QPaintEvent* e)
{
    QWidget::paintEvent(e);
    if (m_watermark.isNull()) return;
    // Fill the empty space under the balances, anchored to the bottom left corner.
    const QRect balances{ui->frame->geometry()};
    const QRect area{QPoint{balances.left(), balances.bottom() + 16}, QPoint{balances.right(), height() - 8}};
    if (area.height() < 60) return;
    QSize size{m_watermark.size()};
    size.scale(area.size() * 0.7, Qt::KeepAspectRatio);
    const QRect target{QPoint{area.left(), area.bottom() - size.height() + 1}, size};
    QPainter painter{this};
    painter.setRenderHint(QPainter::SmoothPixmapTransform);
    painter.drawPixmap(target, m_watermark);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::setPrivacy(bool privacy)
{
    m_privacy = privacy;
    clientModel->getOptionsModel()->setOption(OptionsModel::OptionID::MaskValues, privacy);
    const auto& balances = walletModel->getCachedBalance();
    if (balances.balance != -1) {
        setBalance(balances);
    }

    ui->listTransactions->setVisible(!m_privacy);

    const QString status_tip = m_privacy ? tr("Privacy mode activated for the Overview tab. To unmask the values, uncheck Settings->Mask values.") : "";
    setStatusTip(status_tip);
    QStatusTipEvent event(status_tip);
    QApplication::sendEvent(this, &event);
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(const interfaces::WalletBalances& balances)
{
    NitoUnit unit = walletModel->getOptionsModel()->getDisplayUnit();
    if (m_available_balance_sync_pending != balances.available_balance_sync_pending) {
        m_available_balance_sync_pending = balances.available_balance_sync_pending;
        updateStatusIcons();
        updateAlertLabel();
    }
    const CAmount transparent_available = balances.balance;
    const CAmount transparent_pending = balances.unconfirmed_balance;
    const bool show_private_split = walletModel->privateTxUiEnabled();
    const CAmount private_available = show_private_split ? balances.private_balance : 0;
    const CAmount private_pending = show_private_split ? balances.unconfirmed_private_balance : 0;
    const CAmount available_total = transparent_available + private_available;
    const CAmount pending_total = transparent_pending + private_pending;
    const CAmount total_balance = available_total + pending_total + balances.immature_balance;

    if (walletModel->wallet().isLegacy()) {
        if (walletModel->wallet().privateKeysDisabled()) {
            ui->labelBalance->setText(NitoUnits::formatWithPrivacy(unit, balances.watch_only_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelUnconfirmed->setText(NitoUnits::formatWithPrivacy(unit, balances.unconfirmed_watch_only_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelImmature->setText(NitoUnits::formatWithPrivacy(unit, balances.immature_watch_only_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelTotal->setText(NitoUnits::formatWithPrivacy(unit, balances.watch_only_balance + balances.unconfirmed_watch_only_balance + balances.immature_watch_only_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
        } else {
            ui->labelBalance->setText(NitoUnits::formatWithPrivacy(unit, available_total, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelUnconfirmed->setText(NitoUnits::formatWithPrivacy(unit, pending_total, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelImmature->setText(NitoUnits::formatWithPrivacy(unit, balances.immature_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelTotal->setText(NitoUnits::formatWithPrivacy(unit, total_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelWatchAvailable->setText(NitoUnits::formatWithPrivacy(unit, balances.watch_only_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelWatchPending->setText(NitoUnits::formatWithPrivacy(unit, balances.unconfirmed_watch_only_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelWatchImmature->setText(NitoUnits::formatWithPrivacy(unit, balances.immature_watch_only_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
            ui->labelWatchTotal->setText(NitoUnits::formatWithPrivacy(unit, balances.watch_only_balance + balances.unconfirmed_watch_only_balance + balances.immature_watch_only_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
        }
    } else {
        ui->labelBalance->setText(NitoUnits::formatWithPrivacy(unit, available_total, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
        ui->labelUnconfirmed->setText(NitoUnits::formatWithPrivacy(unit, pending_total, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
        ui->labelImmature->setText(NitoUnits::formatWithPrivacy(unit, balances.immature_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
        ui->labelTotal->setText(NitoUnits::formatWithPrivacy(unit, total_balance, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
    }
    ui->labelTransparentBalanceText->setVisible(show_private_split);
    ui->labelTransparentBalance->setVisible(show_private_split);
    ui->labelPrivateBalanceText->setVisible(show_private_split);
    ui->labelPrivateBalance->setVisible(show_private_split);
    ui->labelTransparentBalance->setText(NitoUnits::formatWithPrivacy(unit, transparent_available, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelPrivateBalance->setText(NitoUnits::formatWithPrivacy(unit, private_available, NitoUnits::SeparatorStyle::ALWAYS, m_privacy));

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = balances.immature_balance != 0;
    bool showWatchOnlyImmature = balances.immature_watch_only_balance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelWatchImmature->setVisible(!walletModel->wallet().privateKeysDisabled() && showWatchOnlyImmature); // show watch-only immature balance
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    ui->lineWatchBalance->setVisible(showWatchOnly);    // show watch-only balance separator line
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance

    if (!showWatchOnly)
        ui->labelWatchImmature->hide();
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if (model) {
        // Show warning, for example if this is a prerelease version
        connect(model, &ClientModel::alertsChanged, this, &OverviewPage::updateAlerts);
        updateAlerts(model->getStatusBarWarnings());

        connect(model->getOptionsModel(), &OptionsModel::fontForMoneyChanged, this, &OverviewPage::setMonospacedFont);
        setMonospacedFont(clientModel->getOptionsModel()->getFontForMoney());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        connect(filter.get(), &TransactionFilterProxy::rowsInserted, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &TransactionFilterProxy::rowsRemoved, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &TransactionFilterProxy::rowsMoved, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &QAbstractItemModel::modelReset, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &QAbstractItemModel::layoutChanged, this, &OverviewPage::LimitTransactionRows);
        LimitTransactionRows();
        // Keep up to date with wallet
        setBalance(model->getCachedBalance());
        connect(model, &WalletModel::balanceChanged, this, &OverviewPage::setBalance);
        connect(model, &WalletModel::showProgress, this, &OverviewPage::setWalletScanProgress);
        connect(model, &WalletModel::privateTxActivationChanged, this, [this](bool) {
            setBalance(walletModel->getCachedBalance());
        });

        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &OverviewPage::updateDisplayUnit);
        connect(model->getOptionsModel(), &OptionsModel::bech32xOrchardReceiveAddressesChanged, this, [this](bool) {
            setBalance(walletModel->getCachedBalance());
        });

        interfaces::Wallet& wallet = model->wallet();
        updateWatchOnlyLabels(wallet.haveWatchOnly() && !wallet.privateKeysDisabled());
        connect(model, &WalletModel::notifyWatchonlyChanged, [this](bool showWatchOnly) {
            updateWatchOnlyLabels(showWatchOnly && !walletModel->wallet().privateKeysDisabled());
        });
    }

    // update the display unit, to not use the default ("NITO")
    updateDisplayUnit();
}

void OverviewPage::changeEvent(QEvent* e)
{
    if (e->type() == QEvent::PaletteChange) {
        updateStatusIcons();
        updateAboutPanel();
    }

    QWidget::changeEvent(e);
}

// Only show most recent NUM_ITEMS rows
void OverviewPage::LimitTransactionRows()
{
    if (filter && ui->listTransactions && ui->listTransactions->model() && filter.get() == ui->listTransactions->model()) {
        for (int i = 0; i < filter->rowCount(); ++i) {
            ui->listTransactions->setRowHidden(i, i >= NUM_ITEMS);
        }
    }
}

void OverviewPage::updateDisplayUnit()
{
    if (walletModel && walletModel->getOptionsModel()) {
        const auto& balances = walletModel->getCachedBalance();
        if (balances.balance != -1) {
            setBalance(balances);
        }

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    m_status_bar_warnings = warnings;
    updateAlertLabel();
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    m_out_of_sync_warning = fShow;
    updateStatusIcons();
}

void OverviewPage::setMonospacedFont(const QFont& f)
{
    ui->labelBalance->setFont(f);
    ui->labelUnconfirmed->setFont(f);
    ui->labelImmature->setFont(f);
    ui->labelTotal->setFont(f);
    ui->labelWatchAvailable->setFont(f);
    ui->labelWatchPending->setFont(f);
    ui->labelWatchImmature->setFont(f);
    ui->labelWatchTotal->setFont(f);
}

void OverviewPage::setWalletScanProgress(const QString& title, int progress)
{
    Q_UNUSED(title);
    m_wallet_scan_in_progress = progress < 100;
    updateStatusIcons();
}

void OverviewPage::updateAlertLabel()
{
    QStringList messages;
    if (!m_status_bar_warnings.isEmpty()) {
        messages.append(m_status_bar_warnings);
    }
    if (m_available_balance_sync_pending) {
        messages.append(tr("The displayed information may be out of date. Your wallet automatically synchronizes with the Nito network after a connection is established, but this process has not completed yet."));
    }

    const QString text = messages.join(QStringLiteral("\n"));
    ui->labelAlerts->setVisible(!text.isEmpty());
    ui->labelAlerts->setText(text);
}

void OverviewPage::updateStatusIcons()
{
    const bool show_status = m_out_of_sync_warning || m_wallet_scan_in_progress || m_available_balance_sync_pending;
    const QString icon_path = m_wallet_scan_in_progress ? QStringLiteral(":/icons/transaction_3") : QStringLiteral(":/icons/warning");
    const QIcon icon = m_platform_style->SingleColorIcon(icon_path);
    const QString tooltip = m_wallet_scan_in_progress
        ? tr("Wallet scan in progress. Transparent and private balances may still be loading.")
        : tr("The displayed information may be out of date. Your wallet automatically synchronizes with the Nito network after a connection is established, but this process has not completed yet.");

    ui->labelWalletStatus->setIcon(icon);
    ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setToolTip(tooltip);
    ui->labelTransactionsStatus->setToolTip(tooltip);
    ui->labelWalletStatus->setVisible(show_status);
    ui->labelTransactionsStatus->setVisible(show_status);
}
