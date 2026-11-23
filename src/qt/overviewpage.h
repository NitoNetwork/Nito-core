// Copyright (c) 2011-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OVERVIEWPAGE_H
#define BITCOIN_QT_OVERVIEWPAGE_H

#include <interfaces/wallet.h>

#include <QPixmap>
#include <QString>
#include <QWidget>
#include <memory>

class ClientModel;
class TransactionFilterProxy;
class TxViewDelegate;
class PlatformStyle;
class WalletModel;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QLabel;
class QModelIndex;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void showOutOfSyncWarning(bool fShow);

public Q_SLOTS:
    void setBalance(const interfaces::WalletBalances& balances);
    void setPrivacy(bool privacy);

Q_SIGNALS:
    void transactionClicked(const QModelIndex &index);
    void outOfSyncWarningClicked();

protected:
    void changeEvent(QEvent* e) override;
    void paintEvent(QPaintEvent* e) override;

private:
    //! Client name, version and links in the bottom left corner.
    void setupAboutPanel();
    void updateAboutPanel();
    void updateAboutLinks();

    Ui::OverviewPage *ui;
    QPixmap m_watermark; //!< large faint Nito N in the bottom left corner
    QLabel* m_about_links{nullptr};
    QString m_hovered_link; //!< link under the mouse in the about panel
    QWidget* m_about_panel{nullptr};
    ClientModel* clientModel{nullptr};
    WalletModel* walletModel{nullptr};
    bool m_privacy{false};

    const PlatformStyle* m_platform_style;

    TxViewDelegate *txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;
    bool m_out_of_sync_warning{true};
    bool m_wallet_scan_in_progress{false};
    bool m_available_balance_sync_pending{false};
    QString m_status_bar_warnings;

    void updateStatusIcons();
    void updateAlertLabel();

private Q_SLOTS:
    void LimitTransactionRows();
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void updateAlerts(const QString &warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void setMonospacedFont(const QFont&);
    void setWalletScanProgress(const QString& title, int progress);
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
