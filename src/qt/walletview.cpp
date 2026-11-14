// Copyright (c) 2011-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletview.h>

#include <qt/addressbookpage.h>
#include <qt/askpassphrasedialog.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/receivecoinsdialog.h>
#include <qt/sendcoinsdialog.h>
#include <qt/signverifymessagedialog.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <node/interface_ui.h>
#include <util/translation.h>

#include <QAction>
#include <QCoreApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QProgressDialog>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

WalletView::WalletView(WalletModel* wallet_model, const PlatformStyle* _platformStyle, QWidget* parent)
    : QStackedWidget(parent),
      walletModel(wallet_model),
      platformStyle(_platformStyle)
{
    assert(walletModel);

    // Create tabs
    overviewPage = new OverviewPage(platformStyle);
    overviewPage->setWalletModel(walletModel);

    lockedPage = new QWidget(this);
    auto* lockedLayout = new QVBoxLayout(lockedPage);
    auto* lockedLabel = new QLabel(QCoreApplication::translate("NitoGUI", "Wallet is <b>encrypted</b> and currently <b>locked</b>"), lockedPage);
    auto* unlockButton = new QPushButton(QCoreApplication::translate("AskPassphraseDialog", "Unlock wallet"), lockedPage);
    lockedLabel->setAlignment(Qt::AlignCenter);
    lockedLabel->setTextFormat(Qt::RichText);
    lockedLabel->setWordWrap(true);
    lockedLayout->addStretch();
    lockedLayout->addWidget(lockedLabel, 0, Qt::AlignCenter);
    lockedLayout->addWidget(unlockButton, 0, Qt::AlignCenter);
    lockedLayout->addStretch();
    connect(unlockButton, &QPushButton::clicked, this, &WalletView::unlockWalletForDisplay);

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    QHBoxLayout *hbox_buttons = new QHBoxLayout();
    transactionView = new TransactionView(platformStyle, this);
    transactionView->setModel(walletModel);

    vbox->addWidget(transactionView);
    QPushButton *exportButton = new QPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
    if (platformStyle->getImagesOnButtons()) {
        exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }
    hbox_buttons->addStretch();
    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    transactionsPage->setLayout(vbox);

    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle);
    receiveCoinsPage->setModel(walletModel);

    sendCoinsPage = new SendCoinsDialog(platformStyle);
    sendCoinsPage->setModel(walletModel);

    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedSendingAddressesPage->setModel(walletModel->getAddressTableModel());

    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);
    usedReceivingAddressesPage->setModel(walletModel->getAddressTableModel());

    addWidget(overviewPage);
    addWidget(lockedPage);
    addWidget(transactionsPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);

    connect(overviewPage, &OverviewPage::transactionClicked, this, &WalletView::transactionClicked);
    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, &OverviewPage::transactionClicked, transactionView, qOverload<const QModelIndex&>(&TransactionView::focusTransaction));

    connect(overviewPage, &OverviewPage::outOfSyncWarningClicked, this, &WalletView::outOfSyncWarningClicked);

    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, this, &WalletView::coinsSent);
    // Highlight transaction after send
    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, transactionView, qOverload<const uint256&>(&TransactionView::focusTransaction));

    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, &QPushButton::clicked, transactionView, &TransactionView::exportClicked);

    // Pass through messages from sendCoinsPage
    connect(sendCoinsPage, &SendCoinsDialog::message, this, &WalletView::message);
    // Pass through messages from transactionView
    connect(transactionView, &TransactionView::message, this, &WalletView::message);

    connect(this, &WalletView::setPrivacy, overviewPage, &OverviewPage::setPrivacy);
    connect(this, &WalletView::setPrivacy, this, &WalletView::disableTransactionView);

    // Receive and pass through messages from wallet model
    connect(walletModel, &WalletModel::message, this, &WalletView::message);

    // Handle changes in encryption status
    connect(walletModel, &WalletModel::encryptionStatusChanged, this, [this] {
        if (isLockedForDisplay()) {
            setCurrentWidget(lockedPage);
        } else if (currentWidget() == lockedPage) {
            setCurrentWidget(overviewPage);
        }
        Q_EMIT encryptionStatusChanged();
    });

    // Balloon pop-up for new transactions, excluding technical row rebuilds.
    connect(walletModel->getTransactionTableModel(), &TransactionTableModel::transactionInserted, this, &WalletView::processNewTransaction);

    // Ask for passphrase if needed
    connect(walletModel, &WalletModel::requireUnlock, this, &WalletView::unlockWallet);

    // Show progress dialog
    connect(walletModel, &WalletModel::showProgress, this, &WalletView::showProgress);

    showLockedPageIfNeeded();
}

WalletView::~WalletView() = default;

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(_clientModel);
    sendCoinsPage->setClientModel(_clientModel);
    walletModel->setClientModel(_clientModel);
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    if (isLockedForDisplay()) return;

    // Prevent balloon-spam when initial block download is in progress
    if (!clientModel || clientModel->node().isInitialBlockDownload()) {
        return;
    }

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QModelIndex index = ttm->index(start, 0, parent);
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = GUIUtil::HtmlEscape(ttm->data(index, TransactionTableModel::LabelRole).toString());

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label, GUIUtil::HtmlEscape(walletModel->getWalletName()));
}

void WalletView::gotoOverviewPage()
{
    if (showLockedPageIfNeeded()) return;
    setCurrentWidget(overviewPage);
}

void WalletView::gotoHistoryPage()
{
    if (showLockedPageIfNeeded()) return;
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    if (showLockedPageIfNeeded()) return;
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    if (showLockedPageIfNeeded()) return;
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty())
        sendCoinsPage->setAddress(addr);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    if (showLockedPageIfNeeded()) return;

    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    if (showLockedPageIfNeeded()) return;

    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    if (isLockedForDisplay()) return false;
    return sendCoinsPage->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

bool WalletView::isLockedForDisplay() const
{
    return walletModel && !walletModel->isDisplayAuthorized();
}

bool WalletView::showLockedPageIfNeeded()
{
    if (!isLockedForDisplay()) return false;
    setCurrentWidget(lockedPage);
    return true;
}

void WalletView::encryptWallet()
{
    auto dlg = new AskPassphraseDialog(AskPassphraseDialog::Encrypt, this);
    dlg->setModel(walletModel);
    connect(dlg, &QDialog::finished, this, [this](int result) {
        if (result == QDialog::Accepted && walletModel->getEncryptionStatus() == WalletModel::Unlocked) {
            walletModel->setDisplayAuthorized(true);
            if (!walletModel->setWalletLockedForDisplay()) {
                walletModel->setDisplayAuthorized(false);
            }
        }
        walletModel->updateStatus();
        if (isLockedForDisplay()) {
            setCurrentWidget(lockedPage);
        } else if (currentWidget() == lockedPage) {
            setCurrentWidget(overviewPage);
        }
        Q_EMIT encryptionStatusChanged();
    });
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

void WalletView::unlockWalletForDisplay()
{
    if (!walletModel || walletModel->isDisplayAuthorized()) return;

    if (walletModel->getEncryptionStatus() == WalletModel::Locked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        if (dlg.exec() != QDialog::Accepted) return;
        walletModel->setDisplayAuthorized(true);
        if (!walletModel->setWalletLockedForDisplay()) {
            walletModel->setDisplayAuthorized(false);
            return;
        }
        walletModel->updateStatus();
        walletModel->forceBalanceUpdate();
    } else {
        walletModel->setDisplayAuthorized(true);
    }
    gotoOverviewPage();
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        //: Name of the wallet data file format.
        tr("Wallet Data") + QLatin1String(" (*.dat)"), nullptr);

    if (filename.isEmpty())
        return;

    if (!walletModel->wallet().backupWallet(filename.toLocal8Bit().data())) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::showHDSeedMnemonic()
{
    const bool bip39_passphrase_required{walletModel->isBIP39PassphraseEnabled()};
    QString confirmation_text{tr("The recovery phrase controls the funds derived from its documented scope. Keep wallet.dat backups for V3 or imported transparent keys. Only reveal the phrase in a private place and store it offline.")};
    if (bip39_passphrase_required) {
        confirmation_text += QLatin1String("\n\n") + tr("This wallet requires the BIP39 passphrase you saved separately. The passphrase is not shown here. Restoring with the recovery phrase alone opens a different wallet.");
    }
    QMessageBox confirmation(QMessageBox::Warning,
        tr("Show Recovery Phrase"),
        confirmation_text,
        QMessageBox::Ok | QMessageBox::Cancel,
        this);
    confirmation.setDefaultButton(QMessageBox::Cancel);
    GUIUtil::PolishMessageBox(&confirmation);
    const auto confirmed = static_cast<QMessageBox::StandardButton>(confirmation.exec());
    if (confirmed != QMessageBox::Ok) return;

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) return;

    QString mnemonic;
    QString error;
    if (!walletModel->getHDSeedMnemonic(mnemonic, error)) {
        Q_EMIT message(tr("Recovery Phrase"), error, CClientUIInterface::MSG_ERROR);
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Recovery Phrase"));
    auto* layout = new QVBoxLayout(&dialog);

    QString warning_text{tr("Write these words down in order. Anyone with this phrase can spend the funds it covers. A wallet upgraded from V3 still requires its wallet.dat backup for older transparent keys.")};
    if (bip39_passphrase_required) {
        warning_text += QLatin1String("\n\n") + tr("BIP39 passphrase required: the passphrase is not displayed or stored with these words. You need the exact passphrase saved separately; the recovery phrase alone opens a different wallet.");
    }
    auto* warning = new QLabel(warning_text);
    warning->setWordWrap(true);
    layout->addWidget(warning);

    auto* phrase = new QTextEdit(&dialog);
    phrase->setPlainText(mnemonic);
    phrase->setReadOnly(true);
    phrase->setLineWrapMode(QTextEdit::WidgetWidth);
    phrase->setMinimumWidth(520);
    phrase->setMinimumHeight(130);
    layout->addWidget(phrase);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    GUIUtil::PolishDialogButtonBox(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);

    dialog.exec();
    phrase->setPlainText(QString(mnemonic.size(), QChar{0}));
    phrase->clear();
    mnemonic.fill(QChar{0});
    mnemonic.clear();
}

void WalletView::changePassphrase()
{
    auto dlg = new AskPassphraseDialog(AskPassphraseDialog::ChangePass, this);
    dlg->setModel(walletModel);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

void WalletView::unlockWallet()
{
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        // A modal dialog must be synchronous here as expected
        // in the WalletModel::requestUnlock() function.
        dlg.exec();
        walletModel->updateStatus();
        if (!isLockedForDisplay() && currentWidget() == lockedPage) {
            setCurrentWidget(overviewPage);
        }
    }
}

void WalletView::usedSendingAddresses()
{
    GUIUtil::bringToFront(usedSendingAddressesPage);
}

void WalletView::usedReceivingAddresses()
{
    GUIUtil::bringToFront(usedReceivingAddressesPage);
}

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0) {
        progressDialog = new QProgressDialog(title, tr("Cancel"), 0, 100, window());
        GUIUtil::PolishProgressDialog(progressDialog);
        progressDialog->setWindowTitle(title);
        progressDialog->setWindowModality(Qt::WindowModal);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
        progressDialog->show();
        GUIUtil::CenterDialogOnParent(progressDialog, this);
    } else if (nProgress == 100) {
        if (progressDialog) {
            progressDialog->close();
            progressDialog->deleteLater();
            progressDialog = nullptr;
        }
    } else if (progressDialog) {
        if (progressDialog->wasCanceled()) {
            getWalletModel()->wallet().abortRescan();
        } else {
            progressDialog->setValue(nProgress);
        }
    }
}

void WalletView::disableTransactionView(bool disable)
{
    transactionView->setDisabled(disable);
}
