// Copyright (c) 2011-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <interfaces/node.h>
#include <qt/receivecoinsdialog.h>
#include <qt/forms/ui_receivecoinsdialog.h>

#include <qt/addresstablemodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/walletmodel.h>
#include <util/result.h>
#include <wallet/address_type.h>

#include <QAction>
#include <QCursor>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QTimer>

ReceiveCoinsDialog::ReceiveCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::ReceiveCoinsDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->clearButton->setIcon(QIcon());
        ui->receiveButton->setIcon(QIcon());
        ui->showRequestButton->setIcon(QIcon());
        ui->removeRequestButton->setIcon(QIcon());
    } else {
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->receiveButton->setIcon(_platformStyle->SingleColorIcon(":/icons/receiving_addresses"));
        ui->showRequestButton->setIcon(_platformStyle->SingleColorIcon(":/icons/eye"));
        ui->removeRequestButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
    }

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(tr("Copy &URI"), this, &ReceiveCoinsDialog::copyURI);
    contextMenu->addAction(tr("&Copy address"), this, &ReceiveCoinsDialog::copyAddress);
    copyLabelAction = contextMenu->addAction(tr("Copy &label"), this, &ReceiveCoinsDialog::copyLabel);
    copyMessageAction = contextMenu->addAction(tr("Copy &message"), this, &ReceiveCoinsDialog::copyMessage);
    copyAmountAction = contextMenu->addAction(tr("Copy &amount"), this, &ReceiveCoinsDialog::copyAmount);
    connect(ui->recentRequestsView, &QWidget::customContextMenuRequested, this, &ReceiveCoinsDialog::showMenu);

    connect(ui->clearButton, &QPushButton::clicked, this, &ReceiveCoinsDialog::clear);

    QTableView* tableView = ui->recentRequestsView;
    tableView->verticalHeader()->hide();
    tableView->setAlternatingRowColors(true);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);

    QSettings settings;
    if (!tableView->horizontalHeader()->restoreState(settings.value("RecentRequestsViewHeaderState").toByteArray())) {
        tableView->setColumnWidth(RecentRequestsTableModel::Date, DATE_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Label, LABEL_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Amount, AMOUNT_MINIMUM_COLUMN_WIDTH);
        tableView->horizontalHeader()->setMinimumSectionSize(MINIMUM_COLUMN_WIDTH);
        tableView->horizontalHeader()->setStretchLastSection(true);
    }
}

void ReceiveCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        _model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ReceiveCoinsDialog::updateDisplayUnit);
        updateDisplayUnit();

        QTableView* tableView = ui->recentRequestsView;
        tableView->setModel(_model->getRecentRequestsTableModel());
        tableView->sortByColumn(RecentRequestsTableModel::Date, Qt::DescendingOrder);

        connect(tableView->selectionModel(),
            &QItemSelectionModel::selectionChanged, this,
            &ReceiveCoinsDialog::recentRequestsView_selectionChanged);

        updateAddressTypes();
        QTimer::singleShot(0, this, [this] {
            updateAddressTypes();
        });
        connect(model, &WalletModel::privateTxActivationChanged, this, [this](bool) {
            updateAddressTypes();
        });
        connect(model, &WalletModel::encryptionStatusChanged, this, [this] {
            updateAddressTypes();
        });
        connect(_model->getOptionsModel(), &OptionsModel::legacyReceiveAddressTypesChanged, this, [this](bool) {
            updateAddressTypes();
        });
        connect(_model->getOptionsModel(), &OptionsModel::bech32xOrchardReceiveAddressesChanged, this, [this](bool) {
            updateAddressTypes();
        });

        // Set the button to be enabled or disabled based on whether the wallet can give out new addresses.
        ui->receiveButton->setEnabled(model->wallet().canGetAddresses());

        // Enable/disable the receive button if the wallet is now able/unable to give out new addresses.
        connect(model, &WalletModel::canGetAddressesChanged, [this] {
            ui->receiveButton->setEnabled(model->wallet().canGetAddresses());
            updateAddressTypes();
        });
    }
}

void ReceiveCoinsDialog::updateAddressTypes()
{
    if (!model || !model->getOptionsModel()) return;

    const QVariant previous_data = ui->addressType->currentData();
    const int previous_kind = previous_data.isValid() ? previous_data.toInt() : -1;
    ui->addressType->clear();

    auto add_address_type = [&](OutputType type, const QString& text, const QString& tooltip) {
        const auto index = ui->addressType->count();
        ui->addressType->addItem(text, static_cast<int>(wallet::WalletAddressKindFromOutputType(type)));
        ui->addressType->setItemData(index, tooltip, Qt::ToolTipRole);
        if (model->wallet().getDefaultAddressType() == type) ui->addressType->setCurrentIndex(index);
    };

    add_address_type(OutputType::BECH32, tr("Bech32 (SegWit)"), tr("Generates a native segwit address."));
    if (model->wallet().taprootEnabled()) {
        add_address_type(OutputType::BECH32M, tr("Bech32m (Taproot)"), tr("Bech32m (BIP-350) is an upgrade to Bech32, wallet support is still limited."));
    }
    if (model->privateTxUiEnabled()) {
        const auto index = ui->addressType->count();
        ui->addressType->addItem(tr("Bech32x (Orchard)"), static_cast<int>(wallet::WalletAddressKind::PRIVATE));
        ui->addressType->setItemData(index, tr("Generates a Bech32x Orchard receiving address starting with nito1x."), Qt::ToolTipRole);
    }
    if (model->getOptionsModel()->getEnableLegacyReceiveAddressTypes()) {
        add_address_type(OutputType::LEGACY, tr("Legacy (P2PKH)"), tr("Generates a legacy address starting with 1."));
        add_address_type(OutputType::P2SH_SEGWIT, tr("P2SH-SegWit"), tr("Generates a P2SH-wrapped SegWit address starting with 3."));
    }

    if (previous_kind >= 0) {
        const int index = ui->addressType->findData(previous_kind);
        if (index >= 0) ui->addressType->setCurrentIndex(index);
    }
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    QSettings settings;
    settings.setValue("RecentRequestsViewHeaderState", ui->recentRequestsView->horizontalHeader()->saveState());
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    ui->reqAmount->clear();
    ui->reqLabel->setText("");
    ui->reqMessage->setText("");
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        ui->reqAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    if(!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    QString address;
    QString label = ui->reqLabel->text();
    /* Generate new receiving address */
    const auto address_kind = static_cast<wallet::WalletAddressKind>(ui->addressType->currentData().toInt());
    const bool private_address = wallet::IsPrivateWalletAddressKind(address_kind);
    if (private_address) {
        if (!model->privateTxActive()) {
            QMessageBox::critical(this, windowTitle(),
                tr("Nito.network private transactions activate at block %1. Current block: %2.")
                    .arg(model->privateTxActivationHeight())
                    .arg(model->node().getNumBlocks()),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        auto op_address = model->getNewPrivateAddress(/*internal=*/false);
        if (!op_address) {
            QMessageBox::critical(this, windowTitle(),
                QString::fromStdString(util::ErrorString(op_address).translated),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        address = QString::fromStdString(*op_address);
    } else {
        const auto address_type = wallet::OutputTypeFromWalletAddressKind(address_kind).value_or(OutputType::BECH32);
        address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "", address_type);
    }

    const auto edit_status = private_address ? AddressTableModel::OK : model->getAddressTableModel()->getEditStatus();
    switch(edit_status)
    {
    case AddressTableModel::EditStatus::OK: {
        // Success
        SendCoinsRecipient info(address, label,
            ui->reqAmount->value(), ui->reqMessage->text());
        ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setModel(model);
        dialog->setInfo(info);
        dialog->show();

        /* Store request for later reference */
        model->getRecentRequestsTableModel()->addNewRequest(info);
        break;
    }
    case AddressTableModel::EditStatus::WALLET_UNLOCK_FAILURE:
        QMessageBox::critical(this, windowTitle(),
            tr("Could not unlock wallet."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case AddressTableModel::EditStatus::KEY_GENERATION_FAILURE:
        QMessageBox::critical(this, windowTitle(),
            tr("Could not generate new %1 address").arg(QString::fromStdString(FormatOutputType(wallet::OutputTypeFromWalletAddressKind(address_kind).value_or(OutputType::BECH32)))),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    // These aren't valid return values for our action
    case AddressTableModel::EditStatus::INVALID_ADDRESS:
    case AddressTableModel::EditStatus::DUPLICATE_ADDRESS:
    case AddressTableModel::EditStatus::NO_CHANGES:
        assert(false);
    }
    clear();
}

void ReceiveCoinsDialog::on_recentRequestsView_doubleClicked(const QModelIndex &index)
{
    const RecentRequestsTableModel *submodel = model->getRecentRequestsTableModel();
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setModel(model);
    dialog->setInfo(submodel->entry(index.row()).recipient);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();
}

void ReceiveCoinsDialog::recentRequestsView_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    // Enable Show/Remove buttons only if anything is selected.
    bool enable = !ui->recentRequestsView->selectionModel()->selectedRows().isEmpty();
    ui->showRequestButton->setEnabled(enable);
    ui->removeRequestButton->setEnabled(enable);
}

void ReceiveCoinsDialog::on_showRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();

    for (const QModelIndex& index : selection) {
        on_recentRequestsView_doubleClicked(index);
    }
}

void ReceiveCoinsDialog::on_removeRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return;
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    model->getRecentRequestsTableModel()->removeRows(firstIndex.row(), selection.length(), firstIndex.parent());
}

QModelIndex ReceiveCoinsDialog::selectedRow()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return QModelIndex();
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    return firstIndex;
}

// copy column of selected row to clipboard
void ReceiveCoinsDialog::copyColumnToClipboard(int column)
{
    QModelIndex firstIndex = selectedRow();
    if (!firstIndex.isValid()) {
        return;
    }
    GUIUtil::setClipboard(model->getRecentRequestsTableModel()->index(firstIndex.row(), column).data(Qt::EditRole).toString());
}

// context menu
void ReceiveCoinsDialog::showMenu(const QPoint &point)
{
    const QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    // disable context menu actions when appropriate
    const RecentRequestsTableModel* const submodel = model->getRecentRequestsTableModel();
    const RecentRequestEntry& req = submodel->entry(sel.row());
    copyLabelAction->setDisabled(req.recipient.label.isEmpty());
    copyMessageAction->setDisabled(req.recipient.message.isEmpty());
    copyAmountAction->setDisabled(req.recipient.amount == 0);

    contextMenu->exec(QCursor::pos());
}

// context menu action: copy URI
void ReceiveCoinsDialog::copyURI()
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    const RecentRequestsTableModel * const submodel = model->getRecentRequestsTableModel();
    const QString uri = GUIUtil::formatNitoURI(submodel->entry(sel.row()).recipient);
    GUIUtil::setClipboard(uri);
}

// context menu action: copy address
void ReceiveCoinsDialog::copyAddress()
{
    const QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    const RecentRequestsTableModel* const submodel = model->getRecentRequestsTableModel();
    const QString address = submodel->entry(sel.row()).recipient.address;
    GUIUtil::setClipboard(address);
}

// context menu action: copy label
void ReceiveCoinsDialog::copyLabel()
{
    copyColumnToClipboard(RecentRequestsTableModel::Label);
}

// context menu action: copy message
void ReceiveCoinsDialog::copyMessage()
{
    copyColumnToClipboard(RecentRequestsTableModel::Message);
}

// context menu action: copy amount
void ReceiveCoinsDialog::copyAmount()
{
    copyColumnToClipboard(RecentRequestsTableModel::Amount);
}
