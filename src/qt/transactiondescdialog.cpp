// Copyright (c) 2011-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactiondescdialog.h>
#include <qt/forms/ui_transactiondescdialog.h>

#include <qt/guiutil.h>
#include <qt/transactiontablemodel.h>

#include <QModelIndex>
#include <QScrollBar>
#include <QTextBrowser>
#include <QUrl>

TransactionDescDialog::TransactionDescDialog(const QModelIndex &idx, QWidget *parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::TransactionDescDialog)
{
    ui->setupUi(this);
    GUIUtil::PolishDialogButtonBox(ui->buttonBox);
    setWindowTitle(tr("Details for %1").arg(idx.data(TransactionTableModel::TxHashRole).toString()));
    QString desc = idx.data(TransactionTableModel::LongDescriptionRole).toString();
    const QString expanded_desc = idx.data(TransactionTableModel::ExpandedInputAddressesRole).toString();
    ui->detailText->setHtml(desc);
    ui->detailText->setOpenLinks(false);
    ui->detailText->setOpenExternalLinks(false);
    connect(ui->detailText, &QTextBrowser::anchorClicked, this,
            [this, desc, expanded_desc, expanded = false](const QUrl& url) mutable {
        if (url != QUrl("#input-addresses")) return;
        expanded = !expanded;
        const int scroll = ui->detailText->verticalScrollBar()->value();
        ui->detailText->setHtml(expanded ? expanded_desc : desc);
        ui->detailText->verticalScrollBar()->setValue(scroll);
    });

    GUIUtil::handleCloseWindowShortcut(this);
}

TransactionDescDialog::~TransactionDescDialog()
{
    delete ui;
}
