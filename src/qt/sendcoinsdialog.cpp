// Copyright (c) 2011-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/nito-config.h>
#endif

#include <qt/sendcoinsdialog.h>
#include <qt/forms/ui_sendcoinsdialog.h>

#include <qt/addresstablemodel.h>
#include <qt/nitounits.h>
#include <qt/clientmodel.h>
#include <qt/coincontroldialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/psbtoperationsdialog.h>
#include <qt/sendcoinsentry.h>

#include <chainparams.h>
#include <interfaces/node.h>
#include <node/interface_ui.h>
#include <policy/fees.h>
#include <private/private_address.h>
#include <txmempool.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>

#include <array>
#include <chrono>
#include <memory>

#include <QFontMetrics>
#include <QCheckBox>
#include <QLayout>
#include <QPalette>
#include <QProgressDialog>
#include <QScrollBar>
#include <QSettings>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QTextDocument>
#include <QtGlobal>

using wallet::CCoinControl;
using wallet::DEFAULT_PAY_TX_FEE;

static constexpr std::array confTargets{2, 4, 6, 12, 24, 48, 144, 504, 1008};
int getConfTargetForIndex(int index) {
    if (index+1 > static_cast<int>(confTargets.size())) {
        return confTargets.back();
    }
    if (index < 0) {
        return confTargets[0];
    }
    return confTargets[index];
}
int getIndexForConfTarget(int target) {
    for (unsigned int i = 0; i < confTargets.size(); i++) {
        if (confTargets[i] >= target) {
            return i;
        }
    }
    return confTargets.size() - 1;
}

static bool IsPrivateSendFlow(const QList<SendCoinsRecipient>& recipients, const CCoinControl& coin_control)
{
    if (coin_control.m_private_tx_source == CCoinControl::PrivateTxSource::PRIVATE_NOTES) {
        return true;
    }
    for (const SendCoinsRecipient& rcp : recipients) {
        std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> raw_private_address{};
        std::string private_address_error;
        if (wallet::DecodeNitoPrivateAddress(rcp.address.toStdString(), Params(), raw_private_address, private_address_error)) {
            return true;
        }
    }
    return false;
}

SendCoinsDialog::SendCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::SendCoinsDialog),
    m_coin_control(new CCoinControl),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);
    m_prepare_timer.setInterval(25);
    connect(&m_prepare_timer, &QTimer::timeout, this, &SendCoinsDialog::pollPrivatePreparation);

    const bool dark_palette{palette().color(QPalette::Window).lightness() < 128};
    const QString panel_border{dark_palette ? QStringLiteral("rgba(96, 173, 255, 0.50)") : QStringLiteral("#9fcbf3")};
    const QString panel_background{dark_palette ? QStringLiteral("rgba(27, 117, 188, 0.16)") : QStringLiteral("#eef7ff")};
    const QString panel_style{QStringLiteral("QFrame#frameCoinControl, QFrame#frameFee { border: 1px solid %1; border-radius: 4px; background: %2; }").arg(panel_border, panel_background)};
    ui->frameCoinControl->setStyleSheet(panel_style);
    ui->frameFee->setStyleSheet(panel_style);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->addButton->setIcon(QIcon());
        ui->clearButton->setIcon(QIcon());
        ui->sendButton->setIcon(QIcon());
    } else {
        ui->addButton->setIcon(_platformStyle->SingleColorIcon(":/icons/add"));
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->sendButton->setIcon(_platformStyle->SingleColorIcon(":/icons/send"));
    }

    addEntry();

    connect(ui->addButton, &QPushButton::clicked, this, &SendCoinsDialog::addEntry);
    connect(ui->clearButton, &QPushButton::clicked, this, &SendCoinsDialog::clear);

    // Coin Control
    connect(ui->pushButtonCoinControl, &QPushButton::clicked, this, &SendCoinsDialog::coinControlButtonClicked);

    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAfterFee);
    connect(clipboardBytesAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardBytes);
    connect(clipboardChangeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardChange);
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    // init transaction fee section
    QSettings settings;
    if (!settings.contains("fFeeSectionMinimized"))
        settings.setValue("fFeeSectionMinimized", true);
    if (!settings.contains("nFeeRadio") && settings.contains("nTransactionFee") && settings.value("nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("nFeeRadio", 1); // custom
    if (!settings.contains("nFeeRadio"))
        settings.setValue("nFeeRadio", 0); // recommended
    if (!settings.contains("nSmartFeeSliderPosition"))
        settings.setValue("nSmartFeeSliderPosition", 0);
    if (!settings.contains("nTransactionFee"))
        settings.setValue("nTransactionFee", (qint64)DEFAULT_PAY_TX_FEE);
    ui->groupFee->setId(ui->radioSmartFee, 0);
    ui->groupFee->setId(ui->radioCustomFee, 1);
    ui->groupFee->button((int)std::max(0, std::min(1, settings.value("nFeeRadio").toInt())))->setChecked(true);
    ui->customFee->SetAllowEmpty(false);
    ui->customFee->setValue(settings.value("nTransactionFee").toLongLong());
    minimizeFeeSection(settings.value("fFeeSectionMinimized").toBool());

    GUIUtil::ExceptionSafeConnect(ui->sendButton, &QPushButton::clicked, this, &SendCoinsDialog::sendButtonClicked);
}

void SendCoinsDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel) {
        connect(_clientModel, &ClientModel::numBlocksChanged, this, &SendCoinsDialog::updateNumberOfBlocks);
    }
}

void SendCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;
    m_model_guard = _model;

    if(_model && _model->getOptionsModel())
    {
        for(int i = 0; i < ui->entries->count(); ++i)
        {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if(entry)
            {
                entry->setModel(_model);
            }
        }

        connect(_model, &WalletModel::balanceChanged, this, &SendCoinsDialog::setBalance);
        connect(_model, &WalletModel::privateTxActivationChanged, this, [this](bool) {
            updatePrivateTxControls();
            refreshBalance();
        });
        connect(_model, &WalletModel::encryptionStatusChanged, this, [this] {
            updatePrivateTxControls();
            refreshBalance();
        });
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::refreshBalance);
        connect(_model->getOptionsModel(), &OptionsModel::bech32xOrchardReceiveAddressesChanged, this, [this](bool) {
            updatePrivateTxControls();
            refreshBalance();
        });
        refreshBalance();
        updatePrivateTxControls();

        // Coin Control
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(_model->getOptionsModel(), &OptionsModel::coinControlFeaturesChanged, this, &SendCoinsDialog::coinControlFeatureChanged);
        ui->frameCoinControl->setVisible(_model->getOptionsModel()->getCoinControlFeatures() || _model->privateTxUiEnabled());
        coinControlUpdateLabels();

        // fee section
        for (const int n : confTargets) {
            ui->confTargetSelector->addItem(tr("%1 (%2 blocks)").arg(GUIUtil::formatNiceTimeOffset(n*Params().GetConsensus().nPowTargetSpacing)).arg(n));
        }
        connect(ui->confTargetSelector, qOverload<int>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(ui->confTargetSelector, qOverload<int>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::coinControlUpdateLabels);

        connect(ui->groupFee, &QButtonGroup::idClicked, this, &SendCoinsDialog::updateFeeSectionControls);
        connect(ui->groupFee, &QButtonGroup::idClicked, this, &SendCoinsDialog::coinControlUpdateLabels);

        connect(ui->customFee, &NitoAmountField::valueChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
#if QT_VERSION >= QT_VERSION_CHECK(6, 7, 0)
        connect(ui->optInRBF, &QCheckBox::checkStateChanged, this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(ui->optInRBF, &QCheckBox::checkStateChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->checkBoxUsePrivateBalance, &QCheckBox::checkStateChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
#else
        connect(ui->optInRBF, &QCheckBox::stateChanged, this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(ui->optInRBF, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->checkBoxUsePrivateBalance, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
#endif
        connect(ui->checkBoxUsePrivateBalance, &QCheckBox::toggled, this, &SendCoinsDialog::updateCoinControlState);
        CAmount requiredFee = model->wallet().getRequiredFee(1000);
        ui->customFee->SetMinValue(requiredFee);
        if (ui->customFee->value() < requiredFee) {
            ui->customFee->setValue(requiredFee);
        }
        ui->customFee->setSingleStep(requiredFee);
        updateFeeSectionControls();
        updateSmartFeeLabel();

        // set default rbf checkbox state
        ui->optInRBF->setCheckState(Qt::Checked);

        if (model->wallet().hasExternalSigner()) {
            //: "device" usually means a hardware wallet.
            ui->sendButton->setText(tr("Sign on device"));
            if (model->getOptionsModel()->hasSigner()) {
                ui->sendButton->setEnabled(true);
                ui->sendButton->setToolTip(tr("Connect your hardware wallet first."));
            } else {
                ui->sendButton->setEnabled(false);
                //: "External signer" means using devices such as hardware wallets.
                ui->sendButton->setToolTip(tr("Set external signer script path in Options -> Wallet"));
            }
        } else if (model->wallet().privateKeysDisabled()) {
            ui->sendButton->setText(tr("Cr&eate Unsigned"));
            ui->sendButton->setToolTip(tr("Creates a Partially Signed Nito Transaction (PSBT) for use with e.g. an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
        }

        // set the smartfee-sliders default value (wallets default conf.target or last stored value)
        QSettings settings;
        if (settings.value("nSmartFeeSliderPosition").toInt() != 0) {
            // migrate nSmartFeeSliderPosition to nConfTarget
            // nConfTarget is available since 0.15 (replaced nSmartFeeSliderPosition)
            int nConfirmTarget = 25 - settings.value("nSmartFeeSliderPosition").toInt(); // 25 == old slider range
            settings.setValue("nConfTarget", nConfirmTarget);
            settings.remove("nSmartFeeSliderPosition");
        }
        if (settings.value("nConfTarget").toInt() == 0)
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(model->wallet().getConfirmTarget()));
        else
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(settings.value("nConfTarget").toInt()));
    }
}

SendCoinsDialog::~SendCoinsDialog()
{
    m_prepare_timer.stop();
    if (m_prepare_task && m_model_guard) {
        // Proof construction is not interruptible. Mark cancellation before
        // joining so its late result can never be shown or committed.
        m_model_guard->cancelAndJoinPrepareTransaction(m_prepare_task);
    }
    m_prepare_task.reset();
    m_send_unlock_context.reset();

    QSettings settings;
    settings.setValue("fFeeSectionMinimized", fFeeMinimized);
    settings.setValue("nFeeRadio", ui->groupFee->checkedId());
    settings.setValue("nConfTarget", getConfTargetForIndex(ui->confTargetSelector->currentIndex()));
    settings.setValue("nTransactionFee", (qint64)ui->customFee->value());

    delete ui;
}

bool SendCoinsDialog::PrepareSendText(QString& question_string, QString& informative_text, QString& detailed_text)
{
    QList<SendCoinsRecipient> recipients;
    bool valid = true;
    for (int i = 0; i < ui->entries->count(); ++i) {
        auto* entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (!entry) continue;
        if (entry->validate(model->node())) {
            recipients.append(entry->getValue());
        } else if (valid) {
            ui->scrollArea->ensureWidgetVisible(entry);
            valid = false;
        }
    }
    if (!valid || recipients.isEmpty()) return false;

    fNewRecipientAllowed = false;
    m_current_transaction = std::make_unique<WalletModelTransaction>(recipients);
    updateCoinControlState();
    CCoinControl coin_control = *m_coin_control;
    coin_control.m_allow_other_inputs = !coin_control.HasSelected();

    if (IsPrivateSendFlow(recipients, coin_control)) {
        m_send_unlock_context = model->requestUnlockContext();
        if (!m_send_unlock_context->isValid()) {
            m_send_unlock_context.reset();
            fNewRecipientAllowed = true;
            return false;
        }
        const auto async = model->prepareTransactionAsync(*m_current_transaction, coin_control, m_send_unlock_context);
        if (!async.task) return finalizePreparedTransaction(async.status, question_string, informative_text, detailed_text);

        m_prepare_task = async.task;
        m_prepare_cancelled = false;
        ui->sendButton->setEnabled(false);
        ui->entries->setEnabled(false);
        ui->frameCoinControl->setEnabled(false);
        ui->frameFee->setEnabled(false);
        m_prepare_progress = new QProgressDialog(tr("Creating private transaction proof..."), tr("Cancel"), 0, 0, this);
        GUIUtil::PolishProgressDialog(m_prepare_progress);
        m_prepare_progress->setWindowModality(Qt::WindowModal);
        m_prepare_progress->setMinimumDuration(0);
        connect(m_prepare_progress, &QProgressDialog::canceled, this, &SendCoinsDialog::cancelPrivatePreparation);
        m_prepare_progress->show();
        m_prepare_timer.start();
        return false;
    }

    WalletModel::UnlockContext unlock_context(model->requestUnlock());
    if (!unlock_context.isValid()) {
        fNewRecipientAllowed = true;
        return false;
    }
    return finalizePreparedTransaction(model->prepareTransaction(*m_current_transaction, coin_control), question_string, informative_text, detailed_text);
}

bool SendCoinsDialog::finalizePreparedTransaction(const WalletModel::SendCoinsReturn& prepareStatus, QString& question_string, QString& informative_text, QString& detailed_text)
{
    // process prepareStatus and on error generate message shown to user
    processSendCoinsReturn(prepareStatus,
        NitoUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), m_current_transaction->getTransactionFee()));

    if(prepareStatus.status != WalletModel::OK) {
        m_send_unlock_context.reset();
        fNewRecipientAllowed = true;
        return false;
    }

    CAmount txFee = m_current_transaction->getTransactionFee();
    QStringList formatted;
    for (const SendCoinsRecipient &rcp : m_current_transaction->getRecipients())
    {
        // generate amount string with wallet name in case of multiwallet
        QString amount = NitoUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
        if (model->isMultiwallet()) {
            amount = tr("%1 from wallet '%2'").arg(amount, GUIUtil::HtmlEscape(model->getWalletName()));
        }

        // generate address string
        QString address = rcp.address;

        QString recipientElement;

        {
            if(rcp.label.length() > 0) // label with address
            {
                recipientElement.append(tr("%1 to '%2'").arg(amount, GUIUtil::HtmlEscape(rcp.label)));
                recipientElement.append(QString(" (%1)").arg(address));
            }
            else // just address
            {
                recipientElement.append(tr("%1 to %2").arg(amount, address));
            }
        }
        formatted.append(recipientElement);
    }

    /*: Message displayed when attempting to create a transaction. Cautionary text to prompt the user to verify
        that the displayed transaction details represent the transaction the user intends to create. */
    question_string.append(tr("Do you want to create this transaction?"));
    question_string.append("<br /><span style='font-size:10pt;'>");
    if (model->wallet().privateKeysDisabled() && !model->wallet().hasExternalSigner()) {
        /*: Text to inform a user attempting to create a transaction of their current options. At this stage,
            a user can only create a PSBT. This string is displayed when private keys are disabled and an external
            signer is not available. */
        question_string.append(tr("Please, review your transaction proposal. This will produce a Partially Signed Nito Transaction (PSBT) which you can save or copy and then sign with e.g. an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
    } else if (model->getOptionsModel()->getEnablePSBTControls()) {
        /*: Text to inform a user attempting to create a transaction of their current options. At this stage,
            a user can send their transaction or create a PSBT. This string is displayed when both private keys
            and PSBT controls are enabled. */
        question_string.append(tr("Please, review your transaction. You can create and send this transaction or create a Partially Signed Nito Transaction (PSBT), which you can save or copy and then sign with, e.g., an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
    } else {
        /*: Text to prompt a user to review the details of the transaction they are attempting to send. */
        question_string.append(tr("Please, review your transaction."));
    }
    question_string.append("</span>%1");
    question_string.append("<hr /><b>");
    question_string.append(tr("Funding source"));
    question_string.append("</b>: ");
    question_string.append(ui->checkBoxUsePrivateBalance->isChecked() ? tr("Private balance") : tr("Transparent balance"));

    if(txFee > 0)
    {
        // append fee string if a fee is required
        question_string.append("<hr /><b>");
        question_string.append(tr("Transaction fee"));
        question_string.append("</b>");

        // append transaction size
        //: When reviewing a newly created PSBT (via Send flow), the transaction fee is shown, with "virtual size" of the transaction displayed for context
        question_string.append(" (" + tr("%1 kvB", "PSBT transaction creation").arg((double)m_current_transaction->getTransactionSize() / 1000, 0, 'g', 3) + "): ");

        // append transaction fee value
        question_string.append("<span style='color:#aa0000; font-weight:bold;'>");
        question_string.append(NitoUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), txFee));
        question_string.append("</span><br />");

        // append RBF message according to transaction's signalling
        question_string.append("<span style='font-size:10pt; font-weight:normal;'>");
        if (ui->optInRBF->isChecked()) {
            question_string.append(tr("You can increase the fee later (signals Replace-By-Fee, BIP-125)."));
        } else {
            question_string.append(tr("Not signalling Replace-By-Fee, BIP-125."));
        }
        question_string.append("</span>");
    }

    // add total amount in all subdivision units
    question_string.append("<hr />");
    CAmount totalAmount = m_current_transaction->getTotalTransactionAmount() + txFee;
    QStringList alternativeUnits;
    for (const NitoUnit u : NitoUnits::availableUnits()) {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(NitoUnits::formatHtmlWithUnit(u, totalAmount));
    }
    question_string.append(QString("<b>%1</b>: <b>%2</b>").arg(tr("Total Amount"))
        .arg(NitoUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    question_string.append(QString("<br /><span style='font-size:10pt; font-weight:normal;'>(=%1)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + " ")));

    if (formatted.size() > 1) {
        question_string = question_string.arg("");
        informative_text = tr("To review recipient list click \"Show Details...\"");
        detailed_text = formatted.join("\n\n");
    } else {
        question_string = question_string.arg("<br /><br />" + formatted.at(0));
    }

    return true;
}

void SendCoinsDialog::cancelPrivatePreparation()
{
    if (!m_prepare_task || !m_model_guard) return;
    m_prepare_cancelled = true;
    // The underlying proof cannot be stopped safely. The completed result is
    // discarded, and no confirmation or commit is permitted after cancellation.
    m_model_guard->cancelPrepareTransaction(m_prepare_task);
}

void SendCoinsDialog::pollPrivatePreparation()
{
    if (!m_prepare_task || !m_model_guard || !m_current_transaction) return;
    const auto status = m_model_guard->finishPrepareTransaction(m_prepare_task, *m_current_transaction);
    if (!status) return;

    m_prepare_timer.stop();
    if (m_prepare_progress) {
        // close() emits canceled(), including when preparation succeeded.
        m_prepare_progress->hide();
        m_prepare_progress->deleteLater();
        m_prepare_progress = nullptr;
    }
    m_prepare_task.reset();
    ui->sendButton->setEnabled(true);
    ui->entries->setEnabled(true);
    ui->frameCoinControl->setEnabled(true);
    ui->frameFee->setEnabled(true);

    if (m_prepare_cancelled) {
        m_send_unlock_context.reset();
        m_current_transaction.reset();
        fNewRecipientAllowed = true;
        return;
    }

    QString question_string, informative_text, detailed_text;
    if (finalizePreparedTransaction(*status, question_string, informative_text, detailed_text)) {
        showSendConfirmation(question_string, informative_text, detailed_text);
    }
}

void SendCoinsDialog::presentPSBT(PartiallySignedTransaction& psbtx)
{
    PSBTOperationsDialog dialog(this, model, &model->clientModel());
    dialog.openWithPSBT(psbtx);
    dialog.exec();
}

bool SendCoinsDialog::signWithExternalSigner(PartiallySignedTransaction& psbtx, CMutableTransaction& mtx, bool& complete) {
    TransactionError err;
    try {
        const std::optional<uint256> private_intent_hash{psbtx.GetNitoPrivateIntentHash()};
        err = model->wallet().fillPSBT(SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/true, /*n_signed=*/nullptr, psbtx, complete, private_intent_hash);
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(nullptr, tr("Sign failed"), e.what());
        return false;
    }
    if (err == TransactionError::EXTERNAL_SIGNER_NOT_FOUND) {
        //: "External signer" means using devices such as hardware wallets.
        const QString msg = tr("External signer not found");
        QMessageBox::critical(nullptr, msg, msg);
        return false;
    }
    if (err == TransactionError::EXTERNAL_SIGNER_FAILED) {
        //: "External signer" means using devices such as hardware wallets.
        const QString msg = tr("External signer failure");
        QMessageBox::critical(nullptr, msg, msg);
        return false;
    }
    if (err != TransactionError::OK) {
        tfm::format(std::cerr, "Failed to sign PSBT");
        processSendCoinsReturn(WalletModel::TransactionCreationFailed);
        return false;
    }
    // fillPSBT does not always properly finalize
    complete = FinalizeAndExtractPSBT(psbtx, mtx);
    return true;
}

bool SendCoinsDialog::fillCurrentTransactionPSBT(PartiallySignedTransaction& psbtx, bool sign, CMutableTransaction& mtx, bool& complete)
{
    assert(m_current_transaction);
    mtx = CMutableTransaction{*(m_current_transaction->getWtx())};
    if (!m_current_transaction->getPrivatePSBTRecords().empty() && mtx.m_private_bundle) {
        mtx.m_private_bundle->auth.reset();
    }

    psbtx = PartiallySignedTransaction(mtx);
    for (const auto& entry : m_current_transaction->getPrivatePSBTRecords()) {
        psbtx.m_proprietary.insert(entry);
    }

    complete = false;
    TransactionError err = model->wallet().fillPSBT(SIGHASH_ALL, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, psbtx, complete);
    if (err != TransactionError::OK) {
        processSendCoinsReturn(WalletModel::TransactionCreationFailed);
        return false;
    }
    if (!sign) {
        return true;
    }

    std::optional<uint256> private_intent_hash;
    try {
        private_intent_hash = psbtx.GetNitoPrivateIntentHash();
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(nullptr, tr("Sign failed"), e.what());
        return false;
    }
    err = model->wallet().fillPSBT(SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, psbtx, complete, private_intent_hash);
    if (err != TransactionError::OK) {
        processSendCoinsReturn(WalletModel::TransactionCreationFailed);
        return false;
    }
    complete = FinalizeAndExtractPSBT(psbtx, mtx);
    if (!complete) {
        presentPSBT(psbtx);
        return false;
    }
    return true;
}

void SendCoinsDialog::sendButtonClicked([[maybe_unused]] bool checked)
{
    if(!model || !model->getOptionsModel())
        return;

    QString question_string, informative_text, detailed_text;
    if (!PrepareSendText(question_string, informative_text, detailed_text)) return;
    showSendConfirmation(question_string, informative_text, detailed_text);
}

void SendCoinsDialog::showSendConfirmation(const QString& question_string, const QString& informative_text, const QString& detailed_text)
{
    assert(m_current_transaction);

    const QString confirmation = tr("Confirm send coins");
    const bool enable_send{!model->wallet().privateKeysDisabled() || model->wallet().hasExternalSigner()};
    const bool always_show_unsigned{model->getOptionsModel()->getEnablePSBTControls()};
    auto confirmationDialog = new SendConfirmationDialog(confirmation, question_string, informative_text, detailed_text, SEND_CONFIRM_DELAY, enable_send, always_show_unsigned, this);
    confirmationDialog->setAttribute(Qt::WA_DeleteOnClose);
    // TODO: Replace QDialog::exec() with safer QDialog::show().
    const auto retval = static_cast<QMessageBox::StandardButton>(confirmationDialog->exec());

    if(retval != QMessageBox::Yes && retval != QMessageBox::Save)
    {
        m_send_unlock_context.reset();
        fNewRecipientAllowed = true;
        return;
    }

    bool send_failure = false;
    if (retval == QMessageBox::Save) {
        // "Create Unsigned" clicked
        CMutableTransaction mtx;
        PartiallySignedTransaction psbtx;
        bool complete = false;
        send_failure = !fillCurrentTransactionPSBT(psbtx, /*sign=*/false, mtx, complete);
        if (!send_failure) {
            presentPSBT(psbtx);
        }
    } else {
        // "Send" clicked
        assert(!model->wallet().privateKeysDisabled() || model->wallet().hasExternalSigner());
        bool broadcast = true;
        if (m_current_transaction->isPrivatePSBTDraft()) {
            CMutableTransaction mtx;
            PartiallySignedTransaction psbtx;
            bool complete = false;
            send_failure = !fillCurrentTransactionPSBT(psbtx, /*sign=*/true, mtx, complete);
            broadcast = complete && !send_failure;
            if (broadcast) {
                m_current_transaction->setWtx(MakeTransactionRef(mtx));
            }
        } else if (model->wallet().hasExternalSigner()) {
            CMutableTransaction mtx = CMutableTransaction{*(m_current_transaction->getWtx())};
            PartiallySignedTransaction psbtx(mtx);
            bool complete = false;
            // Always fill without signing first. This prevents an external signer
            // from being called prematurely and is not expensive.
            TransactionError err = model->wallet().fillPSBT(SIGHASH_ALL, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, psbtx, complete);
            assert(!complete);
            assert(err == TransactionError::OK);
            send_failure = !signWithExternalSigner(psbtx, mtx, complete);
            // Don't broadcast when user rejects it on the device or there's a failure:
            broadcast = complete && !send_failure;
            if (!send_failure) {
                // A transaction signed with an external signer is not always complete,
                // e.g. in a multisig wallet.
                if (complete) {
                    // Prepare transaction for broadcast transaction if complete
                    const CTransactionRef tx = MakeTransactionRef(mtx);
                    m_current_transaction->setWtx(tx);
                } else {
                    presentPSBT(psbtx);
                }
            }
        }

        // Broadcast the transaction, unless an external signer was used and it
        // failed, or more signatures are needed.
        if (broadcast) {
            // now send the prepared transaction
            send_failure = !model->sendCoins(*m_current_transaction);
            if (!send_failure) {
                Q_EMIT coinsSent(m_current_transaction->getWtx()->GetHash());
            }
        }
    }
    if (!send_failure) {
        accept();
        m_coin_control->UnSelectAll();
        coinControlUpdateLabels();
    }
    fNewRecipientAllowed = true;
    m_current_transaction.reset();
    m_send_unlock_context.reset();
}

void SendCoinsDialog::clear()
{
    if (m_prepare_task && m_model_guard) {
        m_prepare_timer.stop();
        m_prepare_cancelled = true;
        m_model_guard->cancelAndJoinPrepareTransaction(m_prepare_task);
        m_prepare_task.reset();
    }
    ui->sendButton->setEnabled(true);
    ui->entries->setEnabled(true);
    ui->frameCoinControl->setEnabled(true);
    ui->frameFee->setEnabled(true);
    if (m_prepare_progress) {
        m_prepare_progress->hide();
        m_prepare_progress->deleteLater();
        m_prepare_progress = nullptr;
    }
    m_current_transaction.reset();
    m_send_unlock_context.reset();

    // Clear coin control settings
    m_coin_control->UnSelectAll();
    ui->checkBoxUsePrivateBalance->setChecked(false);
    coinControlUpdateLabels();

    // Remove entries until only one left
    while(ui->entries->count())
    {
        // takeAt() transfers ownership of the layout item to the caller.
        // Schedule the entry for deletion and free the item itself, which
        // LeakSanitizer otherwise reports at shutdown.
        QLayoutItem* item = ui->entries->takeAt(0);
        if (QWidget* widget = item->widget()) {
            widget->deleteLater();
        }
        delete item;
    }
    addEntry();

    updateTabsAndLabels();
}

void SendCoinsDialog::reject()
{
    clear();
}

void SendCoinsDialog::accept()
{
    clear();
}

SendCoinsEntry *SendCoinsDialog::addEntry()
{
    SendCoinsEntry *entry = new SendCoinsEntry(platformStyle, this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, &SendCoinsEntry::removeEntry, this, &SendCoinsDialog::removeEntry);
    connect(entry, &SendCoinsEntry::useAvailableBalance, this, &SendCoinsDialog::useAvailableBalance);
    connect(entry, &SendCoinsEntry::payAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
    connect(entry, &SendCoinsEntry::subtractFeeFromAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());

    // Scroll to the newly added entry on a QueuedConnection because Qt doesn't
    // adjust the scroll area and scrollbar immediately when the widget is added.
    // Invoking on a DirectConnection will only scroll to the second-to-last entry.
    QMetaObject::invokeMethod(ui->scrollArea, [this] {
        if (ui->scrollArea->verticalScrollBar()) {
            ui->scrollArea->verticalScrollBar()->setValue(ui->scrollArea->verticalScrollBar()->maximum());
        }
    }, Qt::QueuedConnection);

    updateTabsAndLabels();
    return entry;
}

void SendCoinsDialog::updateTabsAndLabels()
{
    setupTabChain(nullptr);
    coinControlUpdateLabels();
}

void SendCoinsDialog::removeEntry(SendCoinsEntry* entry)
{
    entry->hide();

    // If the last entry is about to be removed add an empty one
    if (ui->entries->count() == 1)
        addEntry();

    entry->deleteLater();

    updateTabsAndLabels();
}

QWidget *SendCoinsDialog::setupTabChain(QWidget *prev)
{
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->sendButton);
    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
    QWidget::setTabOrder(ui->clearButton, ui->addButton);
    return ui->addButton;
}

void SendCoinsDialog::setAddress(const QString &address)
{
    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setAddress(address);
}

void SendCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
    updateTabsAndLabels();
}

bool SendCoinsDialog::handlePaymentRequest(const SendCoinsRecipient &rv)
{
    // Just paste the entry, all pre-checks
    // are done in paymentserver.cpp.
    pasteEntry(rv);
    return true;
}

void SendCoinsDialog::setBalance(const interfaces::WalletBalances& balances)
{
    if(model && model->getOptionsModel())
    {
        CAmount transparent_balance = balances.balance;
        const bool private_active = model->privateTxUiEnabled();
        CAmount private_balance = private_active ? balances.private_balance : 0;
        CAmount balance = transparent_balance + private_balance;
        bool show_private_balances = private_active;
        if (model->wallet().hasExternalSigner()) {
            balance = transparent_balance;
            show_private_balances = false;
            ui->labelBalanceName->setText(tr("External balance:"));
        } else if (model->wallet().isLegacy() && model->wallet().privateKeysDisabled()) {
            balance = balances.watch_only_balance;
            transparent_balance = balances.watch_only_balance;
            private_balance = 0;
            show_private_balances = false;
            ui->labelBalanceName->setText(tr("Watch-only balance:"));
        } else {
            ui->labelBalanceName->setText(tr("Total balance:"));
        }
        ui->labelBalance->setText(NitoUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balance));
        ui->labelTransparentBalanceName->setVisible(show_private_balances);
        ui->labelTransparentBalance->setVisible(show_private_balances);
        ui->labelPrivateBalanceName->setVisible(show_private_balances);
        ui->labelPrivateBalance->setVisible(show_private_balances);
        ui->labelTransparentBalance->setText(NitoUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), transparent_balance));
        ui->labelPrivateBalance->setText(NitoUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), private_balance));
    }
}

void SendCoinsDialog::updatePrivateTxControls()
{
    if (!model) return;

    const bool show_private_controls = model->privateTxUiEnabled() &&
        !model->wallet().hasExternalSigner();

    if (!show_private_controls && ui->checkBoxUsePrivateBalance->isChecked()) {
        ui->checkBoxUsePrivateBalance->setChecked(false);
    }
    ui->checkBoxUsePrivateBalance->setVisible(show_private_controls);
    ui->checkBoxUsePrivateBalance->setEnabled(show_private_controls);
    if (model->getOptionsModel()) {
        ui->frameCoinControl->setVisible(model->getOptionsModel()->getCoinControlFeatures() || show_private_controls);
    }
    updateCoinControlState();
}

void SendCoinsDialog::refreshBalance()
{
    setBalance(model->getCachedBalance());
    ui->customFee->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    updateSmartFeeLabel();
}

void SendCoinsDialog::processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SendCoinsDialog usage of WalletModel::SendCoinsReturn.
    // All status values are used only in WalletModel::prepareTransaction()
    switch(sendCoinsReturn.status)
    {
    case WalletModel::InvalidAddress:
        msgParams.first = tr("The recipient address is not valid. Please recheck.");
        break;
    case WalletModel::InvalidAmount:
        msgParams.first = tr("The amount to pay must be larger than 0.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("The amount exceeds your balance.");
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        msgParams.first = tr("The total exceeds your balance when the %1 transaction fee is included.").arg(msgArg);
        break;
    case WalletModel::TransactionCreationFailed:
        msgParams.first = tr("Transaction creation failed!");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::AbsurdFee:
        msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(NitoUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), model->wallet().getDefaultMaxTxFee()));
        break;
    // included to prevent a compiler warning.
    case WalletModel::OK:
    default:
        return;
    }

    Q_EMIT message(tr("Send Coins"), msgParams.first, msgParams.second);
}

void SendCoinsDialog::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee  ->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutSmartFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    ui->frameFee->setSizePolicy(QSizePolicy::Expanding, fMinimize ? QSizePolicy::Maximum : QSizePolicy::Expanding);
    const int minimized_height{ui->horizontalLayoutFee1->sizeHint().height() + 18};
    ui->frameFee->setMinimumHeight(fMinimize ? minimized_height : 0);
    ui->frameFee->setMaximumHeight(fMinimize ? minimized_height : QWIDGETSIZE_MAX);
    ui->frameFee->layout()->activate();
    ui->frameFee->updateGeometry();
    fFeeMinimized = fMinimize;
}

void SendCoinsDialog::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void SendCoinsDialog::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void SendCoinsDialog::useAvailableBalance(SendCoinsEntry* entry)
{
    updateCoinControlState();
    // Include watch-only for wallets without private key
    m_coin_control->fAllowWatchOnly = model->wallet().privateKeysDisabled() && !model->wallet().hasExternalSigner();

    // Same behavior as send: if we have selected coins, only obtain their available balance.
    // Copy to avoid modifying the member's data.
    CCoinControl coin_control = *m_coin_control;
    coin_control.m_allow_other_inputs = !coin_control.HasSelected();

    // Calculate available amount to send.
    CAmount amount = model->getAvailableBalance(&coin_control);
    QList<SendCoinsRecipient> recipients;
    int target_recipient_index{-1};
    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry* e = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (e && !e->isHidden() && e != entry) {
            const SendCoinsRecipient recipient{e->getValue()};
            recipients.append(recipient);
            amount -= recipient.amount;
        } else if (e && !e->isHidden()) {
            target_recipient_index = recipients.size();
            SendCoinsRecipient recipient{e->getValue()};
            recipient.fSubtractFeeFromAmount = true;
            recipients.append(recipient);
        }
    }

    if (amount > 0) {
        entry->checkSubtractFeeFromAmount();
        const CAmount single_tx_amount{model->getMaximumSingleTransactionAmount(recipients, target_recipient_index, coin_control, amount)};
        if (single_tx_amount > 0 && single_tx_amount < amount) {
            Q_EMIT message(
                tr("Send Coins"),
                tr("The wallet has many small UTXOs. The amount was reduced to the largest value that fits in one standard transaction. Send again after confirmation to continue consolidating."),
                CClientUIInterface::MSG_INFORMATION);
        }
        entry->setAmount(single_tx_amount > 0 ? single_tx_amount : amount);
    } else {
        entry->setAmount(0);
    }
}

void SendCoinsDialog::updateFeeSectionControls()
{
    ui->confTargetSelector      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee           ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee2          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee3          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelFeeEstimation      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelCustomFeeWarning   ->setEnabled(ui->radioCustomFee->isChecked());
    ui->labelCustomPerKilobyte  ->setEnabled(ui->radioCustomFee->isChecked());
    ui->customFee               ->setEnabled(ui->radioCustomFee->isChecked());
}

void SendCoinsDialog::updateFeeMinimizedLabel()
{
    if(!model || !model->getOptionsModel())
        return;

    if (ui->radioSmartFee->isChecked())
        ui->labelFeeMinimized->setText(ui->labelSmartFee->text());
    else {
        ui->labelFeeMinimized->setText(tr("%1/kvB").arg(NitoUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), ui->customFee->value())));
    }
}

void SendCoinsDialog::updateCoinControlState()
{
    if (ui->radioCustomFee->isChecked()) {
        m_coin_control->m_feerate = CFeeRate(ui->customFee->value());
    } else {
        m_coin_control->m_feerate.reset();
    }
    // Avoid using global defaults when sending money from the GUI
    // Either custom fee will be used or if not selected, the confirmation target from dropdown box
    m_coin_control->m_confirm_target = getConfTargetForIndex(ui->confTargetSelector->currentIndex());
    m_coin_control->m_signal_bip125_rbf = ui->optInRBF->isChecked();
    const auto private_tx_source = (model && model->privateTxUiEnabled() && ui->checkBoxUsePrivateBalance->isChecked())
        ? CCoinControl::PrivateTxSource::PRIVATE_NOTES
        : CCoinControl::PrivateTxSource::AUTO;
    if (m_coin_control->m_private_tx_source != private_tx_source) {
        m_coin_control->UnSelectAll();
    }
    m_coin_control->m_private_tx_source = private_tx_source;
    m_coin_control->destChange = CNoDestination();
    // Include watch-only for wallets without private key
    m_coin_control->fAllowWatchOnly = model->wallet().privateKeysDisabled() && !model->wallet().hasExternalSigner();
}

void SendCoinsDialog::updateNumberOfBlocks(int count, const QDateTime& blockDate, double nVerificationProgress, SyncType synctype, SynchronizationState sync_state) {
    if (sync_state == SynchronizationState::POST_INIT) {
        updatePrivateTxControls();
        updateSmartFeeLabel();
    }
}

void SendCoinsDialog::updateSmartFeeLabel()
{
    if(!model || !model->getOptionsModel())
        return;
    updateCoinControlState();
    m_coin_control->m_feerate.reset(); // Explicitly use only fee estimation rate for smart fee labels
    int returned_target;
    FeeReason reason;
    CFeeRate feeRate = CFeeRate(model->wallet().getMinimumFee(1000, *m_coin_control, &returned_target, &reason));

    ui->labelSmartFee->setText(tr("%1/kvB").arg(NitoUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), feeRate.GetFeePerK())));

    if (reason == FeeReason::FALLBACK) {
        ui->labelSmartFee2->show(); // (Smart fee not initialized yet. This usually takes a few blocks...)
        ui->labelFeeEstimation->setText("");
        ui->fallbackFeeWarningLabel->setVisible(true);
        int lightness = ui->fallbackFeeWarningLabel->palette().color(QPalette::WindowText).lightness();
        QColor warning_colour(255 - (lightness / 5), 176 - (lightness / 3), 48 - (lightness / 14));
        ui->fallbackFeeWarningLabel->setStyleSheet("QLabel { color: " + warning_colour.name() + "; }");
        ui->fallbackFeeWarningLabel->setIndent(GUIUtil::TextWidth(QFontMetrics(ui->fallbackFeeWarningLabel->font()), "x"));
    }
    else
    {
        ui->labelSmartFee2->hide();
        ui->labelFeeEstimation->setText(tr("Estimated to begin confirmation within %n block(s).", "", returned_target));
        ui->fallbackFeeWarningLabel->setVisible(false);
    }

    updateFeeMinimizedLabel();
}

// Coin Control: copy label "Quantity" to clipboard
void SendCoinsDialog::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void SendCoinsDialog::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void SendCoinsDialog::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void SendCoinsDialog::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void SendCoinsDialog::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Change" to clipboard
void SendCoinsDialog::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: settings menu - coin control enabled/disabled by user
void SendCoinsDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked || (model && model->privateTxUiEnabled()));

    if (!checked && model) { // coin control features disabled
        m_coin_control = std::make_unique<CCoinControl>();
    }

    coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void SendCoinsDialog::coinControlButtonClicked()
{
    updateCoinControlState();
    auto dlg = new CoinControlDialog(*m_coin_control, model, platformStyle);
    connect(dlg, &QDialog::finished, this, &SendCoinsDialog::coinControlUpdateLabels);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

// Coin Control: update labels
void SendCoinsDialog::coinControlUpdateLabels()
{
    if (!model || !model->getOptionsModel())
        return;

    updateCoinControlState();

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    CoinControlDialog::fSubtractFeeFromAmount = false;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry && !entry->isHidden())
        {
            SendCoinsRecipient rcp = entry->getValue();
            CoinControlDialog::payAmounts.append(rcp.amount);
            if (rcp.fSubtractFeeFromAmount)
                CoinControlDialog::fSubtractFeeFromAmount = true;
        }
    }

    if (m_coin_control->HasSelected() || m_coin_control->HasSelectedPrivateNotes())
    {
        // actual coin control calculation
        CoinControlDialog::updateLabels(*m_coin_control, model, this);

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}

SendConfirmationDialog::SendConfirmationDialog(const QString& title, const QString& text, const QString& informative_text, const QString& detailed_text, int _secDelay, bool enable_send, bool always_show_unsigned, QWidget* parent)
    : QMessageBox(parent), secDelay(_secDelay), m_enable_send(enable_send)
{
    setIcon(QMessageBox::Question);
    setWindowTitle(title); // On macOS, the window title is ignored (as required by the macOS Guidelines).
    setText(text);
    setInformativeText(informative_text);
    setDetailedText(detailed_text);
    setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    if (always_show_unsigned || !enable_send) addButton(QMessageBox::Save);
    setDefaultButton(QMessageBox::Cancel);
    yesButton = button(QMessageBox::Yes);
    if (confirmButtonText.isEmpty()) {
        confirmButtonText = yesButton->text();
    }
    m_psbt_button = button(QMessageBox::Save);
    m_cancel_button = button(QMessageBox::Cancel);
    localizeButtons();
    updateButtons();
    connect(&countDownTimer, &QTimer::timeout, this, &SendConfirmationDialog::countDown);
}

int SendConfirmationDialog::exec()
{
    localizeButtons();
    updateButtons();
    QTimer::singleShot(0, this, [this] { localizeButtons(); });
    countDownTimer.start(1s);
    return QMessageBox::exec();
}

void SendConfirmationDialog::localizeButtons()
{
    if (m_cancel_button) {
        m_cancel_button->setText(m_cancel_button_text);
    }
    if (!m_details_button) {
        for (QAbstractButton* button : buttons()) {
            const QString text = QString(button->text()).remove('&');
            if (buttonRole(button) == QMessageBox::ActionRole ||
                text.startsWith(QLatin1String("Show Details")) ||
                text.startsWith(QLatin1String("Hide Details"))) {
                m_details_button = button;
                connect(m_details_button, &QAbstractButton::clicked, this, [this] {
                    m_details_visible = !m_details_visible;
                    QTimer::singleShot(0, this, [this] {
                        if (m_details_button) {
                            m_details_button->setText(m_details_visible ? m_hide_details_button_text : m_show_details_button_text);
                        }
                    });
                });
                break;
            }
        }
    }
    if (m_details_button) {
        m_details_button->setText(m_details_visible ? m_hide_details_button_text : m_show_details_button_text);
    }
}

void SendConfirmationDialog::countDown()
{
    secDelay--;
    updateButtons();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void SendConfirmationDialog::updateButtons()
{
    if(secDelay > 0)
    {
        yesButton->setEnabled(false);
        yesButton->setText(confirmButtonText + (m_enable_send ? (" (" + QString::number(secDelay) + ")") : QString("")));
        if (m_psbt_button) {
            m_psbt_button->setEnabled(false);
            m_psbt_button->setText(m_psbt_button_text + " (" + QString::number(secDelay) + ")");
        }
    }
    else
    {
        yesButton->setEnabled(m_enable_send);
        yesButton->setText(confirmButtonText);
        if (m_psbt_button) {
            m_psbt_button->setEnabled(true);
            m_psbt_button->setText(m_psbt_button_text);
        }
    }
}
