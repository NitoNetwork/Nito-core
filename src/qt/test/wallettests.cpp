// Copyright (c) 2015-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/wallettests.h>
#include <qt/test/util.h>

#include <qt/askpassphrasedialog.h>
#include <wallet/coincontrol.h>
#include <index/orchardindex.h>
#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <node/miner.h>
#include <private/private_address.h>
#include <qt/nitoamountfield.h>
#include <qt/nitounits.h>
#include <qt/addresstablemodel.h>
#include <qt/clientmodel.h>
#include <qt/createwalletdialog.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/psbtoperationsdialog.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/receivecoinsdialog.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/sendcoinsrecipient.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactiondesc.h>
#include <qt/transactiondescdialog.h>
#include <qt/transactionrecord.h>
#include <qt/transactionview.h>
#include <qt/walletcontroller.h>
#include <qt/walletframe.h>
#include <qt/walletmodel.h>
#include <qt/walletview.h>
#include <script/solver.h>
#include <script/script.h>
#include <support/cleanse.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/test/util.h>
#include <wallet/bip39.h>
#include <wallet/context.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/address_type.h>

#include <algorithm>
#include <chrono>
#include <atomic>
#include <condition_variable>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QObject>
#include <QPushButton>
#include <QPointer>
#include <QSignalSpy>
#include <QTimer>
#include <QTranslator>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QListView>
#include <QDialogButtonBox>
#include <QDir>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QToolButton>
#include <QStandardItemModel>
#include <QTextBrowser>
#include <QTextCursor>
#include <QTextDocument>

using wallet::AddWallet;
using wallet::CCoinControl;
using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::CreateTransaction;
using wallet::RemoveWallet;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WalletContext;
using wallet::WalletDescriptor;
using wallet::WalletRescanReserver;

namespace
{
enum class PassphraseDialogResponse {
    ACCEPT,
    REJECT,
    WRONG_THEN_REJECT,
};

void RespondToPassphraseDialog(const QString& passphrase, PassphraseDialogResponse response)
{
    auto* timer = new QTimer(qApp);
    timer->setInterval(10);
    QObject::connect(timer, &QTimer::timeout, timer, [timer, passphrase, response] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            auto* dialog = qobject_cast<AskPassphraseDialog*>(widget);
            if (!dialog || !dialog->isVisible()) continue;

            timer->stop();
            timer->deleteLater();
            if (response == PassphraseDialogResponse::REJECT) {
                dialog->reject();
                return;
            }

            auto* passphrase_edit = dialog->findChild<QLineEdit*>("passEdit1");
            assert(passphrase_edit);
            passphrase_edit->setText(passphrase);
            if (response == PassphraseDialogResponse::WRONG_THEN_REJECT) {
                // The incorrect-passphrase message is modal. Close it, then
                // close the still-open unlock dialog to complete the activity.
                QTimer::singleShot(0, qApp, [] {
                    for (QWidget* modal : QApplication::topLevelWidgets()) {
                        if (auto* message = qobject_cast<QMessageBox*>(modal); message && message->isVisible()) {
                            message->accept();
                        }
                    }
                    QTimer::singleShot(0, qApp, [] {
                        for (QWidget* top_level : QApplication::topLevelWidgets()) {
                            if (auto* unlock = qobject_cast<AskPassphraseDialog*>(top_level); unlock && unlock->isVisible()) {
                                unlock->reject();
                            }
                        }
                    });
                });
            }
            dialog->accept();
            return;
        }
    });
    timer->start();
}

//! Press "Yes" or "Cancel" buttons in modal send confirmation dialog.
void ConfirmSend(QString* text = nullptr, QMessageBox::StandardButton confirm_type = QMessageBox::Yes)
{
    QTimer::singleShot(0, [text, confirm_type]() {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("SendConfirmationDialog")) {
                SendConfirmationDialog* dialog = qobject_cast<SendConfirmationDialog*>(widget);
                if (text) *text = dialog->text();
                QAbstractButton* button = dialog->button(confirm_type);
                button->setEnabled(true);
                button->click();
            }
        }
    });
}

//! Send coins to address and return txid.
uint256 SendCoins(CWallet& wallet, SendCoinsDialog& sendCoinsDialog, const CTxDestination& address, CAmount amount, bool rbf,
                  QMessageBox::StandardButton confirm_type = QMessageBox::Yes)
{
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(address)));
    entry->findChild<NitoAmountField*>("payAmount")->setValue(amount);
    sendCoinsDialog.findChild<QFrame*>("frameFee")
        ->findChild<QFrame*>("frameFeeSelection")
        ->findChild<QCheckBox*>("optInRBF")
        ->setCheckState(rbf ? Qt::Checked : Qt::Unchecked);
    uint256 txid;
    boost::signals2::scoped_connection c(wallet.NotifyTransactionChanged.connect([&txid](const uint256& hash, ChangeType status) {
        if (status == CT_NEW) txid = hash;
    }));
    ConfirmSend(/*text=*/nullptr, confirm_type);
    bool invoked = QMetaObject::invokeMethod(&sendCoinsDialog, "sendButtonClicked", Q_ARG(bool, false));
    assert(invoked);
    return txid;
}

//! Send coins to multiple recipients and return txid.
uint256 SendCoinsMulti(CWallet& wallet, SendCoinsDialog& sendCoinsDialog, const std::vector<std::pair<CTxDestination, CAmount>>& recipients)
{
    sendCoinsDialog.clear();
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    for (int i = 1; i < static_cast<int>(recipients.size()); ++i) {
        sendCoinsDialog.addEntry();
    }
    assert(entries->count() == static_cast<int>(recipients.size()));
    for (int i = 0; i < static_cast<int>(recipients.size()); ++i) {
        SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(i)->widget());
        entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(recipients[i].first)));
        entry->findChild<NitoAmountField*>("payAmount")->setValue(recipients[i].second);
    }

    uint256 txid;
    boost::signals2::scoped_connection c(wallet.NotifyTransactionChanged.connect([&txid](const uint256& hash, ChangeType status) {
        if (status == CT_NEW) txid = hash;
    }));
    ConfirmSend();
    bool invoked = QMetaObject::invokeMethod(&sendCoinsDialog, "sendButtonClicked", Q_ARG(bool, false));
    assert(invoked);
    return txid;
}

//! Send coins with a zero-value OP_RETURN message output and return txid.
uint256 SendCoinsWithData(CWallet& wallet, const CTxDestination& address, CAmount amount)
{
    const std::vector<unsigned char> data{0x01, 0x02, 0x03};
    std::vector<wallet::CRecipient> recipients{
        {address, amount, /*fSubtractFeeFromAmount=*/false},
        {CNoDestination{CScript() << OP_RETURN << data}, 0, /*fSubtractFeeFromAmount=*/false},
    };

    CCoinControl coin_control;
    auto res = CreateTransaction(wallet, recipients, /*change_pos=*/std::nullopt, coin_control);
    assert(res);
    assert(wallet.CommitTransaction(res->tx, /*mapValue=*/{}, /*orderForm=*/{}));
    return res->tx->GetHash();
}

//! Find index of txid in transaction list.
QModelIndex FindTx(const QAbstractItemModel& model, const uint256& txid)
{
    QString hash = QString::fromStdString(txid.ToString());
    int rows = model.rowCount({});
    for (int row = 0; row < rows; ++row) {
        QModelIndex index = model.index(row, 0, {});
        if (model.data(index, TransactionTableModel::TxHashRole) == hash) {
            return index;
        }
    }
    return {};
}

//! Invoke bumpfee on txid and check results.
void BumpFee(TransactionView& view, const uint256& txid, bool expectDisabled, std::string expectError, bool cancel)
{
    QTableView* table = view.findChild<QTableView*>("transactionView");
    QModelIndex index = FindTx(*table->selectionModel()->model(), txid);
    QVERIFY2(index.isValid(), "Could not find BumpFee txid");

    // Select row in table, invoke context menu, and make sure bumpfee action is
    // enabled or disabled as expected.
    QAction* action = view.findChild<QAction*>("bumpFeeAction");
    table->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    action->setEnabled(expectDisabled);
    table->customContextMenuRequested({});
    QCOMPARE(action->isEnabled(), !expectDisabled);

    action->setEnabled(true);
    QString text;
    if (expectError.empty()) {
        ConfirmSend(&text, cancel ? QMessageBox::Cancel : QMessageBox::Yes);
    } else {
        ConfirmMessage(&text, 0ms);
    }
    action->trigger();
    QVERIFY(text.indexOf(QString::fromStdString(expectError)) != -1);
}

void CompareBalance(WalletModel& walletModel, CAmount expected_balance, QLabel* balance_label_to_check, NitoUnits::SeparatorStyle separators = NitoUnits::SeparatorStyle::NEVER)
{
    NitoUnit unit = walletModel.getOptionsModel()->getDisplayUnit();
    QString balanceComparison = NitoUnits::formatWithUnit(unit, expected_balance, false, separators);
    QCOMPARE(balance_label_to_check->text().trimmed(), balanceComparison);
}

// Verify the 'useAvailableBalance' functionality. With and without manually selected coins.
// Case 1: No coin control selected coins.
// 'useAvailableBalance' should fill the amount edit box with the total available balance
// Case 2: With coin control selected coins.
// 'useAvailableBalance' should fill the amount edit box with the sum of the selected coins values.
void VerifyUseAvailableBalance(SendCoinsDialog& sendCoinsDialog, const WalletModel& walletModel)
{
    // Verify first entry amount and "useAvailableBalance" button
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries->count() == 1); // only one entry
    SendCoinsEntry* send_entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    QVERIFY(send_entry->getValue().amount == 0);
    // Now click "useAvailableBalance", check updated balance (the entire wallet balance should be set)
    Q_EMIT send_entry->useAvailableBalance(send_entry);
    QVERIFY(send_entry->getValue().amount == walletModel.getCachedBalance().balance);

    // Now manually select two coins and click on "useAvailableBalance". Then check updated balance
    // (only the sum of the selected coins should be set).
    int COINS_TO_SELECT = 2;
    auto coins = walletModel.wallet().listCoins();
    CAmount sum_selected_coins = 0;
    int selected = 0;
    QVERIFY(coins.size() == 1); // context check, coins received only on one destination
    for (const auto& [outpoint, tx_out] : coins.begin()->second) {
        sendCoinsDialog.getCoinControl()->Select(outpoint);
        sum_selected_coins += tx_out.txout.nValue;
        if (++selected == COINS_TO_SELECT) break;
    }
    QVERIFY(selected == COINS_TO_SELECT);

    // Now that we have 2 coins selected, "useAvailableBalance" should update the balance label only with
    // the sum of them.
    Q_EMIT send_entry->useAvailableBalance(send_entry);
    QVERIFY(send_entry->getValue().amount == sum_selected_coins);
}

struct PrepareBarrier {
    std::atomic<bool> entered{false};
    std::mutex mutex;
    std::condition_variable condition;
    bool release{false};

    void wait()
    {
        entered.store(true, std::memory_order_release);
        std::unique_lock<std::mutex> lock{mutex};
        condition.wait_for(lock, std::chrono::seconds{5}, [this] { return release; });
    }

    void signal()
    {
        {
            std::lock_guard<std::mutex> lock{mutex};
            release = true;
        }
        condition.notify_all();
    }
};

class ThreadJoiner {
public:
    explicit ThreadJoiner(std::thread& thread) : m_thread(thread) {}
    ~ThreadJoiner() { if (m_thread.joinable()) m_thread.join(); }

private:
    std::thread& m_thread;
};

SendCoinsRecipient TestRecipient(CAmount amount)
{
    return SendCoinsRecipient{QString::fromStdString(EncodeDestination(PKHash())), {}, amount, {}};
}

WalletModel::AsyncPrepareTransaction StartAsyncPreparation(WalletModel& model, WalletModelTransaction& transaction)
{
    CCoinControl control;
    return model.prepareTransactionAsync(transaction, control, model.requestUnlockContext());
}

void SyncUpWallet(const std::shared_ptr<CWallet>& wallet, interfaces::Node& node)
{
    WalletRescanReserver reserver(*wallet);
    reserver.reserve();
    CWallet::ScanResult result = wallet->ScanForWalletTransactions(Params().GetConsensus().hashGenesisBlock, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/true, /*save_progress=*/false);
    QCOMPARE(result.status, CWallet::ScanResult::SUCCESS);
    QCOMPARE(result.last_scanned_block, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    QVERIFY(result.last_failed_block.IsNull());
}

bool SetWalletLastProcessedToTip(const std::shared_ptr<CWallet>& wallet, interfaces::Node& node)
{
    int tip_height;
    uint256 tip_hash;
    {
        LOCK(node.context()->chainman->GetMutex());
        const CBlockIndex* tip{node.context()->chainman->ActiveChain().Tip()};
        if (!tip) return false;
        tip_height = tip->nHeight;
        tip_hash = tip->GetBlockHash();
    }
    LOCK(wallet->cs_wallet);
    wallet->SetLastBlockProcessed(tip_height, tip_hash);
    return true;
}

std::shared_ptr<CWallet> SetupLegacyWatchOnlyWallet(interfaces::Node& node, TestChain100Setup& test)
{
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    wallet->LoadWallet();
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        wallet->SetupLegacyScriptPubKeyMan();
        // Add watched key
        CPubKey pubKey = test.coinbaseKey.GetPubKey();
        bool import_keys = wallet->ImportPubKeys({pubKey.GetID()}, {{pubKey.GetID(), pubKey}} , /*key_origins=*/{}, /*add_keypool=*/false, /*internal=*/false, /*timestamp=*/1);
        assert(import_keys);
        wallet->SetLastBlockProcessed(105, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    }
    SyncUpWallet(wallet, node);
    return wallet;
}

std::shared_ptr<CWallet> SetupDescriptorsWallet(interfaces::Node& node, TestChain100Setup& test)
{
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    wallet->LoadWallet();
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->SetupDescriptorScriptPubKeyMans();

    // Add the coinbase key
    FlatSigningProvider provider;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse("combo(" + EncodeSecret(test.coinbaseKey) + ")", provider, error, /* require_checksum=*/ false);
    assert(desc);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
    if (!wallet->AddWalletDescriptor(w_desc, provider, "", false)) assert(false);
    CTxDestination dest = GetDestinationForKey(test.coinbaseKey.GetPubKey(), wallet->m_default_address_type);
    wallet->SetAddressBook(dest, "", wallet::AddressPurpose::RECEIVE);
    wallet->SetLastBlockProcessed(105, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    SyncUpWallet(wallet, node);
    wallet->SetBroadcastTransactions(true);
    return wallet;
}

struct MiniGUI {
public:
    SendCoinsDialog sendCoinsDialog;
    TransactionView transactionView;
    OptionsModel optionsModel;
    std::unique_ptr<ClientModel> clientModel;
    std::unique_ptr<WalletModel> walletModel;

    MiniGUI(interfaces::Node& node, const PlatformStyle* platformStyle) : sendCoinsDialog(platformStyle), transactionView(platformStyle), optionsModel(node) {
        bilingual_str error;
        QVERIFY(optionsModel.Init(error));
        clientModel = std::make_unique<ClientModel>(node, &optionsModel);
    }

    void initModelForWallet(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet, const PlatformStyle* platformStyle)
    {
        WalletContext& context = *node.walletLoader().context();
        AddWallet(context, wallet);
        walletModel = std::make_unique<WalletModel>(interfaces::MakeWallet(context, wallet), *clientModel, platformStyle);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
        sendCoinsDialog.setModel(walletModel.get());
        transactionView.setModel(walletModel.get());
    }

};

void TestWalletControllerLifetimes(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet)
{
    std::unique_ptr<const PlatformStyle> platform_style(PlatformStyle::instantiate("other"));
    OptionsModel options_model(node);
    bilingual_str error;
    QVERIFY(options_model.Init(error));
    ClientModel client_model(node, &options_model);
    WalletContext& context = *node.walletLoader().context();

    // Exercise the actual opt-in startup activity with both wallet states.
    // The unencrypted wallet is published automatically, while the encrypted
    // wallet stays loaded and selectable without a passive passphrase prompt.
    {
        const SecureString passphrase{"qt-startup-encrypted-wallet-test"};
        auto encrypted_wallet = std::make_shared<CWallet>(
            node.context()->chain.get(), "qt-startup-encrypted-wallet", CreateMockableWalletDatabase());
        encrypted_wallet->LoadWallet();
        {
            LOCK(encrypted_wallet->cs_wallet);
            auto* legacy_spkm = encrypted_wallet->GetOrCreateLegacyScriptPubKeyMan();
            QVERIFY(legacy_spkm);
            QVERIFY(legacy_spkm->SetupGeneration(true));
        }
        QVERIFY(SetWalletLastProcessedToTip(encrypted_wallet, node));
        QVERIFY(encrypted_wallet->EncryptWallet(passphrase));
        QVERIFY(encrypted_wallet->IsLocked());
        QVERIFY(AddWallet(context, wallet));
        QVERIFY(AddWallet(context, encrypted_wallet));

        {
            WalletController controller(client_model, platform_style.get(), nullptr);
            QSignalSpy added_spy(&controller, &WalletController::walletAdded);
            auto* activity = new LoadWalletsActivity(&controller, nullptr);
            QSignalSpy finished_spy(activity, &LoadWalletsActivity::finished);
            activity->load(/*show_loading_minimized=*/false);
            QTRY_COMPARE_WITH_TIMEOUT(finished_spy.count(), 1, 5000);

            const auto visible_model{controller.findWalletModel(wallet->GetName())};
            const auto hidden_model{controller.findWalletModel("qt-startup-encrypted-wallet")};
            QVERIFY(visible_model);
            QVERIFY(hidden_model);
            QVERIFY(controller.isWalletPublished(visible_model.data()));
            QVERIFY(!controller.isWalletPublished(hidden_model.data()));
            QVERIFY(!hidden_model->isDisplayAuthorized());
            QCOMPARE(added_spy.count(), 1);
            QCOMPARE(static_cast<int>(controller.listWalletDir().at(wallet->GetName())),
                     static_cast<int>(WalletController::WalletDisplayState::PUBLISHED));
            QCOMPARE(static_cast<int>(controller.listWalletDir().at("qt-startup-encrypted-wallet")),
                     static_cast<int>(WalletController::WalletDisplayState::LOADED_HIDDEN));
            QVERIFY(controller.hasOpenableWallet());
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                auto* dialog = qobject_cast<AskPassphraseDialog*>(widget);
                QVERIFY(!dialog || !dialog->isVisible());
            }
        }

        QVERIFY(RemoveWallet(context, encrypted_wallet, /*load_on_start=*/std::nullopt));
        QVERIFY(RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt));
    }

    // A Core-loaded wallet remains selectable until it is published in Qt.
    // Publishing is idempotent, and the empty-wallet button follows the same
    // availability state as the File > Open Wallet menu.
    {
        QVERIFY(AddWallet(context, wallet));
        WalletController controller(client_model, platform_style.get(), nullptr);
        QSignalSpy added_spy(&controller, &WalletController::walletAdded);
        WalletModel* wallet_model = controller.getOrCreateWallet(interfaces::MakeWallet(context, wallet), /*publish=*/false);
        const std::string wallet_name{wallet->GetName()};

        QCOMPARE(static_cast<int>(controller.listWalletDir().at(wallet_name)),
                 static_cast<int>(WalletController::WalletDisplayState::LOADED_HIDDEN));
        QVERIFY(controller.hasOpenableWallet());
        QCOMPARE(added_spy.count(), 0);

        WalletFrame wallet_frame(platform_style.get(), nullptr);
        auto* open_button = wallet_frame.findChild<QPushButton*>("openWalletButton");
        QVERIFY(open_button);
        wallet_frame.setOpenWalletButtonAvailable(controller.hasOpenableWallet());
        QVERIFY(open_button->isEnabled());
        QVERIFY(!open_button->isHidden());

        QVERIFY(controller.publishWallet(wallet_model));
        QCOMPARE(added_spy.count(), 1);
        QCOMPARE(static_cast<int>(controller.listWalletDir().at(wallet_name)),
                 static_cast<int>(WalletController::WalletDisplayState::PUBLISHED));
        QVERIFY(!controller.hasOpenableWallet());
        QVERIFY(controller.publishWallet(wallet_model));
        QCOMPARE(added_spy.count(), 1);

        wallet_frame.setOpenWalletButtonAvailable(controller.hasOpenableWallet());
        QVERIFY(!open_button->isEnabled());
        QVERIFY(open_button->isHidden());
        QVERIFY(RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt));
    }

    // Encrypted wallets loaded by Core are not published until a deliberate
    // Qt authentication. Cancelling or entering a wrong passphrase leaves the
    // wallet loaded, hidden, and retryable. If RPC had already unlocked it,
    // successful display authentication preserves that independent state.
    {
        const SecureString passphrase{"qt-hidden-wallet-test"};
        const SecureString wrong_passphrase{"qt-hidden-wallet-wrong"};
        auto encrypted_wallet = std::make_shared<CWallet>(
            node.context()->chain.get(), "qt-hidden-wallet", CreateMockableWalletDatabase());
        encrypted_wallet->LoadWallet();
        {
            LOCK(encrypted_wallet->cs_wallet);
            auto* legacy_spkm = encrypted_wallet->GetOrCreateLegacyScriptPubKeyMan();
            QVERIFY(legacy_spkm);
            QVERIFY(legacy_spkm->SetupGeneration(true));
        }
        QVERIFY(SetWalletLastProcessedToTip(encrypted_wallet, node));
        QVERIFY(encrypted_wallet->EncryptWallet(passphrase));
        QVERIFY(encrypted_wallet->IsLocked());
        QVERIFY(AddWallet(context, encrypted_wallet));

        WalletController controller(client_model, platform_style.get(), nullptr);
        QSignalSpy added_spy(&controller, &WalletController::walletAdded);
        WalletModel* wallet_model = controller.getOrCreateWallet(
            interfaces::MakeWallet(context, encrypted_wallet), /*publish=*/false);
        QVERIFY(!wallet_model->isDisplayAuthorized());
        QVERIFY(!controller.publishWallet(wallet_model));
        QCOMPARE(static_cast<int>(controller.listWalletDir().at("qt-hidden-wallet")),
                 static_cast<int>(WalletController::WalletDisplayState::LOADED_HIDDEN));
        QVERIFY(controller.hasOpenableWallet());

        // Simulate an independent RPC walletpassphrase unlock. This must not
        // authorize Qt display or be undone by a cancelled display prompt.
        QVERIFY(encrypted_wallet->Unlock(passphrase));
        QVERIFY(!encrypted_wallet->IsLocked());

        RespondToPassphraseDialog({}, PassphraseDialogResponse::REJECT);
        auto* cancelled_activity = new OpenWalletActivity(&controller, nullptr);
        QSignalSpy cancelled_opened(cancelled_activity, &OpenWalletActivity::opened);
        QSignalSpy cancelled_finished(cancelled_activity, &OpenWalletActivity::finished);
        cancelled_activity->open("qt-hidden-wallet");
        QTRY_COMPARE_WITH_TIMEOUT(cancelled_finished.count(), 1, 5000);
        QCOMPARE(cancelled_opened.count(), 0);
        QVERIFY(!encrypted_wallet->IsLocked());
        QVERIFY(controller.findWalletModel("qt-hidden-wallet"));
        QVERIFY(controller.hasOpenableWallet());

        RespondToPassphraseDialog(QString::fromUtf8(wrong_passphrase.data(), wrong_passphrase.size()), PassphraseDialogResponse::WRONG_THEN_REJECT);
        auto* wrong_activity = new OpenWalletActivity(&controller, nullptr);
        QSignalSpy wrong_opened(wrong_activity, &OpenWalletActivity::opened);
        QSignalSpy wrong_finished(wrong_activity, &OpenWalletActivity::finished);
        wrong_activity->open("qt-hidden-wallet");
        QTRY_COMPARE_WITH_TIMEOUT(wrong_finished.count(), 1, 5000);
        QCOMPARE(wrong_opened.count(), 0);
        QVERIFY(!encrypted_wallet->IsLocked());
        QVERIFY(controller.findWalletModel("qt-hidden-wallet"));
        QVERIFY(controller.hasOpenableWallet());

        RespondToPassphraseDialog(QString::fromUtf8(passphrase.data(), passphrase.size()), PassphraseDialogResponse::ACCEPT);
        auto* accepted_activity = new OpenWalletActivity(&controller, nullptr);
        QSignalSpy accepted_opened(accepted_activity, &OpenWalletActivity::opened);
        QSignalSpy accepted_finished(accepted_activity, &OpenWalletActivity::finished);
        accepted_activity->open("qt-hidden-wallet");
        QTRY_COMPARE_WITH_TIMEOUT(accepted_finished.count(), 1, 5000);
        QCOMPARE(accepted_opened.count(), 1);
        QCOMPARE(added_spy.count(), 1);
        QVERIFY(wallet_model->isDisplayAuthorized());
        QVERIFY(!encrypted_wallet->IsLocked());
        QCOMPARE(static_cast<int>(controller.listWalletDir().at("qt-hidden-wallet")),
                 static_cast<int>(WalletController::WalletDisplayState::PUBLISHED));
        QVERIFY(!controller.hasOpenableWallet());

        QVERIFY(RemoveWallet(context, encrypted_wallet, /*load_on_start=*/std::nullopt));
    }

    // A normally locked wallet is relocked immediately after the one-time
    // display authentication so viewing never becomes a spending unlock.
    {
        const SecureString passphrase{"qt-hidden-locked-wallet-test"};
        auto encrypted_wallet = std::make_shared<CWallet>(
            node.context()->chain.get(), "qt-hidden-locked-wallet", CreateMockableWalletDatabase());
        encrypted_wallet->LoadWallet();
        {
            LOCK(encrypted_wallet->cs_wallet);
            auto* legacy_spkm = encrypted_wallet->GetOrCreateLegacyScriptPubKeyMan();
            QVERIFY(legacy_spkm);
            QVERIFY(legacy_spkm->SetupGeneration(true));
        }
        QVERIFY(SetWalletLastProcessedToTip(encrypted_wallet, node));
        QVERIFY(encrypted_wallet->EncryptWallet(passphrase));
        QVERIFY(encrypted_wallet->IsLocked());
        QVERIFY(AddWallet(context, encrypted_wallet));

        WalletController controller(client_model, platform_style.get(), nullptr);
        WalletModel* wallet_model = controller.getOrCreateWallet(
            interfaces::MakeWallet(context, encrypted_wallet), /*publish=*/false);
        RespondToPassphraseDialog(QString::fromUtf8(passphrase.data(), passphrase.size()), PassphraseDialogResponse::ACCEPT);
        auto* activity = new OpenWalletActivity(&controller, nullptr);
        QSignalSpy opened_spy(activity, &OpenWalletActivity::opened);
        QSignalSpy finished_spy(activity, &OpenWalletActivity::finished);
        activity->open("qt-hidden-locked-wallet");
        QTRY_COMPARE_WITH_TIMEOUT(finished_spy.count(), 1, 5000);
        QCOMPARE(opened_spy.count(), 1);
        QVERIFY(wallet_model->isDisplayAuthorized());
        QVERIFY(encrypted_wallet->IsLocked());
        QCOMPARE(static_cast<int>(controller.listWalletDir().at("qt-hidden-locked-wallet")),
                 static_cast<int>(WalletController::WalletDisplayState::PUBLISHED));

        QVERIFY(RemoveWallet(context, encrypted_wallet, /*load_on_start=*/std::nullopt));
    }

    // If a hidden model is unloaded after selection but before the queued open
    // step, the activity must finish without dereferencing the deleted model.
    {
        QVERIFY(AddWallet(context, wallet));
        WalletController controller(client_model, platform_style.get(), nullptr);
        WalletModel* wallet_model = controller.getOrCreateWallet(
            interfaces::MakeWallet(context, wallet), /*publish=*/false);
        QPointer<WalletModel> model_guard(wallet_model);
        auto* activity = new OpenWalletActivity(&controller, nullptr);
        QSignalSpy opened_spy(activity, &OpenWalletActivity::opened);
        QSignalSpy finished_spy(activity, &OpenWalletActivity::finished);

        // Queue model removal first. open() still sees the model synchronously,
        // then its queued finish runs after the removal event.
        wallet->NotifyUnload();
        activity->open(wallet->GetName());
        QTRY_COMPARE_WITH_TIMEOUT(finished_spy.count(), 1, 5000);
        QCOMPARE(opened_spy.count(), 0);
        QVERIFY(model_guard.isNull());
        QVERIFY(!controller.findWalletModel(wallet->GetName()));

        QVERIFY(RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt));
    }

    // Exercise the queued unload path while the controller owns a published
    // model. The guard makes a sanitizer-independent lifetime assertion too.
    {
        QVERIFY(AddWallet(context, wallet));
        WalletController controller(client_model, platform_style.get(), nullptr);
        QSignalSpy added_spy(&controller, &WalletController::walletAdded);
        QSignalSpy removed_spy(&controller, &WalletController::walletRemoved);
        WalletModel* wallet_model = controller.getOrCreateWallet(interfaces::MakeWallet(context, wallet));
        QPointer<WalletModel> model_guard(wallet_model);

        QCOMPARE(added_spy.count(), 1);
        auto barrier = std::make_shared<PrepareBarrier>();
        wallet_model->setPrepareTransactionTestHook([barrier] { barrier->wait(); });
        WalletModelTransaction pending_transaction({TestRecipient(COIN)});
        const auto pending_async = StartAsyncPreparation(*wallet_model, pending_transaction);
        QVERIFY(pending_async.task);
        QTRY_VERIFY_WITH_TIMEOUT(barrier->entered.load(std::memory_order_acquire), 5000);
        // Wallet removal joins pending preparation before releasing the model.
        // Release from a non-GUI test thread so the GUI can be blocked in join.
        std::thread release_pending([barrier] {
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
            barrier->signal();
        });
        ThreadJoiner release_pending_joiner{release_pending};
        wallet->NotifyUnload();
        wallet->NotifyUnload();
        QTRY_COMPARE_WITH_TIMEOUT(removed_spy.count(), 1, 5000);
        QVERIFY(model_guard.isNull());
        // A queued publication can arrive after the unload notification.
        QVERIFY(!controller.publishWallet(wallet_model));
        QCOMPARE(added_spy.count(), 1);
        QVERIFY(RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt));
    }

    // Exercise application-shutdown ordering with a live view: the controller
    // must emit walletRemoved so the view is deleted before its WalletModel.
    {
        QVERIFY(AddWallet(context, wallet));
        auto controller = std::make_unique<WalletController>(client_model, platform_style.get(), nullptr);
        WalletModel* wallet_model = controller->getOrCreateWallet(interfaces::MakeWallet(context, wallet));
        QPointer<WalletModel> model_guard(wallet_model);
        auto* wallet_view = new WalletView(wallet_model, platform_style.get(), nullptr);
        QPointer<WalletView> view_guard(wallet_view);
        QObject::connect(controller.get(), &WalletController::walletRemoved, wallet_view, [wallet_view, wallet_model](WalletModel* removed) {
            if (removed == wallet_model) delete wallet_view;
        });

        controller.reset();
        QVERIFY(view_guard.isNull());
        QVERIFY(model_guard.isNull());
        QVERIFY(RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt));
    }
}

//! Simple qt wallet tests.
//
// Test widgets can be debugged interactively calling show() on them and
// manually running the event loop, e.g.:
//
//     sendCoinsDialog.show();
//     QEventLoop().exec();
//
// This also requires overriding the default minimal Qt platform:
//
//     QT_QPA_PLATFORM=xcb     src/qt/test/test_nito-qt  # Linux
//     QT_QPA_PLATFORM=windows src/qt/test/test_nito-qt  # Windows
//     QT_QPA_PLATFORM=cocoa   src/qt/test/test_nito-qt  # macOS
void TestGUI(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet)
{
    // Create widgets for sending coins and listing transactions.
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    MiniGUI mini_gui(node, platformStyle.get());
    mini_gui.initModelForWallet(node, wallet, platformStyle.get());
    WalletModel& walletModel = *mini_gui.walletModel;
    SendCoinsDialog& sendCoinsDialog = mini_gui.sendCoinsDialog;
    TransactionView& transactionView = mini_gui.transactionView;
    WalletView walletView(&walletModel, platformStyle.get(), nullptr);
    walletView.setClientModel(mini_gui.clientModel.get());
    QSignalSpy incoming_transaction_spy(&walletView, &WalletView::incomingTransaction);
    QVERIFY(incoming_transaction_spy.isValid());

    // Update walletModel cached balance which will trigger an update for the 'labelBalance' QLabel.
    walletModel.pollBalanceChanged();
    // Check balance in send dialog
    CompareBalance(walletModel, walletModel.wallet().getBalance(), sendCoinsDialog.findChild<QLabel*>("labelBalance"));

    // Check 'UseAvailableBalance' functionality
    VerifyUseAvailableBalance(sendCoinsDialog, walletModel);

    // Amounts must remain in the monetary range as a sum, before balance
    // checks or transaction creation. This also covers private recipients.
    WalletModelTransaction overflow_transaction({TestRecipient(MAX_MONEY), TestRecipient(1)});
    QCOMPARE(walletModel.prepareTransaction(overflow_transaction, CCoinControl{}).status, WalletModel::InvalidAmount);
    WalletModelTransaction zero_transaction({TestRecipient(0)});
    QCOMPARE(walletModel.prepareTransaction(zero_transaction, CCoinControl{}).status, WalletModel::InvalidAmount);
    // The worker hook blocks only C++ code. A GUI timer must still advance
    // while transaction preparation is pending, and cancellation must discard
    // the late result without making it available for commit.
    auto barrier = std::make_shared<PrepareBarrier>();
    walletModel.setPrepareTransactionTestHook([barrier] { barrier->wait(); });
    WalletModelTransaction cancelled_transaction({TestRecipient(COIN)});
    const auto cancelled_async = StartAsyncPreparation(walletModel, cancelled_transaction);
    QVERIFY(cancelled_async.task);
    QTimer heartbeat;
    int heartbeat_count{0};
    QObject::connect(&heartbeat, &QTimer::timeout, [&heartbeat_count] { ++heartbeat_count; });
    heartbeat.start(1);
    QTRY_VERIFY_WITH_TIMEOUT(barrier->entered.load(std::memory_order_acquire), 5000);
    QTRY_VERIFY_WITH_TIMEOUT(heartbeat_count > 3, 5000);
    walletModel.cancelPrepareTransaction(cancelled_async.task);
    barrier->signal();
    QTRY_VERIFY_WITH_TIMEOUT(walletModel.isPrepareTransactionFinished(cancelled_async.task), 5000);
    const auto cancelled_status = walletModel.finishPrepareTransaction(cancelled_async.task, cancelled_transaction);
    QVERIFY(cancelled_status);
    QCOMPARE(cancelled_status->status, WalletModel::TransactionCreationFailed);
    QVERIFY(!cancelled_transaction.getWtx());
    heartbeat.stop();

    // A worker error is surfaced only on the GUI thread and leaves no
    // transaction available for confirmation or commit.
    walletModel.setPrepareTransactionTestHook([] { throw std::runtime_error{"test preparation failure"}; });
    QSignalSpy prepare_error_spy(&walletModel, &WalletModel::message);
    WalletModelTransaction failed_transaction({TestRecipient(COIN)});
    const auto failed_async = StartAsyncPreparation(walletModel, failed_transaction);
    QVERIFY(failed_async.task);
    QTRY_VERIFY_WITH_TIMEOUT(walletModel.isPrepareTransactionFinished(failed_async.task), 5000);
    const auto failed_status = walletModel.finishPrepareTransaction(failed_async.task, failed_transaction);
    QVERIFY(failed_status);
    QCOMPARE(failed_status->status, WalletModel::TransactionCreationFailed);
    QVERIFY(!failed_transaction.getWtx());
    QCOMPARE(prepare_error_spy.count(), 1);
    walletModel.setPrepareTransactionTestHook({});

    // Send two transactions, and verify they are added to transaction list.
    TransactionTableModel* transactionTableModel = walletModel.getTransactionTableModel();
    const int rows_before_send = transactionTableModel->rowCount({});
    QVERIFY(rows_before_send > 0);
    const QString existing_hash = transactionTableModel->index(0, 0).data(TransactionTableModel::TxHashRole).toString();
    transactionTableModel->updateTransaction(existing_hash, CT_UPDATED, /*showTransaction=*/true);
    QCOMPARE(incoming_transaction_spy.count(), 0);
    uint256 txid1 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN, /*rbf=*/false);
    uint256 txid2 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 10 * COIN, /*rbf=*/true);
    // Transaction table model updates on a QueuedConnection, so process events to ensure it's updated.
    qApp->processEvents();
    QCOMPARE(transactionTableModel->rowCount({}), rows_before_send + 2);
    QVERIFY(FindTx(*transactionTableModel, txid1).isValid());
    QVERIFY(FindTx(*transactionTableModel, txid2).isValid());
    QCOMPARE(incoming_transaction_spy.count(), 2);

    const QString txid1_string = QString::fromStdString(txid1.ToString());
    transactionTableModel->updateTransaction(txid1_string, CT_UPDATED, /*showTransaction=*/true);
    transactionTableModel->updateTransaction(txid1_string, CT_UPDATED, /*showTransaction=*/true);
    QCOMPARE(incoming_transaction_spy.count(), 2);

    const CTxDestination multi_recipient_1 = PKHash();
    const CTxDestination multi_recipient_2 = PKHash(uint160(std::vector<unsigned char>(20, 1)));
    const int rows_before_multi_send = transactionTableModel->rowCount({});
    uint256 txid3 = SendCoinsMulti(*wallet.get(), sendCoinsDialog, {{multi_recipient_1, 1 * COIN}, {multi_recipient_2, 2 * COIN}});
    qApp->processEvents();
    QCOMPARE(transactionTableModel->rowCount({}), rows_before_multi_send + 1);
    const QModelIndex multi_send_index = FindTx(*transactionTableModel, txid3);
    QVERIFY(multi_send_index.isValid());
    QCOMPARE(multi_send_index.siblingAtColumn(TransactionTableModel::ToAddress).data().toString(), QString("Multiple recipients"));
    const qint64 multi_send_amount = multi_send_index.siblingAtColumn(TransactionTableModel::Amount).data(TransactionTableModel::AmountRole).toLongLong();
    const qint64 multi_send_nominal_total = qint64{3 * COIN};
    QVERIFY(multi_send_amount <= -multi_send_nominal_total);
    const QString multi_send_details = multi_send_index.data(TransactionTableModel::LongDescriptionRole).toString();
    QVERIFY(multi_send_details.contains(QString::fromStdString(EncodeDestination(multi_recipient_1))));
    QVERIFY(multi_send_details.contains(QString::fromStdString(EncodeDestination(multi_recipient_2))));

    // Call bumpfee. Test disabled, canceled, enabled, then failing cases.
    BumpFee(transactionView, txid1, /*expectDisabled=*/true, /*expectError=*/"not BIP 125 replaceable", /*cancel=*/false);
    BumpFee(transactionView, txid2, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/true);
    BumpFee(transactionView, txid2, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/false);
    BumpFee(transactionView, txid2, /*expectDisabled=*/true, /*expectError=*/"already bumped", /*cancel=*/false);

    const CTxDestination op_return_recipient = PKHash(uint160(std::vector<unsigned char>(20, 2)));
    const int rows_before_op_return_send = transactionTableModel->rowCount({});
    uint256 txid4 = SendCoinsWithData(*wallet.get(), op_return_recipient, 1 * COIN);
    qApp->processEvents();
    QCOMPARE(transactionTableModel->rowCount({}), rows_before_op_return_send + 1);
    const QModelIndex op_return_send_index = FindTx(*transactionTableModel, txid4);
    QVERIFY(op_return_send_index.isValid());
    const QString op_return_recipient_address = QString::fromStdString(EncodeDestination(op_return_recipient));
    const QString op_return_to_address = op_return_send_index.siblingAtColumn(TransactionTableModel::ToAddress).data().toString();
    QVERIFY(op_return_to_address.contains(op_return_recipient_address));
    QVERIFY(op_return_to_address != QString("Multiple recipients"));
    const qint64 op_return_send_amount = op_return_send_index.siblingAtColumn(TransactionTableModel::Amount).data(TransactionTableModel::AmountRole).toLongLong();
    QVERIFY(op_return_send_amount <= -qint64{1 * COIN});
    const QString op_return_send_details = op_return_send_index.data(TransactionTableModel::LongDescriptionRole).toString();
    QVERIFY(op_return_send_details.contains(op_return_recipient_address));
    QVERIFY(!op_return_send_details.contains(QString("Debit: 0.00000000")));
    QVERIFY(!op_return_send_details.contains(QString("multiple recipients")));
    QVERIFY(!op_return_send_details.contains(QString("Multiple recipients")));

    // Check current balance on OverviewPage
    OverviewPage overviewPage(platformStyle.get());
    overviewPage.setWalletModel(&walletModel);
    walletModel.pollBalanceChanged(); // Manual balance polling update
    CompareBalance(walletModel, walletModel.wallet().getBalance(), overviewPage.findChild<QLabel*>("labelBalance"), NitoUnits::SeparatorStyle::ALWAYS);
    auto* recent_transactions = overviewPage.findChild<QListView*>("listTransactions");
    QVERIFY(recent_transactions);
    QVERIFY(recent_transactions->model()->rowCount() > 5);
    auto check_recent_transaction_limit = [&] {
        for (int row = 0; row < recent_transactions->model()->rowCount(); ++row) {
            QCOMPARE(recent_transactions->isRowHidden(row), row >= 5);
        }
    };
    check_recent_transaction_limit();
    transactionTableModel->refreshWallet();
    qApp->processEvents();
    check_recent_transaction_limit();

    // Check Request Payment button
    ReceiveCoinsDialog receiveCoinsDialog(platformStyle.get());
    receiveCoinsDialog.setModel(&walletModel);
    RecentRequestsTableModel* requestTableModel = walletModel.getRecentRequestsTableModel();

    // Label input
    QLineEdit* labelInput = receiveCoinsDialog.findChild<QLineEdit*>("reqLabel");
    labelInput->setText("TEST_LABEL_1");

    // Amount input
    NitoAmountField* amountInput = receiveCoinsDialog.findChild<NitoAmountField*>("reqAmount");
    amountInput->setValue(1);

    // Message input
    QLineEdit* messageInput = receiveCoinsDialog.findChild<QLineEdit*>("reqMessage");
    messageInput->setText("TEST_MESSAGE_1");
    int initialRowCount = requestTableModel->rowCount({});
    QPushButton* requestPaymentButton = receiveCoinsDialog.findChild<QPushButton*>("receiveButton");
    requestPaymentButton->click();
    QString address;
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->inherits("ReceiveRequestDialog")) {
            ReceiveRequestDialog* receiveRequestDialog = qobject_cast<ReceiveRequestDialog*>(widget);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("payment_header")->text(), QString("Payment information"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("uri_tag")->text(), QString("URI:"));
            QString uri = receiveRequestDialog->QObject::findChild<QLabel*>("uri_content")->text();
            QCOMPARE(uri.count("nito:"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("address_tag")->text(), QString("Address:"));
            QVERIFY(address.isEmpty());
            address = receiveRequestDialog->QObject::findChild<QLabel*>("address_content")->text();
            QVERIFY(!address.isEmpty());

            QCOMPARE(uri.count("amount=0.00000001"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_tag")->text(), QString("Amount:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_content")->text(), QString::fromStdString("0.00000001 " + CURRENCY_UNIT));

            QCOMPARE(uri.count("label=TEST_LABEL_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_tag")->text(), QString("Label:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_content")->text(), QString("TEST_LABEL_1"));

            QCOMPARE(uri.count("message=TEST_MESSAGE_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_tag")->text(), QString("Message:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_content")->text(), QString("TEST_MESSAGE_1"));
        }
    }

    // Clear button
    QPushButton* clearButton = receiveCoinsDialog.findChild<QPushButton*>("clearButton");
    clearButton->click();
    QCOMPARE(labelInput->text(), QString(""));
    QCOMPARE(amountInput->value(), CAmount(0));
    QCOMPARE(messageInput->text(), QString(""));

    // Check addition to history
    int currentRowCount = requestTableModel->rowCount({});
    QCOMPARE(currentRowCount, initialRowCount+1);

    // Check addition to wallet
    std::vector<std::string> requests = walletModel.wallet().getAddressReceiveRequests();
    QCOMPARE(requests.size(), size_t{1});
    RecentRequestEntry entry;
    DataStream{MakeUCharSpan(requests[0])} >> entry;
    QCOMPARE(entry.nVersion, int{1});
    QCOMPARE(entry.id, int64_t{1});
    QVERIFY(entry.date.isValid());
    QCOMPARE(entry.recipient.address, address);
    QCOMPARE(entry.recipient.label, QString{"TEST_LABEL_1"});
    QCOMPARE(entry.recipient.amount, CAmount{1});
    QCOMPARE(entry.recipient.message, QString{"TEST_MESSAGE_1"});
    QCOMPARE(entry.recipient.sPaymentRequest, std::string{});
    QCOMPARE(entry.recipient.authenticatedMerchant, QString{});

    // Check Remove button
    QTableView* table = receiveCoinsDialog.findChild<QTableView*>("recentRequestsView");
    table->selectRow(currentRowCount-1);
    QPushButton* removeRequestButton = receiveCoinsDialog.findChild<QPushButton*>("removeRequestButton");
    removeRequestButton->click();
    QCOMPARE(requestTableModel->rowCount({}), currentRowCount-1);

    // Check removal from wallet
    QCOMPARE(walletModel.wallet().getAddressReceiveRequests().size(), size_t{0});

    // An unrelated address-book failure must not discard a private request.
    auto* address_book = walletModel.getAddressTableModel();
    address_book->addRow(AddressTableModel::Send, "invalid", "invalid", OutputType::BECH32);
    QCOMPARE(address_book->getEditStatus(), AddressTableModel::INVALID_ADDRESS);
    auto* address_types = receiveCoinsDialog.findChild<QComboBox*>("addressType");
    QVERIFY(address_types);
    QVERIFY(InitOrchardIndex([&] { return interfaces::MakeChain(*node.context()); }, 1 << 20, true));
    const auto destroy_index = [](OrchardIndex*) { DestroyOrchardIndex(); };
    std::unique_ptr<OrchardIndex, decltype(destroy_index)> index{GetOrchardIndex(), destroy_index};
    // Address generation requires the index; dropdown synchronization is
    // exercised independently by the index integration tests.
    address_types->addItem("Bech32x", static_cast<int>(wallet::WalletAddressKind::PRIVATE));
    address_types->setCurrentIndex(address_types->count() - 1);
    requestPaymentButton->click();
    QCOMPARE(requestTableModel->rowCount({}), 1);
    QVERIFY(walletModel.isPrivateAddress(requestTableModel->entry(0).recipient.address));
}

void TestGUIWatchOnly(interfaces::Node& node, TestChain100Setup& test)
{
    const std::shared_ptr<CWallet>& wallet = SetupLegacyWatchOnlyWallet(node, test);

    // Create widgets and init models
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    MiniGUI mini_gui(node, platformStyle.get());
    mini_gui.initModelForWallet(node, wallet, platformStyle.get());
    WalletModel& walletModel = *mini_gui.walletModel;
    SendCoinsDialog& sendCoinsDialog = mini_gui.sendCoinsDialog;

    // Update walletModel cached balance which will trigger an update for the 'labelBalance' QLabel.
    walletModel.pollBalanceChanged();
    // Check balance in send dialog
    CompareBalance(walletModel, walletModel.wallet().getBalances().watch_only_balance,
                   sendCoinsDialog.findChild<QLabel*>("labelBalance"));

    // Set change address
    sendCoinsDialog.getCoinControl()->destChange = GetDestinationForKey(test.coinbaseKey.GetPubKey(), OutputType::LEGACY);

    auto interact_with_psbt_dialog = [](bool copy) {
        auto* timer = new QTimer(QApplication::instance());
        timer->setInterval(100);
        QObject::connect(timer, &QTimer::timeout, [timer, copy]() {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (!widget->inherits("PSBTOperationsDialog")) continue;
                if (copy) {
                    QPushButton* copy_button = widget->findChild<QPushButton*>("copyToClipboardButton");
                    QVERIFY(copy_button);
                    copy_button->click();
                }
                QPushButton* close_button = widget->findChild<QPushButton*>("closeButton");
                QVERIFY(close_button);
                close_button->click();
                timer->stop();
                timer->deleteLater();
                break;
            }
        });
        timer->start();
    };

    // Discarding a PSBT must not overwrite the clipboard.
    const QString clipboard_sentinel{"nito-psbt-clipboard-sentinel"};
    QApplication::clipboard()->setText(clipboard_sentinel);
    interact_with_psbt_dialog(/*copy=*/false);
    SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN, /*rbf=*/false, QMessageBox::Save);
    QCOMPARE(QApplication::clipboard()->text(), clipboard_sentinel);

    // Copying requires an explicit button click and still produces a decodable PSBT.
    interact_with_psbt_dialog(/*copy=*/true);
    SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN, /*rbf=*/false, QMessageBox::Save);
    const std::string psbt_string = QApplication::clipboard()->text().toStdString();
    QVERIFY(!psbt_string.empty());

    const std::optional<std::vector<unsigned char>> decoded_psbt = DecodeBase64(psbt_string);
    QVERIFY(decoded_psbt);
    PartiallySignedTransaction psbt;
    std::string err;
    QVERIFY(DecodeRawPSBT(psbt, MakeByteSpan(*decoded_psbt), err));

    // Private signing material is visibly marked sensitive without touching the clipboard.
    CPrivatePSBTOrchardBundlePlan plan;
    psbt.m_proprietary.insert(MakeNitoPSBTOrchardBundlePlanProprietary(plan));
    QApplication::clipboard()->setText(clipboard_sentinel);
    PSBTOperationsDialog private_dialog(nullptr, nullptr, mini_gui.clientModel.get());
    private_dialog.openWithPSBT(psbt);
    QTextEdit* description = private_dialog.findChild<QTextEdit*>("transactionDescription");
    QVERIFY(description);
    QVERIFY(description->toPlainText().contains("sensitive transaction details"));
    QCOMPARE(QApplication::clipboard()->text(), clipboard_sentinel);

    // Zero is a known fee. Missing input data must remain a distinct state.
    CMutableTransaction no_fee_tx;
    no_fee_tx.vin.resize(1);
    no_fee_tx.vin[0].prevout.n = 0;
    no_fee_tx.vout.emplace_back(COIN, CScript() << OP_TRUE);
    PartiallySignedTransaction no_fee_psbt(no_fee_tx);
    no_fee_psbt.inputs[0].witness_utxo = CTxOut(COIN, GetScriptForDestination(WitnessV0KeyHash(uint160{})));
    PSBTOperationsDialog amount_dialog(nullptr, nullptr, mini_gui.clientModel.get());
    amount_dialog.openWithPSBT(no_fee_psbt);
    auto* amount_description = amount_dialog.findChild<QTextEdit*>("transactionDescription");
    QVERIFY(amount_description);
    QVERIFY(amount_description->toPlainText().contains("Pays transaction fee:"));
    QVERIFY(!amount_description->toPlainText().contains("Unable to calculate"));

    no_fee_psbt.inputs[0].witness_utxo.SetNull();
    amount_dialog.openWithPSBT(no_fee_psbt);
    QVERIFY(amount_description->toPlainText().contains("Unable to calculate"));

    for (const CAmount invalid_amount : {CAmount{-1}, MAX_MONEY, std::numeric_limits<CAmount>::max()}) {
        PartiallySignedTransaction invalid = no_fee_psbt;
        CPrivatePSBTOrchardBundlePlan invalid_plan;
        invalid_plan.output_count = 1;
        CPrivatePSBTOrchardOutputMaterial output;
        output.recipient_raw.resize(NITO_ORCHARD_RAW_ADDRESS_SIZE);
        output.value = invalid_amount;
        invalid.m_proprietary.insert(MakeNitoPSBTOrchardBundlePlanProprietary(invalid_plan));
        invalid.m_proprietary.insert(MakeNitoPSBTOrchardOutputMaterialProprietary(0, output));
        amount_dialog.openWithPSBT(invalid);
        QVERIFY(amount_description->toPlainText().isEmpty());
        QVERIFY(!amount_dialog.findChild<QPushButton*>("signTransactionButton")->isEnabled());
        QVERIFY(!amount_dialog.findChild<QPushButton*>("broadcastTransactionButton")->isEnabled());
        QVERIFY(!amount_dialog.findChild<QPushButton*>("saveButton")->isEnabled());
    }
    no_fee_psbt.tx->vout[0].nValue = -1;
    amount_dialog.openWithPSBT(no_fee_psbt);
    QVERIFY(amount_description->toPlainText().isEmpty());
    amount_dialog.openWithPSBT(PartiallySignedTransaction{});
    QVERIFY(amount_description->toPlainText().isEmpty());
}

void TestPrivateSendReplacement(interfaces::Node& node, TestChain100Setup& test, const std::shared_ptr<CWallet>& wallet)
{
    QVERIFY(InitOrchardIndex([&] { return interfaces::MakeChain(*node.context()); }, 1 << 20, true));
    const auto stop_index = [](OrchardIndex* index) {
        index->Interrupt();
        index->Stop();
        DestroyOrchardIndex();
    };
    std::unique_ptr<OrchardIndex, decltype(stop_index)> index{GetOrchardIndex(), stop_index};
    QVERIFY(index->Init());
    QVERIFY(index->StartBackgroundSync());
    QTRY_VERIFY_WITH_TIMEOUT(index->BlockUntilSyncedToCurrentChain(), 30000);

    std::unique_ptr<const PlatformStyle> style{PlatformStyle::instantiate("other")};
    MiniGUI gui(node, style.get());
    gui.initModelForWallet(node, wallet, style.get());
    WalletModel& model = *gui.walletModel;
    SendCoinsDialog& dialog = gui.sendCoinsDialog;
    const auto private_address = model.wallet().getNewPrivateAddress(false);
    QVERIFY(private_address);
    const SecureString passphrase{"qt-private-replacement-test"};
    QVERIFY(wallet->EncryptWallet(passphrase));
    QVERIFY(wallet->IsLocked());
    // Simulate the initial GUI display unlock: authenticate once, authorize
    // private viewing, then immediately remove the spending key from memory.
    QVERIFY(wallet->Unlock(passphrase));
    model.setDisplayAuthorized(true);
    QVERIFY(model.setWalletLockedForDisplay());
    QVERIFY(wallet->IsLocked());
    int unlock_requests{0};
    QObject::connect(&model, &WalletModel::requireUnlock, &dialog, [&] {
        ++unlock_requests;
        QVERIFY(wallet->Unlock(passphrase));
    });

    auto send = [&](bool private_source, bool psbt, bool cancel, uint256& sent) {
        dialog.clear();
        gui.optionsModel.setData(gui.optionsModel.index(OptionsModel::EnablePSBTControls), psbt);
        gui.optionsModel.setData(gui.optionsModel.index(OptionsModel::EnableBech32xOrchardReceiveAddresses), true);
        // Display authorization exposes viewing data without unlocking the
        // spending keys. Every send still requests its own temporary unlock.
        model.pollBalanceChanged();
        dialog.findChild<QCheckBox*>("checkBoxUsePrivateBalance")->setChecked(private_source);
        auto* entries = dialog.findChild<QVBoxLayout*>("entries");
        auto* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
        entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(private_source
            ? EncodeDestination(GetDestinationForKey(test.coinbaseKey.GetPubKey(), OutputType::BECH32)) : *private_address));
        entry->findChild<NitoAmountField*>("payAmount")->setValue(private_source ? COIN : 3 * COIN);
        dialog.findChild<QCheckBox*>("optInRBF")->setChecked(true);
        const auto connection = QObject::connect(&dialog, &SendCoinsDialog::coinsSent, &dialog, [&](const uint256& txid) { sent = txid; });
        bool confirmed{false};
        bool unlocked_at_confirmation{false};
        QString unexpected_message;
        QTimer confirm_timer;
        QObject::connect(&confirm_timer, &QTimer::timeout, &dialog, [&] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* confirmation = qobject_cast<SendConfirmationDialog*>(widget); confirmation && confirmation->isVisible()) {
                    unlocked_at_confirmation = !wallet->IsLocked();
                    confirm_timer.stop();
                    auto* button = confirmation->button(cancel ? QMessageBox::Cancel : QMessageBox::Yes);
                    button->setEnabled(true);
                    button->click();
                    confirmed = true;
                } else if (auto* message = qobject_cast<QMessageBox*>(widget); message && message->isVisible()) {
                    unexpected_message = message->text();
                    message->reject();
                    confirm_timer.stop();
                    confirmed = true;
                }
            }
        });
        confirm_timer.start(25);
        const int previous_unlock_requests = unlock_requests;
        QVERIFY(QMetaObject::invokeMethod(&dialog, "sendButtonClicked", Q_ARG(bool, false)));
        QTRY_VERIFY_WITH_TIMEOUT(confirmed, 120000);
        QObject::disconnect(connection);
        QVERIFY2(unexpected_message.isEmpty(), qPrintable(unexpected_message));
        QVERIFY(unlocked_at_confirmation);
        QVERIFY(wallet->IsLocked());
        QCOMPARE(unlock_requests, previous_unlock_requests + 1);
        QCOMPARE(sent.IsNull(), cancel);
    };

    uint256 cancelled;
    const size_t transaction_count = WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.size());
    send(false, false, true, cancelled);
    if (QTest::currentTestFailed()) return;
    QCOMPARE(WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.size()), transaction_count);

    for (bool private_source : {false, true}) {
        uint256 sent;
        send(private_source, private_source, false, sent);
        if (QTest::currentTestFailed()) return;
        QVERIFY(!sent.IsNull());
        {
            LOCK(wallet->cs_wallet);
            const auto& wtx = wallet->mapWallet.at(sent);
            QVERIFY(wtx.mapValue.count("nito_private_bump_recipe"));
            QCOMPARE(wtx.tx->vin.empty(), private_source);
        }
        QVERIFY(wallet->LockForDisplay());
        qApp->processEvents();
        BumpFee(gui.transactionView, sent, false, {}, false);
        if (QTest::currentTestFailed()) return;
        CTransactionRef replacement;
        {
            LOCK(wallet->cs_wallet);
            const auto& old = wallet->mapWallet.at(sent);
            QVERIFY(old.mapValue.count("replaced_by_txid"));
            const auto& bumped = wallet->mapWallet.at(uint256S(old.mapValue.at("replaced_by_txid")));
            QVERIFY(bumped.mapValue.count("nito_private_bump_recipe"));
            replacement = bumped.tx;
        }
        QVERIFY(wallet->IsLocked());
        const auto mining_script = GetScriptForRawPubKey(test.coinbaseKey.GetPubKey());
        // Include the replacement's unconfirmed transparent ancestors, if any.
        const auto block_template = node::BlockAssembler(test.m_node.chainman->ActiveChainstate(), test.m_node.mempool.get()).CreateNewBlock(mining_script);
        std::vector<CMutableTransaction> block_transactions;
        for (size_t i = 1; i < block_template->block.vtx.size(); ++i) {
            block_transactions.emplace_back(*block_template->block.vtx[i]);
        }
        const auto block = test.CreateAndProcessBlock(block_transactions, mining_script);
        QCOMPARE(block.GetHash(), WITH_LOCK(test.m_node.chainman->GetMutex(), return test.m_node.chainman->ActiveChain().Tip()->GetBlockHash()));
        QVERIFY(std::any_of(block.vtx.begin(), block.vtx.end(), [&](const auto& tx) { return tx->GetHash() == replacement->GetHash(); }));
        SyncWithValidationInterfaceQueue();
        QTRY_VERIFY_WITH_TIMEOUT(index->BlockUntilSyncedToCurrentChain(), 30000);
        // This fixture removes the wallet from the loader; advance its cursor
        // explicitly before scanning the newly mined block.
        {
            LOCK2(test.m_node.chainman->GetMutex(), wallet->cs_wallet);
            const auto* tip = test.m_node.chainman->ActiveChain().Tip();
            wallet->SetLastBlockProcessed(tip->nHeight, tip->GetBlockHash());
        }
        QVERIFY(wallet->Unlock(passphrase));
        SyncUpWallet(wallet, node);
        if (QTest::currentTestFailed()) return;
        QVERIFY(wallet->LockForDisplay());
    }

    QVERIFY(model.isDisplayAuthorized());
    QVERIFY(model.setWalletLocked(true));
    model.updateStatus();
    QVERIFY(!model.isDisplayAuthorized());
}

void TestGUI(interfaces::Node& node)
{
    // Set up wallet and chain with 105 blocks (5 mature blocks for spending).
    TestChain100Setup test;
    for (int i = 0; i < 5; ++i) {
        test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    }
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);

    // Legacy watch-only wallet test
    // Verify PSBT creation.
    TestGUIWatchOnly(node, test);

    // "Full" GUI tests, use descriptor wallet
    const std::shared_ptr<CWallet>& desc_wallet = SetupDescriptorsWallet(node, test);
    TestGUI(node, desc_wallet);
    if (QTest::currentTestFailed()) return;
    TestWalletControllerLifetimes(node, desc_wallet);
    if (QTest::currentTestFailed()) return;
    TestPrivateSendReplacement(node, test, desc_wallet);
}

void TestCreateWalletDialogRecoveryEncryption()
{
    CreateWalletDialog dialog(nullptr);
    QLineEdit* wallet_name = dialog.findChild<QLineEdit*>("wallet_name_line_edit");
    QCheckBox* restore_mnemonic = dialog.findChild<QCheckBox*>("restore_mnemonic_checkbox");
    QCheckBox* restore_file = dialog.findChild<QCheckBox*>("restore_file_checkbox");
    QPlainTextEdit* recovery_phrase = dialog.findChild<QPlainTextEdit*>("recovery_phrase_text_edit");
    QCheckBox* bip39_option = dialog.findChild<QCheckBox*>("bip39_passphrase_checkbox");
    QWidget* bip39_widget = dialog.findChild<QWidget*>("bip39_passphrase_widget");
    QLabel* bip39_description = dialog.findChild<QLabel*>("bip39_passphrase_description_label");
    QLineEdit* bip39_passphrase = dialog.findChild<QLineEdit*>("bip39_passphrase_line_edit");
    QLabel* bip39_confirmation_label = dialog.findChild<QLabel*>("bip39_passphrase_confirmation_label");
    QLineEdit* bip39_confirmation = dialog.findChild<QLineEdit*>("bip39_passphrase_confirmation_line_edit");
    QToolButton* show_bip39 = dialog.findChild<QToolButton*>("show_bip39_passphrase_button");
    QCheckBox* bip39_backup = dialog.findChild<QCheckBox*>("bip39_passphrase_backup_checkbox");
    QLabel* bip39_error = dialog.findChild<QLabel*>("bip39_passphrase_error_label");
    QCheckBox* encrypt_wallet = dialog.findChild<QCheckBox*>("encrypt_wallet_checkbox");
    QCheckBox* disable_privkeys = dialog.findChild<QCheckBox*>("disable_privkeys_checkbox");
    QCheckBox* blank_wallet = dialog.findChild<QCheckBox*>("blank_wallet_checkbox");
    QCheckBox* external_signer = dialog.findChild<QCheckBox*>("external_signer_checkbox");
    QDialogButtonBox* button_box = dialog.findChild<QDialogButtonBox*>("buttonBox");
    QVERIFY(wallet_name);
    QVERIFY(restore_mnemonic);
    QVERIFY(restore_file);
    QVERIFY(recovery_phrase);
    QVERIFY(bip39_option);
    QVERIFY(bip39_widget);
    QVERIFY(bip39_description);
    QVERIFY(bip39_passphrase);
    QVERIFY(bip39_confirmation_label);
    QVERIFY(bip39_confirmation);
    QVERIFY(show_bip39);
    QVERIFY(bip39_backup);
    QVERIFY(bip39_error);
    QVERIFY(encrypt_wallet);
    QVERIFY(disable_privkeys);
    QVERIFY(blank_wallet);
    QVERIFY(external_signer);
    QVERIFY(button_box);

    QCOMPARE(bip39_option->text(), QStringLiteral("Use an optional BIP39 passphrase"));
    QCOMPARE(bip39_description->text(), QStringLiteral("This passphrase is an additional secret associated with your recovery phrase.\nEnter it exactly: a different value opens a different wallet."));
    QVERIFY(bip39_widget->isHidden());
    QCOMPARE(bip39_passphrase->echoMode(), QLineEdit::Password);
    QCOMPARE(bip39_confirmation->echoMode(), QLineEdit::Password);
    QCOMPARE(bip39_passphrase->maxLength(), static_cast<int>(wallet::MAX_BIP39_PASSPHRASE_SIZE + 1));
    QCOMPARE(bip39_confirmation->maxLength(), static_cast<int>(wallet::MAX_BIP39_PASSPHRASE_SIZE + 1));
    for (QLineEdit* field : {bip39_passphrase, bip39_confirmation}) {
        QVERIFY(field->inputMethodHints().testFlag(Qt::ImhHiddenText));
        QVERIFY(field->inputMethodHints().testFlag(Qt::ImhNoPredictiveText));
        QVERIFY(field->inputMethodHints().testFlag(Qt::ImhNoAutoUppercase));
        QVERIFY(field->inputMethodHints().testFlag(Qt::ImhSensitiveData));
    }

    wallet_name->setText(QStringLiteral("bip39-qt-test"));
    bip39_option->setChecked(true);
    QVERIFY(!bip39_widget->isHidden());
    QVERIFY(!bip39_confirmation_label->isHidden());
    QVERIFY(!bip39_confirmation->isHidden());
    QVERIFY(!bip39_backup->isHidden());

    // Creation compares the NFKD forms, not the original UTF-8 spellings.
    bip39_passphrase->setText(QString::fromUtf8("caf\xC3\xA9"));
    bip39_confirmation->setText(QString::fromUtf8("cafe\xCC\x81"));
    bip39_backup->setChecked(true);
    QVERIFY(button_box->button(QDialogButtonBox::Ok)->isEnabled());

    show_bip39->setChecked(true);
    QCOMPARE(bip39_passphrase->echoMode(), QLineEdit::Normal);
    QCOMPARE(bip39_confirmation->echoMode(), QLineEdit::Normal);
    QCOMPARE(show_bip39->text(), QStringLiteral("Hide"));
    show_bip39->setChecked(false);
    QCOMPARE(bip39_passphrase->echoMode(), QLineEdit::Password);
    QCOMPARE(bip39_confirmation->echoMode(), QLineEdit::Password);

    const QString exact_passphrase{QStringLiteral("  Keep  Spaces And Case  ")};
    bip39_passphrase->setText(exact_passphrase);
    bip39_confirmation->setText(exact_passphrase);
    SecureString transported{dialog.bip39Passphrase()};
    QCOMPARE(QString::fromUtf8(transported.data(), static_cast<int>(transported.size())), exact_passphrase);
    if (!transported.empty()) memory_cleanse(transported.data(), transported.size());
    transported.clear();
    QVERIFY(button_box->button(QDialogButtonBox::Ok)->isEnabled());

    bip39_confirmation->setText(QStringLiteral("  keep  Spaces And Case  "));
    QVERIFY(!button_box->button(QDialogButtonBox::Ok)->isEnabled());
    bip39_confirmation->setText(exact_passphrase + QLatin1Char(' '));
    QVERIFY(!button_box->button(QDialogButtonBox::Ok)->isEnabled());
    bip39_confirmation->setText(exact_passphrase);
    bip39_backup->setChecked(false);
    QVERIFY(!button_box->button(QDialogButtonBox::Ok)->isEnabled());
    QVERIFY(!bip39_error->text().isEmpty());
    bip39_backup->setChecked(true);
    QVERIFY(button_box->button(QDialogButtonBox::Ok)->isEnabled());

    restore_mnemonic->setChecked(true);
    recovery_phrase->setPlainText(QStringLiteral("one two three four five six seven eight nine ten eleven twelve"));
    QVERIFY(encrypt_wallet->isEnabled());
    QVERIFY(!encrypt_wallet->isChecked());
    QVERIFY(!disable_privkeys->isEnabled());
    QVERIFY(!blank_wallet->isEnabled());
    QVERIFY(!external_signer->isEnabled());
    QVERIFY(bip39_option->isEnabled());
    QVERIFY(bip39_confirmation_label->isHidden());
    QVERIFY(bip39_confirmation->isHidden());
    QVERIFY(bip39_backup->isHidden());
    QVERIFY(button_box->button(QDialogButtonBox::Ok)->isEnabled());

    // The UI character limit is shared with Core, while Core validation also
    // enforces the UTF-8 byte limit and the post-NFKD byte limit.
    bip39_passphrase->setText(QString(400, QChar(0x20ac)));
    QVERIFY(!button_box->button(QDialogButtonBox::Ok)->isEnabled());
    QVERIFY(!bip39_error->text().isEmpty());
    bip39_passphrase->setText(QString(100, QChar(0xfdfa)));
    QVERIFY(!button_box->button(QDialogButtonBox::Ok)->isEnabled());
    QVERIFY(!bip39_error->text().isEmpty());
    bip39_passphrase->clear();
    QVERIFY(button_box->button(QDialogButtonBox::Ok)->isEnabled());

    encrypt_wallet->setChecked(true);
    QVERIFY(dialog.isEncryptWalletChecked());
    QVERIFY(encrypt_wallet->isEnabled());
    QVERIFY(!disable_privkeys->isEnabled());
    QVERIFY(!blank_wallet->isEnabled());
    QVERIFY(!external_signer->isEnabled());

    restore_file->setChecked(true);
    QVERIFY(!restore_mnemonic->isChecked());
    QVERIFY(!encrypt_wallet->isEnabled());
    QVERIFY(!encrypt_wallet->isChecked());
    QVERIFY(!bip39_option->isEnabled());
    QVERIFY(!bip39_option->isChecked());
    QVERIFY(bip39_passphrase->text().isEmpty());

    restore_file->setChecked(false);
    bip39_option->setChecked(true);
    bip39_passphrase->setText(QStringLiteral("blank exclusion"));
    bip39_confirmation->setText(QStringLiteral("blank exclusion"));
    bip39_backup->setChecked(true);
    blank_wallet->setChecked(true);
    QVERIFY(!bip39_option->isEnabled());
    QVERIFY(!bip39_option->isChecked());
    QVERIFY(bip39_passphrase->text().isEmpty());

    blank_wallet->setChecked(false);
    bip39_option->setChecked(true);
    disable_privkeys->setChecked(true);
    QVERIFY(!bip39_option->isEnabled());
    QVERIFY(!bip39_option->isChecked());

    disable_privkeys->setChecked(false);
    external_signer->setEnabled(true);
    external_signer->setChecked(true);
    QVERIFY(!bip39_option->isEnabled());
    QVERIFY(!bip39_option->isChecked());
    external_signer->setChecked(false);

    bip39_option->setChecked(true);
    bip39_passphrase->setText(QStringLiteral("wipe me"));
    recovery_phrase->setPlainText(QStringLiteral("wipe this mnemonic too"));
    dialog.clearSensitiveFields();
    QVERIFY(!bip39_option->isChecked());
    QVERIFY(bip39_passphrase->text().isEmpty());
    QVERIFY(bip39_confirmation->text().isEmpty());
    QVERIFY(recovery_phrase->toPlainText().isEmpty());
}

} // namespace

void WalletTests::createWalletDialogTests()
{
    TestCreateWalletDialogRecoveryEncryption();
}

void WalletTests::transactionSourceAddresses()
{
    BasicTestingSetup setup{ChainType::REGTEST};
    interfaces::WalletTx wtx{};
    wtx.txin_addresses = {WitnessV0KeyHash{uint160{}}};
    wtx.txin_addresses_complete = true;
    const QString first = QString::fromStdString(EncodeDestination(wtx.txin_addresses.front()));
    QString html = TransactionDesc::FormatInputAddresses(wtx);
    QVERIFY(html.contains(first));
    QVERIFY(!html.contains("href="));
    QVERIFY(!html.contains("unavailable"));

    wtx.txin_addresses.push_back(PKHash{uint160{}});
    wtx.txin_addresses.push_back(WitnessV0ScriptHash{uint256{}});
    html = TransactionDesc::FormatInputAddresses(wtx);
    QVERIFY(html.contains("3 input addresses"));
    QVERIFY(!html.contains(first));
    QVERIFY(TransactionDesc::FormatInputAddresses(wtx, true).contains(first));

    wtx.txin_addresses_complete = false;
    QVERIFY(TransactionDesc::FormatInputAddresses(wtx).contains("Some input addresses are unavailable."));
    wtx.has_private_bundle = true;
    QVERIFY(TransactionDesc::FormatInputAddresses(wtx).isEmpty());
    wtx.has_private_bundle = false;
    wtx.is_coinbase = true;
    QVERIFY(TransactionDesc::FormatInputAddresses(wtx).isEmpty());
    wtx.is_coinbase = false;
    wtx.txin_addresses_complete = true;

    // Render the actual details dialog and exercise its mouse/keyboard link handling.
    QTranslator translator;
    QVERIFY(translator.load(":/translations/fr"));
    QApplication::installTranslator(&translator);
    QStandardItemModel model(1, 1);
    const QModelIndex index = model.index(0, 0);
    const QString suffix = "<b>" + TransactionDesc::tr("Credit") + ":</b> 0.01000000 NITO<br>";
    model.setData(index, QString(TransactionDesc::FormatInputAddresses(wtx) + suffix), TransactionTableModel::LongDescriptionRole);
    model.setData(index, QString(TransactionDesc::FormatInputAddresses(wtx, true) + suffix), TransactionTableModel::ExpandedInputAddressesRole);
    model.setData(index, QString(64, QLatin1Char('a')), TransactionTableModel::TxHashRole);
    TransactionDescDialog dialog(index);
    auto* browser = dialog.findChild<QTextBrowser*>("detailText");
    QVERIFY(browser);
    QVERIFY(!browser->openLinks());
    QVERIFY(!browser->openExternalLinks());
    dialog.show();
    QVERIFY(QTest::qWaitForWindowExposed(&dialog));
    const QString screenshot_dir = qEnvironmentVariable("NITO_QT_TEST_SCREENSHOT_DIR");
    if (!screenshot_dir.isEmpty()) {
        QVERIFY(QDir().mkpath(screenshot_dir));
        QVERIFY(dialog.grab().save(screenshot_dir + "/source-addresses-collapsed.png"));
    }
    QTextCursor link = browser->document()->find(TransactionDesc::tr("%1 input addresses").arg(3));
    QVERIFY(!link.isNull());
    link.setPosition(link.selectionStart() + 1);
    QTest::mouseClick(browser->viewport(), Qt::LeftButton, Qt::NoModifier, browser->cursorRect(link).center());
    QTRY_VERIFY(browser->toPlainText().contains(first));
    QVERIFY(browser->toPlainText().contains("0.01000000 NITO"));
    browser->selectAll();
    browser->copy();
    QVERIFY(QApplication::clipboard()->text().contains(first));
    if (!screenshot_dir.isEmpty()) {
        QVERIFY(dialog.grab().save(screenshot_dir + "/source-addresses-expanded.png"));
    }
    // Focus the collapse link using the keyboard and activate it.
    browser->setTextCursor(QTextCursor(browser->document()));
    browser->setFocus();
    QTest::keyClick(browser, Qt::Key_Tab);
    QTest::keyClick(browser, Qt::Key_Return);
    QTRY_VERIFY(!browser->toPlainText().contains(first));
    QVERIFY(browser->toPlainText().contains("0.01000000 NITO"));

    // Model updates during confirmations must not invalidate the displayed snapshot.
    model.clear();
    QMetaObject::invokeMethod(browser, "anchorClicked", Qt::DirectConnection, Q_ARG(QUrl, QUrl("#input-addresses")));
    QVERIFY(browser->toPlainText().contains(first));
    QApplication::removeTranslator(&translator);
    wtx.txin_addresses.clear();
    QVERIFY(TransactionDesc::FormatInputAddresses(wtx).contains("Source address unavailable"));
}

void WalletTests::transactionSourceWithoutAddressBook()
{
    TestingSetup test{ChainType::REGTEST};
    auto node = interfaces::MakeNode(test.m_node);
    auto wallet = std::make_shared<CWallet>(test.m_node.chain.get(), "source-without-label", CreateMockableWalletDatabase());
    CKey recipient_key;
    recipient_key.MakeNewKey(true);
    const CTxDestination recipient{WitnessV0KeyHash(recipient_key.GetPubKey())};
    const CTxDestination source{WitnessV0KeyHash{uint160{}}};
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        FlatSigningProvider provider;
        std::string error;
        auto descriptor = Parse("wpkh(" + EncodeSecret(recipient_key) + ")", provider, error, /*require_checksum=*/false);
        QVERIFY(descriptor);
        WalletDescriptor wallet_descriptor(std::move(descriptor), 0, 0, 1, 1);
        // Internal descriptors own their addresses without adding receiving labels.
        QVERIFY(wallet->AddWalletDescriptor(wallet_descriptor, provider, "", /*internal=*/true));
        QCOMPARE(wallet->IsMine(recipient), wallet::ISMINE_SPENDABLE);
        wallet->SetLastBlockProcessed(0, WITH_LOCK(cs_main, return test.m_node.chainman->ActiveChain().Tip()->GetBlockHash()));
    }
    CMutableTransaction previous;
    previous.vin.emplace_back(Txid::FromUint256(uint256::ONE), 0);
    previous.vout.emplace_back(2 * COIN, GetScriptForDestination(source));
    const auto previous_ref = MakeTransactionRef(previous);
    QVERIFY(wallet->AddToWallet(previous_ref, wallet::TxStateInactive{}));
    CMutableTransaction received;
    received.vin.emplace_back(previous_ref->GetHash(), 0);
    received.vout.emplace_back(COIN, GetScriptForDestination(recipient));
    const auto received_ref = MakeTransactionRef(received);
    QVERIFY(wallet->AddToWallet(received_ref, wallet::TxStateInactive{}));

    WalletContext context;
    context.chain = test.m_node.chain.get();
    context.args = test.m_node.args;
    auto interface = interfaces::MakeWallet(context, wallet);
    QVERIFY(!interface->getAddress(recipient, /*name=*/nullptr, /*is_mine=*/nullptr, /*purpose=*/nullptr));
    const auto details = interface->getWalletTx(received_ref->GetHash());
    QVERIFY(details.txin_addresses_complete);
    auto records = TransactionRecord::decomposeTransaction(details);
    QCOMPARE(records.size(), 1);
    const QString html = TransactionDesc::toHTML(*node, *interface, &records.front(), NitoUnit::BTC);
    // The source must be rendered even when the owned recipient has no book entry.
    QVERIFY(html.contains("<b>From:</b> " + QString::fromStdString(EncodeDestination(source)) + "<br>"));
}

void WalletTests::prunedRecoveryTranslations()
{
    const auto recovery{wallet::PrunedWalletRecoveryError()};
    const char* index_error = "The Orchard index cannot catch up because required blocks have been pruned. To recover Orchard functionality, use a non-pruned node or explicitly rebuild with -reindex and -prune=0. This requires downloading data, time and disk space. No resynchronization has been started. To continue without Orchard, restart with -orchardindex=0; private balances and spending will be unavailable.";
    // Exercise the actual compiled catalogs, not just the source TS files.
    for (const auto* locale : {"ar", "de", "en", "es", "fr", "id", "it", "ja", "ko", "nl", "pl", "pt", "pt_BR", "ru", "tr", "uk", "zh", "zh-Hans", "zh_CN"}) {
        QTranslator translator;
        QVERIFY2(translator.load(QStringLiteral(":/translations/") + QLatin1String(locale)), locale);
        for (const auto* source : {recovery.original.c_str(), index_error, "Wallet loading failed."}) {
            const QString translated{translator.translate("nito-core", source)};
            QVERIFY2(!translated.isEmpty(), locale);
            if (QLatin1String(locale) != QLatin1String("en")) {
                QVERIFY2(translated != QString::fromUtf8(source), locale);
            }
            if (source == index_error) {
                QVERIFY(translated.contains(QStringLiteral("-reindex")));
                QVERIFY(translated.contains(QStringLiteral("-prune=0")));
                QVERIFY(translated.contains(QStringLiteral("-orchardindex=0")));
            }
        }
    }
}

void WalletTests::privateMixedHistory()
{
    const CTxDestination destination{WitnessV0KeyHash{uint160{}}};
    CMutableTransaction tx;
    tx.vout.emplace_back(COIN / 4, GetScriptForDestination(destination));
    interfaces::WalletTx wtx;
    wtx.tx = MakeTransactionRef(tx);
    wtx.txout_address = {destination};
    wtx.txout_is_change = {false};
    wtx.has_private_bundle = true;
    wtx.private_debit = 2 * COIN;
    wtx.fee = 1000;
    wtx.private_value_balance = COIN / 4 + wtx.fee;
    wtx.private_internal_credit = 5 * COIN / 4 - wtx.fee;
    wtx.private_credit = wtx.private_internal_credit;
    for (const bool own_transparent : {true, false}) {
        const auto mine{own_transparent ? wallet::ISMINE_SPENDABLE : wallet::ISMINE_NO};
        wtx.txout_is_mine = {mine};
        wtx.txout_address_is_mine = {mine};
        wtx.credit = own_transparent ? COIN / 4 : 0;
        const auto records{TransactionRecord::decomposeTransaction(wtx)};
        CAmount net{0};
        bool has_mixed_payment{false};
        for (const auto& record : records) {
            net += record.credit + record.debit;
            has_mixed_payment |= record.is_multi_recipient && record.type == TransactionRecord::SendToOther;
        }
        QCOMPARE(net, own_transparent ? -COIN / 2 : -3 * COIN / 4);
        QVERIFY(has_mixed_payment);
    }
}

void WalletTests::walletTests()
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        qWarning("Skipping WalletTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
                 "with 'QT_QPA_PLATFORM=cocoa test_nito-qt' on mac, or else use a linux or windows build.");
        return;
    }
#endif
    TestGUI(m_node);
}
