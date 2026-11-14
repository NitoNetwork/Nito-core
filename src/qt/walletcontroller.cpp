// Copyright (c) 2019-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletcontroller.h>

#include <qt/askpassphrasedialog.h>
#include <qt/clientmodel.h>
#include <qt/createwalletdialog.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/walletmodel.h>

#include <external_signer.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <support/cleanse.h>
#include <util/string.h>
#include <util/fs.h>
#include <util/threadnames.h>
#include <util/translation.h>
#include <wallet/bip39.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <utility>

#include <QApplication>
#include <QCoreApplication>
#include <QDialog>
#include <QMessageBox>
#include <QMetaObject>
#include <QMutexLocker>
#include <QThread>
#include <QTimer>
#include <QWindow>

using wallet::WALLET_FLAG_BLANK_WALLET;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WALLET_FLAG_EXTERNAL_SIGNER;

namespace {
void ClearPassphrase(SecureString& passphrase)
{
    if (!passphrase.empty()) {
        memory_cleanse(passphrase.data(), passphrase.size());
    }
    SecureString empty;
    passphrase.swap(empty);
}

bool UnlockWalletForDisplay(WalletModel* wallet_model, QWidget* parent, const SecureString* passphrase_hint = nullptr)
{
    if (!wallet_model) return false;
    if (wallet_model->isDisplayAuthorized()) return true;
    if (wallet_model->getEncryptionStatus() != WalletModel::Locked) {
        wallet_model->setDisplayAuthorized(true);
        return true;
    }

    bool unlocked{false};
    if (passphrase_hint && !passphrase_hint->empty()) {
        bilingual_str unlock_error;
        unlocked = wallet_model->setWalletLocked(false, *passphrase_hint, &unlock_error);
        if (!unlocked && !unlock_error.empty()) {
            QMessageBox::critical(parent, QCoreApplication::translate("AskPassphraseDialog", "Wallet unlock failed"), QString::fromStdString(unlock_error.translated));
        }
    } else {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, parent);
        dlg.setModel(wallet_model);
        unlocked = dlg.exec() == QDialog::Accepted;
    }
    if (!unlocked) return false;

    wallet_model->setDisplayAuthorized(true);
    if (!wallet_model->setWalletLockedForDisplay()) {
        wallet_model->setDisplayAuthorized(false);
        return false;
    }
    wallet_model->updateStatus();
    wallet_model->forceBalanceUpdate();
    return true;
}
} // namespace

WalletController::WalletController(ClientModel& client_model, const PlatformStyle* platform_style, QObject* parent)
    : QObject(parent)
    , m_activity_thread(new QThread(this))
    , m_activity_worker(new QObject)
    , m_client_model(client_model)
    , m_node(client_model.node())
    , m_platform_style(platform_style)
    , m_options_model(client_model.getOptionsModel())
{
    m_handler_load_wallet = m_node.walletLoader().handleLoadWallet([this](std::unique_ptr<interfaces::Wallet> wallet) {
        WalletModel* wallet_model = getOrCreateWallet(std::move(wallet), /*publish=*/false);
        QTimer::singleShot(1000ms, this, [this, wallet_model] {
            {
                QMutexLocker locker(&m_mutex);
                if (std::find(m_wallets.begin(), m_wallets.end(), wallet_model) == m_wallets.end()) return;
                if (m_published_wallets.count(wallet_model)) return;
            }
            publishWallet(wallet_model);
        });
    });

    m_activity_worker->moveToThread(m_activity_thread);
    connect(m_activity_thread, &QThread::finished, m_activity_worker, &QObject::deleteLater);
    m_activity_thread->start();
    QTimer::singleShot(0, m_activity_worker, []() {
        util::ThreadRename("qt-walletctrl");
    });
}

// Not using the default destructor because not all member types definitions are
// available in the header, just forward declared.
WalletController::~WalletController()
{
    // Stop accepting callbacks that could enqueue new model creation while
    // the activity worker is being drained.
    m_handler_load_wallet.reset();
    m_activity_thread->quit();
    m_activity_thread->wait();

    std::vector<WalletModel*> wallets;
    std::set<WalletModel*> published_wallets;
    {
        QMutexLocker locker(&m_mutex);
        wallets = std::move(m_wallets);
        published_wallets = std::move(m_published_wallets);
    }
    // Remove views first. Their destructors join any wallet operation before
    // the corresponding WalletModel is released below.
    for (WalletModel* wallet_model : wallets) {
        if (published_wallets.count(wallet_model)) Q_EMIT walletRemoved(wallet_model);
    }
    for (WalletModel* wallet_model : wallets) delete wallet_model;
}

std::map<std::string, bool> WalletController::listWalletDir() const
{
    QMutexLocker locker(&m_mutex);
    std::map<std::string, bool> wallets;
    for (const std::string& name : m_node.walletLoader().listWalletDir()) {
        wallets[name] = false;
    }
    for (WalletModel* wallet_model : m_wallets) {
        auto it = wallets.find(wallet_model->wallet().getWalletName());
        if (it != wallets.end()) it->second = true;
    }
    return wallets;
}

void WalletController::closeWallet(WalletModel* wallet_model, QWidget* parent)
{
    QMessageBox box(parent);
    box.setWindowTitle(tr("Close wallet"));
    box.setText(tr("Are you sure you wish to close the wallet <i>%1</i>?").arg(GUIUtil::HtmlEscape(wallet_model->getDisplayName())));
    if (m_options_model && m_options_model->getOption(OptionsModel::Prune).toBool()) {
        box.setInformativeText(tr("Closing the wallet for too long can result in having to resync the entire chain if pruning is enabled."));
    }
    box.setStandardButtons(QMessageBox::Yes|QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Yes);
    if (box.exec() != QMessageBox::Yes) return;

    // First remove wallet from node.
    wallet_model->wallet().remove();
    // Now release the model.
    removeAndDeleteWallet(wallet_model);
}

void WalletController::closeAllWallets(QWidget* parent)
{
    QMessageBox::StandardButton button = QMessageBox::question(parent, tr("Close all wallets"),
        tr("Are you sure you wish to close all wallets?"),
        QMessageBox::Yes|QMessageBox::Cancel,
        QMessageBox::Yes);
    if (button != QMessageBox::Yes) return;

    std::vector<WalletModel*> wallets;
    std::set<WalletModel*> published_wallets;
    {
        QMutexLocker locker(&m_mutex);
        wallets = std::move(m_wallets);
        published_wallets = std::move(m_published_wallets);
        m_wallets.clear();
        m_published_wallets.clear();
    }
    for (WalletModel* wallet_model : wallets) {
        wallet_model->wallet().remove();
        if (published_wallets.count(wallet_model)) Q_EMIT walletRemoved(wallet_model);
        delete wallet_model;
    }
}

WalletModel* WalletController::getOrCreateWallet(std::unique_ptr<interfaces::Wallet> wallet, bool publish)
{
    WalletModel* wallet_model{nullptr};
    {
        QMutexLocker locker(&m_mutex);

        // Return model instance if exists.
        if (!m_wallets.empty()) {
            std::string name = wallet->getWalletName();
            for (WalletModel* current_model : m_wallets) {
                if (current_model->wallet().getWalletName() == name) {
                    wallet_model = current_model;
                    break;
                }
            }
        }

        if (!wallet_model) {
            // Instantiate model and register it.
            wallet_model = new WalletModel(std::move(wallet), m_client_model, m_platform_style,
                                           nullptr /* required for the following moveToThread() call */);

            // Move WalletModel object to the thread that created the WalletController
            // object (GUI main thread), instead of the current thread, which could be
            // an outside wallet thread or RPC thread sending a LoadWallet notification.
            // This ensures queued signals sent to the WalletModel object will be
            // handled on the GUI event loop.
            wallet_model->moveToThread(thread());
            m_wallets.push_back(wallet_model);

            connect(wallet_model, &WalletModel::unload, this, [this, wallet_model = QPointer<WalletModel>{wallet_model}] {
                if (!wallet_model) return;
                // Defer removeAndDeleteWallet when no modal widget is active.
                // TODO: remove this workaround by removing usage of QDialog::exec.
                if (QApplication::activeModalWidget()) {
                    connect(qApp, &QApplication::focusWindowChanged, wallet_model.data(), [this, wallet_model]() {
                        if (!QApplication::activeModalWidget()) {
                            removeAndDeleteWallet(wallet_model.data());
                        }
                    }, Qt::QueuedConnection);
                } else {
                    removeAndDeleteWallet(wallet_model.data());
                }
            }, Qt::QueuedConnection);

            // Re-emit coinsSent signal from wallet model.
            connect(wallet_model, &WalletModel::coinsSent, this, &WalletController::coinsSent);
        }
    }

    if (publish) {
        if (QThread::currentThread() == thread()) {
            publishWallet(wallet_model);
        } else {
            QMetaObject::invokeMethod(this, [this, wallet_model] {
                publishWallet(wallet_model);
            }, Qt::QueuedConnection);
        }
    }

    return wallet_model;
}

void WalletController::publishWallet(WalletModel* wallet_model)
{
    assert(QThread::currentThread() == thread());
    if (!wallet_model) return;
    {
        QMutexLocker locker(&m_mutex);
        // Queued publication can arrive after the model has been removed.
        if (std::find(m_wallets.begin(), m_wallets.end(), wallet_model) == m_wallets.end()) return;
        if (!wallet_model->isDisplayAuthorized()) return;
        if (!m_published_wallets.insert(wallet_model).second) return;
    }

    // Parent and timer setup are intentionally performed only on the GUI
    // thread. Workers never make a blocking call back into the GUI thread, so
    // WalletController shutdown cannot deadlock while joining them.
    if (!wallet_model->parent()) wallet_model->setParent(this);
    const bool called = QMetaObject::invokeMethod(wallet_model, "startPollBalance", Qt::DirectConnection);
    assert(called);

    Q_EMIT walletAdded(wallet_model);
}

void WalletController::removeAndDeleteWallet(WalletModel* wallet_model)
{
    bool was_published{false};
    // Unregister wallet model.
    {
        QMutexLocker locker(&m_mutex);
        const auto it = std::find(m_wallets.begin(), m_wallets.end(), wallet_model);
        if (it == m_wallets.end()) return;
        m_wallets.erase(it);
        was_published = m_published_wallets.erase(wallet_model) > 0;
    }
    if (was_published) Q_EMIT walletRemoved(wallet_model);
    // Currently this can trigger the unload since the model can hold the last
    // CWallet shared pointer.
    delete wallet_model;
}

WalletControllerActivity::WalletControllerActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : QObject(wallet_controller)
    , m_wallet_controller(wallet_controller)
    , m_parent_widget(parent_widget)
{
    connect(this, &WalletControllerActivity::finished, this, &QObject::deleteLater);
}

void WalletControllerActivity::removeWalletModel(WalletModel* wallet_model)
{
    m_wallet_controller->removeAndDeleteWallet(wallet_model);
}

void WalletControllerActivity::showProgressDialog(const QString& title_text, const QString& label_text, bool show_minimized)
{
    auto progress_dialog = new QProgressDialog(m_parent_widget);
    m_progress_dialog = progress_dialog;
    m_progress_label_text = label_text;
    progress_dialog->setAttribute(Qt::WA_DeleteOnClose);
    connect(this, &WalletControllerActivity::finished, progress_dialog, &QWidget::close);
    connect(progress_dialog, &QObject::destroyed, this, [this] {
        m_progress_dialog = nullptr;
    });

    progress_dialog->setWindowTitle(title_text);
    progress_dialog->setLabelText(label_text);
    progress_dialog->setRange(0, 0);
    progress_dialog->setCancelButton(nullptr);
    progress_dialog->setWindowModality(Qt::WindowModal);
    GUIUtil::PolishProgressDialog(progress_dialog);
    // The setValue call forces QProgressDialog to start the internal duration estimation.
    // See details in https://bugreports.qt.io/browse/QTBUG-47042.
    progress_dialog->setValue(0);
    progress_dialog->show();
    GUIUtil::CenterDialogOnParent(progress_dialog, m_parent_widget);
    // When requested, launch dialog minimized
    if (show_minimized) progress_dialog->showMinimized();
}

void WalletControllerActivity::updateProgressDialog(const QString& status_text, int progress)
{
    if (!m_progress_dialog) return;

    const int clamped_progress{std::max(0, std::min(100, progress))};
    if (m_progress_dialog->minimum() != 0 || m_progress_dialog->maximum() != 100) {
        m_progress_dialog->setRange(0, 100);
    }
    const QString details = status_text.isEmpty()
        ? tr("%1%").arg(clamped_progress)
        : tr("%1\n%2%").arg(status_text, QString::number(clamped_progress));
    m_progress_dialog->setLabelText(QStringLiteral("%1\n%2").arg(m_progress_label_text, details));
    m_progress_dialog->setValue(clamped_progress);
}

CreateWalletActivity::CreateWalletActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : WalletControllerActivity(wallet_controller, parent_widget)
{
    m_wallet_passphrase.reserve(MAX_PASSPHRASE_SIZE);
    m_bip39_passphrase.reserve(wallet::MAX_BIP39_PASSPHRASE_SIZE);
}

CreateWalletActivity::~CreateWalletActivity()
{
    ClearPassphrase(m_wallet_passphrase);
    ClearPassphrase(m_mnemonic);
    ClearPassphrase(m_bip39_passphrase);
    if (m_create_wallet_dialog) m_create_wallet_dialog->clearSensitiveFields();
    delete m_create_wallet_dialog;
    delete m_passphrase_dialog;
}

void CreateWalletActivity::askPassphrase()
{
    m_passphrase_dialog = new AskPassphraseDialog(AskPassphraseDialog::Encrypt, m_parent_widget, &m_wallet_passphrase);
    m_passphrase_dialog->setWindowModality(Qt::ApplicationModal);
    m_passphrase_dialog->show();

    connect(m_passphrase_dialog, &QObject::destroyed, [this] {
        m_passphrase_dialog = nullptr;
    });
    connect(m_passphrase_dialog, &QDialog::accepted, [this] {
        createWallet();
    });
    connect(m_passphrase_dialog, &QDialog::rejected, [this] {
        if (m_create_wallet_dialog) m_create_wallet_dialog->clearSensitiveFields();
        ClearPassphrase(m_wallet_passphrase);
        ClearPassphrase(m_mnemonic);
        ClearPassphrase(m_bip39_passphrase);
        Q_EMIT finished();
    });
}

void CreateWalletActivity::createWallet()
{
    const bool restore_from_mnemonic = m_create_wallet_dialog->isRestoreMnemonicChecked();
    const bool restore_from_file = m_create_wallet_dialog->isRestoreFileChecked();
    m_restore_from_mnemonic = restore_from_mnemonic;
    m_restoring = restore_from_mnemonic || restore_from_file;
    if (restore_from_mnemonic) {
        m_mnemonic = m_create_wallet_dialog->recoveryPhrase();
    }
    m_bip39_passphrase = m_create_wallet_dialog->bip39Passphrase();
    m_create_wallet_dialog->clearSensitiveFields();
    fs::path backup_file_path;
    if (restore_from_file) {
        //: Name of the wallet data file format.
        const QString name_data_file = QCoreApplication::translate("NitoGUI", "Wallet Data");
        //: The title for Restore Wallet File Windows
        const QString title_windows = QCoreApplication::translate("NitoGUI", "Load Wallet Backup");
        const QString backup_file = GUIUtil::getOpenFileName(m_parent_widget, title_windows, QString(), name_data_file + QLatin1String(" (*.dat)"), nullptr);
        if (backup_file.isEmpty()) {
            ClearPassphrase(m_mnemonic);
            ClearPassphrase(m_bip39_passphrase);
            Q_EMIT finished();
            return;
        }
        backup_file_path = fs::PathFromString(backup_file.toStdString());
    }

    if (restore_from_mnemonic) {
        showProgressDialog(
            tr("Restore Wallet"),
            tr("Restoring available funds for Wallet <b>%1</b> from recovery phrase...").arg(m_create_wallet_dialog->walletName().toHtmlEscaped()));
    } else if (restore_from_file) {
        showProgressDialog(
            tr("Restore Wallet"),
            tr("Restoring Wallet <b>%1</b> from backup file...").arg(m_create_wallet_dialog->walletName().toHtmlEscaped()));
    } else {
        showProgressDialog(
            //: Title of window indicating the progress of creation of a new wallet.
            tr("Create Wallet"),
            /*: Descriptive text of the create wallet progress window which indicates
                to the user which wallet is currently being created. */
            tr("Creating Wallet <b>%1</b>…").arg(m_create_wallet_dialog->walletName().toHtmlEscaped()));
    }

    std::string name = m_create_wallet_dialog->walletName().toStdString();
    uint64_t flags = 0;
    // Enable descriptors by default.
    flags |= WALLET_FLAG_DESCRIPTORS;
    if (m_create_wallet_dialog->isDisablePrivateKeysChecked()) {
        flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    }
    if (m_create_wallet_dialog->isMakeBlankWalletChecked()) {
        flags |= WALLET_FLAG_BLANK_WALLET;
    }
    if (m_create_wallet_dialog->isExternalSignerChecked()) {
        flags |= WALLET_FLAG_EXTERNAL_SIGNER;
    }
    if (restore_from_mnemonic) {
        flags |= WALLET_FLAG_BLANK_WALLET;
        flags &= ~WALLET_FLAG_DISABLE_PRIVATE_KEYS;
        flags &= ~WALLET_FLAG_EXTERNAL_SIGNER;
    }

    QTimer::singleShot(500ms, worker(), [this, name, flags, restore_from_mnemonic, restore_from_file, backup_file_path] {
        interfaces::WalletLoader::RestoreProgressFn progress_fn;
        if (restore_from_mnemonic) {
            progress_fn = [this](const std::string& title, int progress) {
                QMetaObject::invokeMethod(this, [this, title = QString::fromStdString(title), progress] {
                    updateProgressDialog(title, progress);
                }, Qt::QueuedConnection);
            };
        }
        auto wallet{restore_from_file
            ? node().walletLoader().restoreWallet(backup_file_path, name, m_warning_message)
            : restore_from_mnemonic
                ? node().walletLoader().createWalletFromMnemonic(name, m_wallet_passphrase, std::move(m_mnemonic), std::move(m_bip39_passphrase), flags, m_warning_message, progress_fn)
                : node().walletLoader().createWallet(name, m_wallet_passphrase, std::move(m_bip39_passphrase), flags, m_warning_message)};
        ClearPassphrase(m_mnemonic);
        ClearPassphrase(m_bip39_passphrase);

        if (wallet) {
            m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*wallet), /*publish=*/false);
        } else {
            m_error_message = util::ErrorString(wallet);
        }

        QTimer::singleShot(500ms, this, &CreateWalletActivity::finish);
    });
}

void CreateWalletActivity::finish()
{
    if (m_wallet_model && m_progress_dialog) m_progress_dialog->close();
    if (m_wallet_model && m_restore_from_mnemonic) m_wallet_model->forceBalanceUpdate();
    bool unlocked_for_display{true};
    if (m_wallet_model) {
        const SecureString* passphrase_hint = m_wallet_passphrase.empty() ? nullptr : &m_wallet_passphrase;
        unlocked_for_display = UnlockWalletForDisplay(m_wallet_model, m_parent_widget, passphrase_hint);
    }
    ClearPassphrase(m_wallet_passphrase);
    ClearPassphrase(m_mnemonic);
    ClearPassphrase(m_bip39_passphrase);
    if (m_wallet_model && !unlocked_for_display) {
        m_wallet_model->wallet().remove();
        removeWalletModel(m_wallet_model);
        m_wallet_model = nullptr;
    }

    if (m_wallet_model) {
        m_wallet_controller->publishWallet(m_wallet_model);
        Q_EMIT created(m_wallet_model);
    }

    Q_EMIT finished();

    if (!m_error_message.empty()) {
        QMessageBox::critical(m_parent_widget, m_restoring ? tr("Restore wallet failed") : tr("Create wallet failed"), QString::fromStdString(m_error_message.translated));
    } else if (!m_warning_message.empty()) {
        QMessageBox::warning(m_parent_widget, m_restoring ? tr("Restore wallet warning") : tr("Create wallet warning"), QString::fromStdString(Join(m_warning_message, Untranslated("\n")).translated));
    }
}

void CreateWalletActivity::create()
{
    m_create_wallet_dialog = new CreateWalletDialog(m_parent_widget);

    std::vector<std::unique_ptr<interfaces::ExternalSigner>> signers;
    try {
        signers = node().listExternalSigners();
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(nullptr, tr("Can't list signers"), e.what());
    }
    if (signers.size() > 1) {
        QMessageBox::critical(nullptr, tr("Too many external signers found"), QString::fromStdString("More than one external signer found. Please connect only one at a time."));
        signers.clear();
    }
    m_create_wallet_dialog->setSigners(signers);

    m_create_wallet_dialog->setWindowModality(Qt::ApplicationModal);
    m_create_wallet_dialog->show();

    connect(m_create_wallet_dialog, &QObject::destroyed, [this] {
        m_create_wallet_dialog = nullptr;
    });
    connect(m_create_wallet_dialog, &QDialog::rejected, [this] {
        if (m_create_wallet_dialog) m_create_wallet_dialog->clearSensitiveFields();
        ClearPassphrase(m_wallet_passphrase);
        ClearPassphrase(m_mnemonic);
        ClearPassphrase(m_bip39_passphrase);
        Q_EMIT finished();
    });
    connect(m_create_wallet_dialog, &QDialog::accepted, [this] {
        if (!m_create_wallet_dialog->isRestoreFileChecked() && m_create_wallet_dialog->isEncryptWalletChecked()) {
            askPassphrase();
        } else {
            createWallet();
        }
    });
}

OpenWalletActivity::OpenWalletActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : WalletControllerActivity(wallet_controller, parent_widget)
{
}

void OpenWalletActivity::finish()
{
    if (!m_error_message.empty()) {
        QMessageBox::critical(m_parent_widget, tr("Open wallet failed"), QString::fromStdString(m_error_message.translated));
    } else if (!m_warning_message.empty()) {
        QMessageBox::warning(m_parent_widget, tr("Open wallet warning"), QString::fromStdString(Join(m_warning_message, Untranslated("\n")).translated));
    }

    if (m_wallet_model && m_progress_dialog) m_progress_dialog->close();
    if (m_wallet_model && !UnlockWalletForDisplay(m_wallet_model, m_parent_widget)) {
        m_wallet_model->wallet().remove();
        removeWalletModel(m_wallet_model);
        m_wallet_model = nullptr;
    }

    if (m_wallet_model) {
        m_wallet_controller->publishWallet(m_wallet_model);
        Q_EMIT opened(m_wallet_model);
    }

    Q_EMIT finished();
}

void OpenWalletActivity::open(const std::string& path)
{
    QString name = path.empty() ? QString("["+tr("default wallet")+"]") : QString::fromStdString(path);

    showProgressDialog(
        //: Title of window indicating the progress of opening of a wallet.
        tr("Open Wallet"),
        /*: Descriptive text of the open wallet progress window which indicates
            to the user which wallet is currently being opened. */
        tr("Opening Wallet <b>%1</b>...").arg(name.toHtmlEscaped()));

    QTimer::singleShot(0, worker(), [this, path] {
        auto wallet{node().walletLoader().loadWallet(path, m_warning_message)};

        if (wallet) {
            m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*wallet), /*publish=*/false);
        } else {
            m_error_message = util::ErrorString(wallet);
        }

        QTimer::singleShot(0, this, &OpenWalletActivity::finish);
    });
}

LoadWalletsActivity::LoadWalletsActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : WalletControllerActivity(wallet_controller, parent_widget)
{
}

void LoadWalletsActivity::load(bool show_loading_minimized)
{
    (void)show_loading_minimized;
    auto wallets{std::make_shared<std::vector<std::unique_ptr<interfaces::Wallet>>>(node().walletLoader().getWallets())};
    if (wallets->empty()) {
        QTimer::singleShot(0, this, [this] { Q_EMIT finished(); });
        return;
    }

    auto wallet_models{std::make_shared<std::vector<WalletModel*>>()};
    QTimer::singleShot(0, worker(), [this, wallets, wallet_models] {
        for (auto& wallet : *wallets) {
            wallet_models->push_back(m_wallet_controller->getOrCreateWallet(std::move(wallet), /*publish=*/false));
        }

        QTimer::singleShot(0, this, [this, wallet_models] {
            for (WalletModel* wallet_model : *wallet_models) {
                m_wallet_controller->publishWallet(wallet_model);
            }
            Q_EMIT finished();
        });
    });
}

RestoreWalletActivity::RestoreWalletActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : WalletControllerActivity(wallet_controller, parent_widget)
{
}

void RestoreWalletActivity::restore(const fs::path& backup_file, const std::string& wallet_name)
{
    QString name = QString::fromStdString(wallet_name);

    showProgressDialog(
        //: Title of progress window which is displayed when wallets are being restored.
        tr("Restore Wallet"),
        /*: Descriptive text of the restore wallets progress window which indicates to
            the user that wallets are currently being restored.*/
        tr("Restoring Wallet <b>%1</b>…").arg(name.toHtmlEscaped()));

    QTimer::singleShot(0, worker(), [this, backup_file, wallet_name] {
        auto wallet{node().walletLoader().restoreWallet(backup_file, wallet_name, m_warning_message)};

        if (wallet) {
            m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*wallet), /*publish=*/false);
        } else {
            m_error_message = util::ErrorString(wallet);
        }

        QTimer::singleShot(0, this, &RestoreWalletActivity::finish);
    });
}

void RestoreWalletActivity::finish()
{
    if (!m_error_message.empty()) {
        //: Title of message box which is displayed when the wallet could not be restored.
        QMessageBox::critical(m_parent_widget, tr("Restore wallet failed"), QString::fromStdString(m_error_message.translated));
    } else if (!m_warning_message.empty()) {
        //: Title of message box which is displayed when the wallet is restored with some warning.
        QMessageBox::warning(m_parent_widget, tr("Restore wallet warning"), QString::fromStdString(Join(m_warning_message, Untranslated("\n")).translated));
    } else {
        //: Title of message box which is displayed when the wallet is successfully restored.
        QMessageBox::information(m_parent_widget, tr("Restore wallet message"), QString::fromStdString(Untranslated("Wallet restored successfully \n").translated));
    }

    if (m_wallet_model && m_progress_dialog) m_progress_dialog->close();
    if (m_wallet_model && !UnlockWalletForDisplay(m_wallet_model, m_parent_widget)) {
        m_wallet_model->wallet().remove();
        removeWalletModel(m_wallet_model);
        m_wallet_model = nullptr;
    }

    if (m_wallet_model) {
        m_wallet_controller->publishWallet(m_wallet_model);
        Q_EMIT restored(m_wallet_model);
    }

    Q_EMIT finished();
}

void MigrateWalletActivity::migrate(WalletModel* wallet_model)
{
    // Warn the user about migration
    QMessageBox box(m_parent_widget);
    box.setWindowTitle(tr("Migrate wallet"));
    box.setText(tr("Are you sure you wish to migrate the wallet <i>%1</i>?").arg(GUIUtil::HtmlEscape(wallet_model->getDisplayName())));
    box.setInformativeText(tr("Migrating the wallet will convert this wallet to one or more descriptor wallets. A new wallet backup will need to be made.\n"
                "If this wallet contains any watchonly scripts, a new wallet will be created which contains those watchonly scripts.\n"
                "If this wallet contains any solvable but not watched scripts, a different and new wallet will be created which contains those scripts.\n\n"
                "The migration process will create a backup of the wallet before migrating. This backup file will be named "
                "<wallet name>-<timestamp>.legacy.bak and can be found in the directory for this wallet. In the event of "
                "an incorrect migration, the backup can be restored with the \"Restore Wallet\" functionality."));
    box.setStandardButtons(QMessageBox::Yes|QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Yes);
    if (box.exec() != QMessageBox::Yes) return;

    // Get the passphrase if it is encrypted regardless of it is locked or unlocked. We need the passphrase itself.
    SecureString passphrase;
    WalletModel::EncryptionStatus enc_status = wallet_model->getEncryptionStatus();
    if (enc_status == WalletModel::EncryptionStatus::Locked || enc_status == WalletModel::EncryptionStatus::Unlocked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, m_parent_widget, &passphrase);
        dlg.setModel(wallet_model);
        dlg.exec();
    }

    // GUI needs to remove the wallet so that it can actually be unloaded by migration
    const std::string name = wallet_model->wallet().getWalletName();
    m_wallet_controller->removeAndDeleteWallet(wallet_model);

    showProgressDialog(tr("Migrate Wallet"), tr("Migrating Wallet <b>%1</b>…").arg(GUIUtil::HtmlEscape(name)));

    QTimer::singleShot(0, worker(), [this, name, passphrase] {
        auto res{node().walletLoader().migrateWallet(name, passphrase)};

        if (res) {
            m_success_message = tr("The wallet '%1' was migrated successfully.").arg(GUIUtil::HtmlEscape(res->wallet->getWalletName()));
            if (res->watchonly_wallet_name) {
                m_success_message += QChar(' ') + tr("Watchonly scripts have been migrated to a new wallet named '%1'.").arg(GUIUtil::HtmlEscape(res->watchonly_wallet_name.value()));
            }
            if (res->solvables_wallet_name) {
                m_success_message += QChar(' ') + tr("Solvable but not watched scripts have been migrated to a new wallet named '%1'.").arg(GUIUtil::HtmlEscape(res->solvables_wallet_name.value()));
            }
            m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(res->wallet), /*publish=*/false);
        } else {
            m_error_message = util::ErrorString(res);
        }

        QTimer::singleShot(0, this, &MigrateWalletActivity::finish);
    });
}

void MigrateWalletActivity::finish()
{
    if (!m_error_message.empty()) {
        QMessageBox::critical(m_parent_widget, tr("Migration failed"), QString::fromStdString(m_error_message.translated));
    } else {
        QMessageBox::information(m_parent_widget, tr("Migration Successful"), m_success_message);
    }

    if (m_wallet_model && !UnlockWalletForDisplay(m_wallet_model, m_parent_widget)) {
        m_wallet_model->wallet().remove();
        removeWalletModel(m_wallet_model);
        m_wallet_model = nullptr;
    }

    if (m_wallet_model) {
        m_wallet_controller->publishWallet(m_wallet_model);
        Q_EMIT migrated(m_wallet_model);
    }

    Q_EMIT finished();
}
