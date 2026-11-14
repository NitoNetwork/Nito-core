// Copyright (c) 2019-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/nito-config.h>
#endif

#include <interfaces/wallet.h>
#include <interfaces/node.h>
#include <qt/createwalletdialog.h>
#include <qt/forms/ui_createwalletdialog.h>

#include <qt/guiutil.h>

#include <support/cleanse.h>
#include <util/result.h>
#include <wallet/bip39.h>

#include <QByteArray>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStringList>
#include <QToolButton>

namespace {

void ClearPassphrase(SecureString& passphrase)
{
    if (!passphrase.empty()) memory_cleanse(passphrase.data(), passphrase.size());
    SecureString empty;
    passphrase.swap(empty);
}

SecureString ReadSecureText(const QLineEdit* line_edit)
{
    QByteArray utf8{line_edit->text().toUtf8()};
    SecureString result;
    result.reserve(static_cast<size_t>(utf8.size()));
    result.assign(utf8.constData(), utf8.constData() + utf8.size());
    if (!utf8.isEmpty()) memory_cleanse(utf8.data(), static_cast<size_t>(utf8.size()));
    return result;
}

void WipeLineEdit(QLineEdit* line_edit)
{
    const QSignalBlocker blocker{line_edit};
    const int length{static_cast<int>(line_edit->text().size())};
    if (length > 0) line_edit->setText(QString(length, QChar{0}));
    line_edit->clear();
}

void WipePlainTextEdit(QPlainTextEdit* text_edit)
{
    const QSignalBlocker blocker{text_edit};
    const int length{static_cast<int>(text_edit->toPlainText().size())};
    if (length > 0) text_edit->setPlainText(QString(length, QChar{0}));
    text_edit->clear();
}

} // namespace

CreateWalletDialog::CreateWalletDialog(QWidget* parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::CreateWalletDialog)
{
    ui->setupUi(this);
    GUIUtil::PolishDialogButtonBox(ui->buttonBox);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Create"));
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    ui->recovery_phrase_widget->setVisible(false);
    ui->bip39_passphrase_widget->setVisible(false);
    ui->wallet_name_line_edit->setFocus(Qt::ActiveWindowFocusReason);

    const Qt::InputMethodHints sensitive_input_hints{
        Qt::ImhHiddenText | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase | Qt::ImhSensitiveData};
    for (QLineEdit* field : {ui->bip39_passphrase_line_edit, ui->bip39_passphrase_confirmation_line_edit}) {
        field->setEchoMode(QLineEdit::Password);
        field->setInputMethodHints(sensitive_input_hints);
        // Keep one extra character as a rejection sentinel. Capping at the
        // exact byte limit would silently truncate an overlong ASCII value
        // into a different valid passphrase before validation can reject it.
        field->setMaxLength(static_cast<int>(wallet::MAX_BIP39_PASSPHRASE_SIZE + 1));
    }

    connect(ui->wallet_name_line_edit, &QLineEdit::textEdited, [this]() {
        updateCreateButtonState();
    });

    connect(ui->restore_file_checkbox, &QCheckBox::toggled, [this](bool checked) {
        if (checked && ui->restore_mnemonic_checkbox->isChecked()) {
            ui->restore_mnemonic_checkbox->setChecked(false);
        }
        updateRecoveryPhraseState();
        updateCreateButtonState();
    });

    connect(ui->restore_mnemonic_checkbox, &QCheckBox::toggled, [this]() {
        if (ui->restore_mnemonic_checkbox->isChecked() && ui->restore_file_checkbox->isChecked()) {
            ui->restore_file_checkbox->setChecked(false);
        }
        updateRecoveryPhraseState();
        updateCreateButtonState();
    });

    connect(ui->recovery_phrase_text_edit, &QPlainTextEdit::textChanged, [this]() {
        updateCreateButtonState();
    });

    connect(ui->bip39_passphrase_checkbox, &QCheckBox::toggled, [this](bool checked) {
        if (!checked) clearBIP39Passphrase();
        updateBIP39PassphraseState();
        updateCreateButtonState();
        if (checked) ui->bip39_passphrase_line_edit->setFocus(Qt::TabFocusReason);
    });

    connect(ui->bip39_passphrase_line_edit, &QLineEdit::textChanged, [this]() {
        updateCreateButtonState();
    });
    connect(ui->bip39_passphrase_confirmation_line_edit, &QLineEdit::textChanged, [this]() {
        updateCreateButtonState();
    });
    connect(ui->bip39_passphrase_backup_checkbox, &QCheckBox::toggled, [this]() {
        updateCreateButtonState();
    });
    connect(ui->show_bip39_passphrase_button, &QToolButton::toggled, [this](bool show) {
        const auto echo_mode{show ? QLineEdit::Normal : QLineEdit::Password};
        ui->bip39_passphrase_line_edit->setEchoMode(echo_mode);
        ui->bip39_passphrase_confirmation_line_edit->setEchoMode(echo_mode);
        ui->show_bip39_passphrase_button->setText(show ? tr("Hide") : tr("Show"));
    });

    connect(ui->encrypt_wallet_checkbox, &QCheckBox::toggled, [this](bool checked) {
        // Disable the disable_privkeys_checkbox and external_signer_checkbox when isEncryptWalletChecked is
        // set to true, enable it when isEncryptWalletChecked is false.
        ui->disable_privkeys_checkbox->setEnabled(!checked);
#ifdef ENABLE_EXTERNAL_SIGNER
        ui->external_signer_checkbox->setEnabled(m_has_signers && !checked);
#endif
        // When the disable_privkeys_checkbox is disabled, uncheck it.
        if (!ui->disable_privkeys_checkbox->isEnabled()) {
            ui->disable_privkeys_checkbox->setChecked(false);
        }

        // When the external_signer_checkbox box is disabled, uncheck it.
        if (!ui->external_signer_checkbox->isEnabled()) {
            ui->external_signer_checkbox->setChecked(false);
        }

        updateRecoveryPhraseState();
        updateCreateButtonState();
    });

    connect(ui->external_signer_checkbox, &QCheckBox::toggled, [this](bool checked) {
        ui->encrypt_wallet_checkbox->setEnabled(!checked);
        ui->blank_wallet_checkbox->setEnabled(!checked);
        ui->disable_privkeys_checkbox->setEnabled(!checked);

        // The external signer checkbox is only enabled when a device is detected.
        // In that case it is checked by default. Toggling it restores the other
        // options to their default.
        ui->encrypt_wallet_checkbox->setChecked(false);
        ui->disable_privkeys_checkbox->setChecked(checked);
        ui->blank_wallet_checkbox->setChecked(false);
        updateRecoveryPhraseState();
        updateCreateButtonState();
    });

    connect(ui->disable_privkeys_checkbox, &QCheckBox::toggled, [this](bool checked) {
        // Disable the encrypt_wallet_checkbox when isDisablePrivateKeysChecked is
        // set to true, enable it when isDisablePrivateKeysChecked is false.
        ui->encrypt_wallet_checkbox->setEnabled(!checked);

        // Wallets without private keys cannot set blank
        ui->blank_wallet_checkbox->setEnabled(!checked);
        if (checked) {
            ui->blank_wallet_checkbox->setChecked(false);
        }

        // When the encrypt_wallet_checkbox is disabled, uncheck it.
        if (!ui->encrypt_wallet_checkbox->isEnabled()) {
            ui->encrypt_wallet_checkbox->setChecked(false);
        }
        updateRecoveryPhraseState();
        updateCreateButtonState();
    });

    connect(ui->blank_wallet_checkbox, &QCheckBox::toggled, [this](bool checked) {
        // Disable the disable_privkeys_checkbox when blank_wallet_checkbox is checked
        // as blank-ness only pertains to wallets with private keys.
        ui->disable_privkeys_checkbox->setEnabled(!checked);
        if (checked) {
            ui->disable_privkeys_checkbox->setChecked(false);
        }
        updateRecoveryPhraseState();
        updateCreateButtonState();
    });

#ifndef ENABLE_EXTERNAL_SIGNER
        //: "External signing" means using devices such as hardware wallets.
        ui->external_signer_checkbox->setToolTip(tr("Compiled without external signing support (required for external signing)"));
        ui->external_signer_checkbox->setEnabled(false);
        ui->external_signer_checkbox->setChecked(false);
#endif

    updateRecoveryPhraseState();
    updateCreateButtonState();
}

CreateWalletDialog::~CreateWalletDialog()
{
    clearSensitiveFields();
    delete ui;
}

void CreateWalletDialog::setSigners(const std::vector<std::unique_ptr<interfaces::ExternalSigner>>& signers)
{
    m_has_signers = !signers.empty();
    if (m_has_signers) {
        ui->external_signer_checkbox->setEnabled(true);
        ui->external_signer_checkbox->setChecked(true);
        ui->encrypt_wallet_checkbox->setEnabled(false);
        ui->encrypt_wallet_checkbox->setChecked(false);
        // The order matters, because connect() is called when toggling a checkbox:
        ui->blank_wallet_checkbox->setEnabled(false);
        ui->blank_wallet_checkbox->setChecked(false);
        ui->disable_privkeys_checkbox->setEnabled(false);
        ui->disable_privkeys_checkbox->setChecked(true);
        const std::string label = signers[0]->getName();
        ui->wallet_name_line_edit->setText(QString::fromStdString(label));
        updateCreateButtonState();
    } else {
        ui->external_signer_checkbox->setEnabled(false);
    }
}

QString CreateWalletDialog::walletName() const
{
    return ui->wallet_name_line_edit->text();
}

bool CreateWalletDialog::isEncryptWalletChecked() const
{
    return ui->encrypt_wallet_checkbox->isChecked();
}

bool CreateWalletDialog::isDisablePrivateKeysChecked() const
{
    return ui->disable_privkeys_checkbox->isChecked();
}

bool CreateWalletDialog::isMakeBlankWalletChecked() const
{
    return ui->blank_wallet_checkbox->isChecked();
}

bool CreateWalletDialog::isExternalSignerChecked() const
{
    return ui->external_signer_checkbox->isChecked();
}

bool CreateWalletDialog::isRestoreMnemonicChecked() const
{
    return ui->restore_mnemonic_checkbox->isChecked();
}

bool CreateWalletDialog::isRestoreFileChecked() const
{
    return ui->restore_file_checkbox->isChecked();
}

bool CreateWalletDialog::isBIP39PassphraseChecked() const
{
    return ui->bip39_passphrase_checkbox->isChecked();
}

SecureString CreateWalletDialog::recoveryPhrase() const
{
    QByteArray phrase{ui->recovery_phrase_text_edit->toPlainText().simplified().toUtf8()};
    SecureString secure_phrase;
    secure_phrase.reserve(static_cast<size_t>(phrase.size()));
    secure_phrase.assign(phrase.constData(), phrase.constData() + phrase.size());
    if (!phrase.isEmpty()) memory_cleanse(phrase.data(), static_cast<size_t>(phrase.size()));
    return secure_phrase;
}

SecureString CreateWalletDialog::bip39Passphrase() const
{
    return isBIP39PassphraseChecked() ? ReadSecureText(ui->bip39_passphrase_line_edit) : SecureString{};
}

void CreateWalletDialog::clearBIP39Passphrase()
{
    WipeLineEdit(ui->bip39_passphrase_line_edit);
    WipeLineEdit(ui->bip39_passphrase_confirmation_line_edit);
    ui->show_bip39_passphrase_button->setChecked(false);
    ui->bip39_passphrase_backup_checkbox->setChecked(false);
    ui->bip39_passphrase_error_label->clear();
    ui->bip39_passphrase_error_label->setVisible(false);
}

void CreateWalletDialog::clearSensitiveFields()
{
    WipePlainTextEdit(ui->recovery_phrase_text_edit);
    if (ui->bip39_passphrase_checkbox->isChecked()) {
        ui->bip39_passphrase_checkbox->setChecked(false);
    } else {
        clearBIP39Passphrase();
    }
}

int CreateWalletDialog::recoveryPhraseWordCount() const
{
    const QString phrase{ui->recovery_phrase_text_edit->toPlainText().simplified()};
    if (phrase.isEmpty()) return 0;
    return phrase.split(QLatin1Char(' '), Qt::SkipEmptyParts).size();
}

void CreateWalletDialog::updateCreateButtonState()
{
    const bool has_wallet_name{!ui->wallet_name_line_edit->text().trimmed().isEmpty()};
    const int word_count{recoveryPhraseWordCount()};
    const bool has_valid_phrase{!isRestoreMnemonicChecked() || word_count == 12 || word_count == 24};
    QString bip39_error;
    const bool has_valid_bip39_passphrase{validateBIP39Passphrase(bip39_error)};
    ui->bip39_passphrase_error_label->setText(bip39_error);
    ui->bip39_passphrase_error_label->setVisible(!bip39_error.isEmpty());
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(has_wallet_name && has_valid_phrase && has_valid_bip39_passphrase);
}

void CreateWalletDialog::updateRecoveryPhraseState()
{
    const bool restore_mnemonic{ui->restore_mnemonic_checkbox->isChecked()};
    const bool restore_file{ui->restore_file_checkbox->isChecked()};
    const bool restore{restore_mnemonic || restore_file};
    ui->recovery_phrase_widget->setVisible(restore_mnemonic);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(restore ? tr("Restore") : tr("Create"));

    if (restore_file) {
        ui->encrypt_wallet_checkbox->setChecked(false);
        ui->encrypt_wallet_checkbox->setEnabled(false);
        ui->disable_privkeys_checkbox->setChecked(false);
        ui->disable_privkeys_checkbox->setEnabled(false);
        ui->blank_wallet_checkbox->setChecked(false);
        ui->blank_wallet_checkbox->setEnabled(false);
        ui->external_signer_checkbox->setChecked(false);
        ui->external_signer_checkbox->setEnabled(false);
        updateBIP39PassphraseState();
        return;
    }

    if (restore_mnemonic) {
        ui->encrypt_wallet_checkbox->setEnabled(true);
        ui->disable_privkeys_checkbox->setChecked(false);
        ui->disable_privkeys_checkbox->setEnabled(false);
        ui->blank_wallet_checkbox->setChecked(false);
        ui->blank_wallet_checkbox->setEnabled(false);
        ui->external_signer_checkbox->setChecked(false);
        ui->external_signer_checkbox->setEnabled(false);
        updateBIP39PassphraseState();
        return;
    }

    ui->encrypt_wallet_checkbox->setEnabled(!ui->external_signer_checkbox->isChecked());
    ui->disable_privkeys_checkbox->setEnabled(!ui->encrypt_wallet_checkbox->isChecked() && !ui->blank_wallet_checkbox->isChecked() && !ui->external_signer_checkbox->isChecked());
    ui->blank_wallet_checkbox->setEnabled(!ui->disable_privkeys_checkbox->isChecked() && !ui->external_signer_checkbox->isChecked());
#ifdef ENABLE_EXTERNAL_SIGNER
    ui->external_signer_checkbox->setEnabled(m_has_signers && !ui->encrypt_wallet_checkbox->isChecked());
#else
    ui->external_signer_checkbox->setEnabled(false);
#endif
    updateBIP39PassphraseState();
}

bool CreateWalletDialog::validateBIP39Passphrase(QString& error) const
{
    error.clear();
    if (!isBIP39PassphraseChecked()) return true;

    SecureString passphrase{ReadSecureText(ui->bip39_passphrase_line_edit)};
    auto normalized{wallet::NormalizeBIP39Passphrase(passphrase)};
    ClearPassphrase(passphrase);
    if (!normalized) {
        error = QString::fromStdString(util::ErrorString(normalized).translated);
        return false;
    }

    if (isRestoreMnemonicChecked()) {
        ClearPassphrase(*normalized);
        return true;
    }

    SecureString confirmation{ReadSecureText(ui->bip39_passphrase_confirmation_line_edit)};
    auto normalized_confirmation{wallet::NormalizeBIP39Passphrase(confirmation)};
    ClearPassphrase(confirmation);
    if (!normalized_confirmation) {
        ClearPassphrase(*normalized);
        error = QString::fromStdString(util::ErrorString(normalized_confirmation).translated);
        return false;
    }

    const bool matches{*normalized == *normalized_confirmation};
    ClearPassphrase(*normalized);
    ClearPassphrase(*normalized_confirmation);
    if (!matches) {
        error = tr("The BIP39 passphrase confirmation does not match.");
        return false;
    }
    if (!ui->bip39_passphrase_backup_checkbox->isChecked()) {
        error = tr("Confirm that you saved the BIP39 passphrase exactly and separately.");
        return false;
    }
    return true;
}

void CreateWalletDialog::updateBIP39PassphraseState()
{
    const bool restore_mnemonic{isRestoreMnemonicChecked()};
    const bool allowed{!isRestoreFileChecked() &&
        (restore_mnemonic || (!isDisablePrivateKeysChecked() && !isMakeBlankWalletChecked() && !isExternalSignerChecked()))};

    ui->bip39_passphrase_checkbox->setEnabled(allowed);
    if (!allowed && ui->bip39_passphrase_checkbox->isChecked()) {
        ui->bip39_passphrase_checkbox->setChecked(false);
        return;
    }

    const bool expanded{allowed && ui->bip39_passphrase_checkbox->isChecked()};
    ui->bip39_passphrase_widget->setVisible(expanded);
    const bool needs_confirmation{expanded && !restore_mnemonic};
    ui->bip39_passphrase_confirmation_label->setVisible(needs_confirmation);
    ui->bip39_passphrase_confirmation_line_edit->setVisible(needs_confirmation);
    ui->bip39_passphrase_backup_checkbox->setVisible(needs_confirmation);
    if (!needs_confirmation) {
        WipeLineEdit(ui->bip39_passphrase_confirmation_line_edit);
        ui->bip39_passphrase_backup_checkbox->setChecked(false);
    }
}
