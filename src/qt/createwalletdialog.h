// Copyright (c) 2019-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CREATEWALLETDIALOG_H
#define BITCOIN_QT_CREATEWALLETDIALOG_H

#include <support/allocators/secure.h>

#include <QDialog>

#include <memory>

namespace interfaces {
class ExternalSigner;
} // namespace interfaces

class WalletModel;

namespace Ui {
    class CreateWalletDialog;
}

/** Dialog for creating wallets
 */
class CreateWalletDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateWalletDialog(QWidget* parent);
    virtual ~CreateWalletDialog();

    void setSigners(const std::vector<std::unique_ptr<interfaces::ExternalSigner>>& signers);

    QString walletName() const;
    bool isEncryptWalletChecked() const;
    bool isDisablePrivateKeysChecked() const;
    bool isMakeBlankWalletChecked() const;
    bool isExternalSignerChecked() const;
    bool isRestoreMnemonicChecked() const;
    bool isRestoreFileChecked() const;
    bool isBIP39PassphraseChecked() const;
    SecureString recoveryPhrase() const;
    SecureString bip39Passphrase() const;
    void clearSensitiveFields();

private:
    void clearBIP39Passphrase();
    int recoveryPhraseWordCount() const;
    bool validateBIP39Passphrase(QString& error) const;
    void updateCreateButtonState();
    void updateRecoveryPhraseState();
    void updateBIP39PassphraseState();

    Ui::CreateWalletDialog *ui;
    bool m_has_signers = false;
};

#endif // BITCOIN_QT_CREATEWALLETDIALOG_H
