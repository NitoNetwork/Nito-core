// Copyright (c) 2011-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactiondesc.h>

#include <qt/nitounits.h>
#include <qt/guiutil.h>
#include <qt/paymentserver.h>
#include <qt/transactionrecord.h>

#include <common/system.h>
#include <consensus/consensus.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <logging.h>
#include <policy/policy.h>
#include <validation.h>
#include <wallet/types.h>

#include <stdint.h>
#include <string>

#include <QLatin1String>
#include <QStringList>

using wallet::ISMINE_ALL;
using wallet::ISMINE_NO;
using wallet::ISMINE_SPENDABLE;
using wallet::ISMINE_WATCH_ONLY;
using wallet::isminetype;

namespace {
bool IsUserVisibleRecipientOutput(const CTxOut& txout)
{
    return txout.nValue > 0 && !txout.scriptPubKey.IsUnspendable();
}
} // namespace

QString TransactionDesc::FormatTxStatus(const interfaces::WalletTxStatus& status, bool inMempool)
{
    int depth = status.depth_in_main_chain;
    if (depth < 0) {
        /*: Text explaining the current status of a transaction, shown in the
            status field of the details window for this transaction. This status
            represents an unconfirmed transaction that conflicts with a confirmed
            transaction. */
        return tr("conflicted with a transaction with %1 confirmations").arg(-depth);
    } else if (depth == 0) {
        QString s;
        if (inMempool) {
            /*: Text explaining the current status of a transaction, shown in the
                status field of the details window for this transaction. This status
                represents an unconfirmed transaction that is in the memory pool. */
            s = tr("0/unconfirmed, in memory pool");
        } else {
            /*: Text explaining the current status of a transaction, shown in the
                status field of the details window for this transaction. This status
                represents an unconfirmed transaction that is not in the memory pool. */
            s = tr("0/unconfirmed, not in memory pool");
        }
        if (status.is_abandoned) {
            /*: Text explaining the current status of a transaction, shown in the
                status field of the details window for this transaction. This
                status represents an abandoned transaction. */
            s += QLatin1String(", ") + tr("abandoned");
        }
        return s;
    } else if (depth < 6) {
        /*: Text explaining the current status of a transaction, shown in the
            status field of the details window for this transaction. This
            status represents a transaction confirmed in at least one block,
            but less than 6 blocks. */
        return tr("%1/unconfirmed").arg(depth);
    } else {
        /*: Text explaining the current status of a transaction, shown in the
            status field of the details window for this transaction. This status
            represents a transaction confirmed in 6 or more blocks. */
        return tr("%1 confirmations").arg(depth);
    }
}

// Takes an encoded PaymentRequest as a string and tries to find the Common Name of the X.509 certificate
// used to sign the PaymentRequest.
bool GetPaymentRequestMerchant(const std::string& pr, QString& merchant)
{
    // Search for the supported pki type strings
    if (pr.find(std::string({0x12, 0x0b}) + "x509+sha256") != std::string::npos || pr.find(std::string({0x12, 0x09}) + "x509+sha1") != std::string::npos) {
        // We want the common name of the Subject of the cert. This should be the second occurrence
        // of the bytes 0x0603550403. The first occurrence of those is the common name of the issuer.
        // After those bytes will be either 0x13 or 0x0C, then length, then either the ascii or utf8
        // string with the common name which is the merchant name
        size_t cn_pos = pr.find({0x06, 0x03, 0x55, 0x04, 0x03});
        if (cn_pos != std::string::npos) {
            cn_pos = pr.find({0x06, 0x03, 0x55, 0x04, 0x03}, cn_pos + 5);
            if (cn_pos != std::string::npos) {
                cn_pos += 5;
                if (pr[cn_pos] == 0x13 || pr[cn_pos] == 0x0c) {
                    cn_pos++; // Consume the type
                    int str_len = pr[cn_pos];
                    cn_pos++; // Consume the string length
                    merchant = QString::fromUtf8(pr.data() + cn_pos, str_len);
                    return true;
                }
            }
        }
    }
    return false;
}

QString TransactionDesc::FormatInputAddresses(const interfaces::WalletTx& wtx, bool expanded)
{
    // Public inputs cannot identify the source of Orchard or mixed payments.
    if (wtx.is_coinbase || wtx.has_private_bundle) return {};

    QStringList addresses;
    for (const auto& address : wtx.txin_addresses) {
        addresses.append(QString::fromStdString(EncodeDestination(address)));
    }
    QString html = "<b>" + tr("From") + ":</b> ";
    if (addresses.isEmpty()) {
        return html + tr("Source address unavailable") + "<br>";
    }
    if (addresses.size() == 1) {
        html += GUIUtil::HtmlEscape(addresses.front());
    } else {
        const QString action = expanded ? tr("Hide input addresses") : tr("Show input addresses");
        html += "<a href=\"#input-addresses\" title=\"" + GUIUtil::HtmlEscape(action) + "\">";
        html += GUIUtil::HtmlEscape(expanded ? action : tr("%1 input addresses").arg(addresses.size()));
        html += "</a>";
    }
    if (!wtx.txin_addresses_complete) {
        html += " (" + tr("Some input addresses are unavailable.") + ")";
    }
    html += "<br>";
    if (expanded && addresses.size() > 1) {
        for (const auto& address : addresses) {
            html += "&nbsp;&nbsp;" + GUIUtil::HtmlEscape(address) + "<br>";
        }
    }
    return html;
}

QString TransactionDesc::toHTML(interfaces::Node& node, interfaces::Wallet& wallet, TransactionRecord* rec, NitoUnit unit, bool expand_input_addresses)
{
    int numBlocks;
    interfaces::WalletTxStatus status;
    interfaces::WalletOrderForm orderForm;
    bool inMempool;
    interfaces::WalletTx wtx = wallet.getWalletTxDetails(rec->hash, status, orderForm, inMempool, numBlocks);

    QString strHTML;

    strHTML.reserve(4000);
    strHTML += "<html><font face='verdana, arial, helvetica, sans-serif'>";

    if (rec->is_private_note_only && !wtx.tx) {
        interfaces::WalletTxStatus note_status{};
        note_status.depth_in_main_chain = rec->status.depth;
        note_status.is_abandoned = rec->status.status == TransactionStatus::Abandoned;
        strHTML += "<b>" + tr("Status") + ":</b> " + FormatTxStatus(note_status, false);
        strHTML += "<br>";
        strHTML += "<b>" + tr("Date") + ":</b> " + (rec->time ? GUIUtil::dateTimeStr(rec->time) : "") + "<br>";
        strHTML += "<b>" + tr("Privacy") + ":</b> " + tr("Bech32x private transaction") + "<br>";
        strHTML += "<b>" + tr("Private credit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, rec->credit) + "<br>";
        strHTML += "<b>" + tr("Net amount") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, rec->credit, true) + "<br>";
        strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxHash() + "<br>";
        strHTML += "<b>" + tr("Output index (vout)") + ":</b> " + QString::number(rec->getOutputIndex()) + "<br>";
        return strHTML + "</font></html>";
    }

    if (!wtx.tx) {
        strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxHash() + "<br>";
        return strHTML + "</font></html>";
    }

    int64_t nTime = wtx.time;
    CAmount nCredit = wtx.credit + wtx.private_credit;
    CAmount nDebit = wtx.debit + wtx.private_debit;
    CAmount nNet = nCredit - nDebit;
    CAmount nDisplayNet = nNet;

    if (nDebit == 0 && rec->credit > 0) {
        nDisplayNet = rec->credit;
    }

    strHTML += "<b>" + tr("Status") + ":</b> " + FormatTxStatus(status, inMempool);
    strHTML += "<br>";

    strHTML += "<b>" + tr("Date") + ":</b> " + (nTime ? GUIUtil::dateTimeStr(nTime) : "") + "<br>";

    if (rec->is_private || wtx.has_private_bundle) {
        strHTML += "<b>" + tr("Privacy") + ":</b> " + tr("Bech32x private transaction") + "<br>";
        if (!rec->is_private && wtx.private_credit > 0) {
            strHTML += "<b>" + tr("Private credit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, wtx.private_credit) + "<br>";
        }
        if (!rec->is_private && wtx.private_debit > 0) {
            strHTML += "<b>" + tr("Private debit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, -wtx.private_debit) + "<br>";
        }
        if (!rec->is_private && wtx.private_value_balance != 0) {
            strHTML += "<b>" + tr("Private value balance") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, wtx.private_value_balance) + "<br>";
        }
    }

    if (rec->type == TransactionRecord::InternalTransfer) {
        const CAmount row_amount = rec->credit + rec->debit;
        int internal_output_count{0};
        for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
            if (i >= wtx.txout_is_mine.size() || i >= wtx.txout_address.size()) {
                continue;
            }
            const CTxOut& txout = wtx.tx->vout[i];
            const isminetype mine = wtx.txout_is_mine[i];
            if (!(mine & (ISMINE_SPENDABLE | ISMINE_WATCH_ONLY)) || !IsUserVisibleRecipientOutput(txout)) {
                continue;
            }

            if (internal_output_count == 0) {
                strHTML += "<b>" + tr("To") + ":</b><br>";
            }
            const CTxDestination& dest = wtx.txout_address[i];
            strHTML += "&nbsp;&nbsp;";
            if (IsValidDestination(dest)) {
                std::string name;
                if (wallet.getAddress(dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty()) {
                    strHTML += GUIUtil::HtmlEscape(name) + " ";
                }
                strHTML += GUIUtil::HtmlEscape(EncodeDestination(dest));
                if (mine & ISMINE_WATCH_ONLY) {
                    strHTML += " (" + tr("watch-only") + ")";
                } else if (mine & ISMINE_SPENDABLE) {
                    strHTML += " (" + tr("own address") + ")";
                }
            } else {
                strHTML += tr("unknown");
            }
            strHTML += " - <b>" + tr("Amount") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, txout.nValue);
            strHTML += " - <b>" + tr("Output index (vout)") + ":</b> " + QString::number(i) + "<br>";
            ++internal_output_count;
        }
        if (internal_output_count == 0 && !rec->address.empty()) {
            CTxDestination dest = DecodeDestination(rec->address);
            std::string name;
            strHTML += "<b>" + tr("To") + ":</b> ";
            if (IsValidDestination(dest) &&
                wallet.getAddress(dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty()) {
                strHTML += GUIUtil::HtmlEscape(name) + " ";
            }
            strHTML += GUIUtil::HtmlEscape(rec->address);
            if (IsValidDestination(dest)) {
                isminetype ismine;
                if (wallet.getAddress(dest, /* name= */ nullptr, &ismine, /* purpose= */ nullptr) && ismine == ISMINE_SPENDABLE) {
                    strHTML += " (" + tr("own address") + ")";
                }
            }
            strHTML += "<br>";
        }
        // Internal transfers/consolidations are represented by their table row amount;
        // wallet-wide debit/credit totals are change heuristics and confuse this view.
        strHTML += "<b>" + tr("Amount") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, row_amount, true) + "<br>";
        if (wtx.fee > 0) {
            strHTML += "<b>" + tr("Transaction fee") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, -wtx.fee) + "<br>";
        }
        strHTML += "<b>" + tr("Net amount") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, nNet, true) + "<br>";
        strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxHash() + "<br>";
        strHTML += "<b>" + tr("Transaction total size") + ":</b> " + QString::number(wtx.tx->GetTotalSize()) + " bytes<br>";
        strHTML += "<b>" + tr("Transaction virtual size") + ":</b> " + QString::number(GetVirtualTransactionSize(*wtx.tx)) + " bytes<br>";
        strHTML += "<b>" + tr("Output index (vout)") + ":</b> ";
        const bool has_multiple_internal_outputs = internal_output_count > 1 || rec->is_multi_recipient;
        strHTML += has_multiple_internal_outputs ? tr("multiple recipients") : QString::number(rec->getOutputIndex());
        strHTML += "<br>";
        return strHTML + "</font></html>";
    }

    if (rec->type == TransactionRecord::PrivateUnshield) {
        if (!rec->address.empty()) {
            CTxDestination dest = DecodeDestination(rec->address);
            std::string name;
            strHTML += "<b>" + tr("To") + ":</b> ";
            if (IsValidDestination(dest) &&
                wallet.getAddress(dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty()) {
                strHTML += GUIUtil::HtmlEscape(name) + " ";
            }
            strHTML += GUIUtil::HtmlEscape(rec->address);
            if (IsValidDestination(dest)) {
                isminetype ismine;
                if (wallet.getAddress(dest, /* name= */ nullptr, &ismine, /* purpose= */ nullptr) && ismine == ISMINE_SPENDABLE) {
                    strHTML += " (" + tr("own address") + ")";
                }
            }
            strHTML += "<br>";
        }
        if (rec->debit < 0) {
            strHTML += "<b>" + tr("Debit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, rec->debit) + "<br>";
        }
        if (rec->credit > 0) {
            strHTML += "<b>" + tr("Credit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, rec->credit) + "<br>";
        }
        if (rec->debit < 0 && wtx.fee > 0) {
            strHTML += "<b>" + tr("Transaction fee") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, -wtx.fee) + "<br>";
        }
        strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxHash() + "<br>";
        strHTML += "<b>" + tr("Transaction total size") + ":</b> " + QString::number(wtx.tx->GetTotalSize()) + " bytes<br>";
        strHTML += "<b>" + tr("Transaction virtual size") + ":</b> " + QString::number(GetVirtualTransactionSize(*wtx.tx)) + " bytes<br>";
        strHTML += "<b>" + tr("Output index (vout)") + ":</b> " + QString::number(rec->getOutputIndex()) + "<br>";
        return strHTML + "</font></html>";
    }

    if (rec->is_private && wtx.has_private_bundle) {
        if (rec->debit < 0) {
            strHTML += "<b>" + tr("Debit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, rec->debit) + "<br>";
        } else if (rec->credit > 0) {
            strHTML += "<b>" + tr("Credit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, rec->credit) + "<br>";
        } else {
            strHTML += "<b>" + tr("Amount") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, rec->credit + rec->debit, true) + "<br>";
        }
        if (rec->debit < 0 && wtx.fee > 0) {
            strHTML += "<b>" + tr("Transaction fee") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, -wtx.fee) + "<br>";
        }
        strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxHash() + "<br>";
        strHTML += "<b>" + tr("Transaction total size") + ":</b> " + QString::number(wtx.tx->GetTotalSize()) + " bytes<br>";
        strHTML += "<b>" + tr("Transaction virtual size") + ":</b> " + QString::number(GetVirtualTransactionSize(*wtx.tx)) + " bytes<br>";
        strHTML += "<b>" + tr("Output index (vout)") + ":</b> " + QString::number(rec->getOutputIndex()) + "<br>";
        return strHTML + "</font></html>";
    }

    //
    // From
    //
    if (wtx.is_coinbase)
    {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Generated") + "<br>";
    }
    else if ((nNet <= 0 || wtx.has_private_bundle) && wtx.value_map.count("from") && !wtx.value_map["from"].empty())
    {
        // Online transaction
        strHTML += "<b>" + tr("From") + ":</b> " + GUIUtil::HtmlEscape(wtx.value_map["from"]) + "<br>";
    }
    else
    {
        // Offline transaction
        if (nNet > 0)
        {
            // Credit
            if (!wtx.has_private_bundle) {
                strHTML += FormatInputAddresses(wtx, expand_input_addresses);
            }
            CTxDestination address = DecodeDestination(rec->address);
            if (IsValidDestination(address)) {
                std::string name;
                isminetype ismine;
                if (wallet.getAddress(address, &name, &ismine, /* purpose= */ nullptr))
                {
                    if (wtx.has_private_bundle) {
                        strHTML += "<b>" + tr("From") + ":</b> " + tr("unknown") + "<br>";
                    }
                    strHTML += "<b>" + tr("To") + ":</b> ";
                    strHTML += GUIUtil::HtmlEscape(rec->address);
                    QString addressOwned = ismine == ISMINE_SPENDABLE ? tr("own address") : tr("watch-only");
                    if (!name.empty())
                        strHTML += " (" + addressOwned + ", " + tr("label") + ": " + GUIUtil::HtmlEscape(name) + ")";
                    else
                        strHTML += " (" + addressOwned + ")";
                    strHTML += "<br>";
                }
            }
        }
    }

    //
    // To
    //
    if (wtx.value_map.count("to") && !wtx.value_map["to"].empty())
    {
        // Online transaction
        std::string strAddress = wtx.value_map["to"];
        strHTML += "<b>" + tr("To") + ":</b> ";
        CTxDestination dest = DecodeDestination(strAddress);
        std::string name;
        if (wallet.getAddress(
                dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty())
            strHTML += GUIUtil::HtmlEscape(name) + " ";
        strHTML += GUIUtil::HtmlEscape(strAddress) + "<br>";
    }

    //
    // Amount
    //
    if (wtx.is_coinbase && nCredit == 0)
    {
        //
        // Coinbase
        //
        CAmount nUnmatured = 0;
        for (const CTxOut& txout : wtx.tx->vout)
            nUnmatured += wallet.getCredit(txout, ISMINE_ALL);
        strHTML += "<b>" + tr("Credit") + ":</b> ";
        if (status.is_in_main_chain)
            strHTML += NitoUnits::formatHtmlWithUnit(unit, nUnmatured)+ " (" + tr("matures in %n more block(s)", "", status.blocks_to_maturity) + ")";
        else
            strHTML += "(" + tr("not accepted") + ")";
        strHTML += "<br>";
    }
    else if (nNet > 0)
    {
        //
        // Credit
        //
        const CAmount nDisplayCredit = rec->credit > 0 ? rec->credit : nNet;
        strHTML += "<b>" + tr("Credit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, nDisplayCredit) + "<br>";
    }
    else
    {
        isminetype fAllFromMe = wtx.txin_is_mine.empty() ? ISMINE_NO : ISMINE_SPENDABLE;
        for (const isminetype mine : wtx.txin_is_mine)
        {
            if(fAllFromMe > mine) fAllFromMe = mine;
        }

        isminetype fAllToMe = ISMINE_SPENDABLE;
        for (const isminetype mine : wtx.txout_is_mine)
        {
            if(fAllToMe > mine) fAllToMe = mine;
        }

        if (fAllFromMe)
        {
            if(fAllFromMe & ISMINE_WATCH_ONLY)
                strHTML += "<b>" + tr("From") + ":</b> " + tr("watch-only") + "<br>";

            //
            // Debit
            //
            auto mine = wtx.txout_is_mine.begin();
            for (const CTxOut& txout : wtx.tx->vout)
            {
                // Ignore change
                isminetype toSelf = *(mine++);
                if ((toSelf == ISMINE_SPENDABLE) && (fAllFromMe == ISMINE_SPENDABLE))
                    continue;
                if (!toSelf && !IsUserVisibleRecipientOutput(txout))
                    continue;

                if (!wtx.value_map.count("to") || wtx.value_map["to"].empty())
                {
                    // Offline transaction
                    CTxDestination address;
                    if (ExtractDestination(txout.scriptPubKey, address))
                    {
                        strHTML += "<b>" + tr("To") + ":</b> ";
                        std::string name;
                        if (wallet.getAddress(
                                address, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty())
                            strHTML += GUIUtil::HtmlEscape(name) + " ";
                        strHTML += GUIUtil::HtmlEscape(EncodeDestination(address));
                        if(toSelf == ISMINE_SPENDABLE)
                            strHTML += " (" + tr("own address") + ")";
                        else if(toSelf & ISMINE_WATCH_ONLY)
                            strHTML += " (" + tr("watch-only") + ")";
                        strHTML += "<br>";
                    }
                }

                strHTML += "<b>" + tr("Debit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, -txout.nValue) + "<br>";
                if(toSelf)
                    strHTML += "<b>" + tr("Credit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, txout.nValue) + "<br>";
            }

            if (fAllToMe)
            {
                // Payment to self / consolidation. Change heuristics can mark every
                // output as change after a history rebuild, so show the selected row
                // or wallet-visible output amount instead of misleading zero totals.
                const CAmount row_amount = rec->credit + rec->debit;
                const CAmount self_amount = row_amount > 0 ? row_amount : nCredit;
                if (self_amount > 0) {
                    strHTML += "<b>" + tr("Amount") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, self_amount) + "<br>";
                }
            }

            CAmount nTxFee = wtx.fee;
            if (nTxFee > 0)
                strHTML += "<b>" + tr("Transaction fee") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, -nTxFee) + "<br>";
        }
        else
        {
            //
            // Mixed debit transaction
            //
            auto mine = wtx.txin_is_mine.begin();
            for (const CTxIn& txin : wtx.tx->vin) {
                if (*(mine++)) {
                    strHTML += "<b>" + tr("Debit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, -wallet.getDebit(txin, ISMINE_ALL)) + "<br>";
                }
            }
            mine = wtx.txout_is_mine.begin();
            for (const CTxOut& txout : wtx.tx->vout) {
                if (*(mine++)) {
                    strHTML += "<b>" + tr("Credit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, wallet.getCredit(txout, ISMINE_ALL)) + "<br>";
                }
            }
        }
    }

    strHTML += "<b>" + tr("Net amount") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, nDisplayNet, true) + "<br>";

    //
    // Message
    //
    if (wtx.value_map.count("message") && !wtx.value_map["message"].empty())
        strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.value_map["message"], true) + "<br>";
    if (wtx.value_map.count("comment") && !wtx.value_map["comment"].empty())
        strHTML += "<br><b>" + tr("Comment") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.value_map["comment"], true) + "<br>";

    strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxHash() + "<br>";
    strHTML += "<b>" + tr("Transaction total size") + ":</b> " + QString::number(wtx.tx->GetTotalSize()) + " bytes<br>";
    strHTML += "<b>" + tr("Transaction virtual size") + ":</b> " + QString::number(GetVirtualTransactionSize(*wtx.tx)) + " bytes<br>";
    strHTML += "<b>" + tr("Output index (vout)") + ":</b> ";
    strHTML += rec->is_multi_recipient ? tr("multiple recipients") : QString::number(rec->getOutputIndex());
    strHTML += "<br>";

    // Message from normal nito:URI (nito:123...?message=example)
    for (const std::pair<std::string, std::string>& r : orderForm) {
        if (r.first == "Message")
            strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(r.second, true) + "<br>";

        //
        // PaymentRequest info:
        //
        if (r.first == "PaymentRequest")
        {
            QString merchant;
            if (!GetPaymentRequestMerchant(r.second, merchant)) {
                merchant.clear();
            } else {
                merchant = tr("%1 (Certificate was not verified)").arg(merchant);
            }
            if (!merchant.isNull()) {
                strHTML += "<b>" + tr("Merchant") + ":</b> " + GUIUtil::HtmlEscape(merchant) + "<br>";
            }
        }
    }

    if (wtx.is_coinbase)
    {
        quint32 numBlocksToMaturity = COINBASE_MATURITY +  1;
        strHTML += "<br>" + tr("Generated coins must mature %1 blocks before they can be spent. When you generated this block, it was broadcast to the network to be added to the block chain. If it fails to get into the chain, its state will change to \"not accepted\" and it won't be spendable. This may occasionally happen if another node generates a block within a few seconds of yours.").arg(QString::number(numBlocksToMaturity)) + "<br>";
    }

    //
    // Debug view
    //
    if (node.getLogCategories() != BCLog::NONE)
    {
        strHTML += "<hr><br>" + tr("Debug information") + "<br><br>";
        for (const CTxIn& txin : wtx.tx->vin)
            if(wallet.txinIsMine(txin))
                strHTML += "<b>" + tr("Debit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, -wallet.getDebit(txin, ISMINE_ALL)) + "<br>";
        for (const CTxOut& txout : wtx.tx->vout)
            if(wallet.txoutIsMine(txout))
                strHTML += "<b>" + tr("Credit") + ":</b> " + NitoUnits::formatHtmlWithUnit(unit, wallet.getCredit(txout, ISMINE_ALL)) + "<br>";

        strHTML += "<br><b>" + tr("Transaction") + ":</b><br>";
        strHTML += GUIUtil::HtmlEscape(wtx.tx->ToString(), true);

        strHTML += "<br><b>" + tr("Inputs") + ":</b>";
        strHTML += "<ul>";

        for (const CTxIn& txin : wtx.tx->vin)
        {
            COutPoint prevout = txin.prevout;

            if (auto prev{node.getUnspentOutput(prevout)}) {
                {
                    strHTML += "<li>";
                    const CTxOut& vout = prev->out;
                    CTxDestination address;
                    if (ExtractDestination(vout.scriptPubKey, address))
                    {
                        std::string name;
                        if (wallet.getAddress(address, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty())
                            strHTML += GUIUtil::HtmlEscape(name) + " ";
                        strHTML += QString::fromStdString(EncodeDestination(address));
                    }
                    strHTML = strHTML + " " + tr("Amount") + "=" + NitoUnits::formatHtmlWithUnit(unit, vout.nValue);
                    strHTML = strHTML + " IsMine=" + (wallet.txoutIsMine(vout) & ISMINE_SPENDABLE ? tr("true") : tr("false")) + "</li>";
                    strHTML = strHTML + " IsWatchOnly=" + (wallet.txoutIsMine(vout) & ISMINE_WATCH_ONLY ? tr("true") : tr("false")) + "</li>";
                }
            }
        }

        strHTML += "</ul>";
    }

    strHTML += "</font></html>";
    return strHTML;
}
