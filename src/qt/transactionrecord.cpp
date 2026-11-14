// Copyright (c) 2011-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactionrecord.h>

#include <chain.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <wallet/types.h>

#include <stdint.h>

#include <algorithm>
#include <limits>

#include <QDateTime>

using wallet::ISMINE_NO;
using wallet::ISMINE_SPENDABLE;
using wallet::ISMINE_WATCH_ONLY;
using wallet::isminetype;

namespace {
constexpr const char* AVAILABLE_BALANCE_CURRENT_TX_KEY{"nito_available_balance_current"};

bool IsUserVisibleRecipientOutput(const CTxOut& txout)
{
    return txout.nValue > 0 && !txout.scriptPubKey.IsUnspendable();
}
} // namespace

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction()
{
    // There are currently no cases where we hide transactions, but
    // we may want to use this in the future for things like RBF.
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const interfaces::WalletTx& wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.time;
    CAmount nCredit = wtx.credit;
    CAmount nDebit = wtx.debit;
    CAmount nNet = nCredit - nDebit;
    uint256 hash = wtx.tx->GetHash();
    std::map<std::string, std::string> mapValue = wtx.value_map;

    bool involvesWatchAddress = false;
    isminetype fAllFromMe = ISMINE_SPENDABLE;
    bool any_from_me = false;
    if (wtx.is_coinbase) {
        fAllFromMe = ISMINE_NO;
    } else if (wtx.txin_is_mine.empty()) {
        fAllFromMe = ISMINE_NO;
    } else {
        for (const isminetype mine : wtx.txin_is_mine)
        {
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
            if(fAllFromMe > mine) fAllFromMe = mine;
            if (mine) any_from_me = true;
        }
    }

    if (mapValue.count(AVAILABLE_BALANCE_CURRENT_TX_KEY) != 0) {
        for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
            const CTxOut& txout = wtx.tx->vout[i];
            const isminetype mine = wtx.txout_is_mine[i];
            if (!(mine & (ISMINE_SPENDABLE | ISMINE_WATCH_ONLY)) || !IsUserVisibleRecipientOutput(txout)) continue;

            TransactionRecord sub(hash, nTime);
            sub.idx = i;
            sub.credit = txout.nValue;
            sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
            if (!std::get_if<CNoDestination>(&wtx.txout_address[i])) {
                sub.type = TransactionRecord::RecvWithAddress;
                sub.address = EncodeDestination(wtx.txout_address[i]);
            } else {
                sub.type = TransactionRecord::RecvFromOther;
                sub.address = mapValue["from"];
            }
            if (wtx.is_coinbase) {
                sub.type = TransactionRecord::Generated;
            }
            parts.append(sub);
        }
        if (!parts.empty()) {
            return parts;
        }
    }

    if (wtx.has_private_bundle) {
        const std::string private_label = "bech32x";
        const bool transparent_from_me = nDebit > 0;
        const bool private_from_me = wtx.private_debit > 0;
        const bool shield_from_transparent = transparent_from_me && wtx.private_value_balance < 0;
        const bool unshield_to_transparent = private_from_me && !transparent_from_me && wtx.private_value_balance > 0 && !wtx.tx->vout.empty();
        const CAmount private_receive_credit = wtx.private_external_credit;
        const CAmount private_change_credit = wtx.private_internal_credit;

        CAmount public_sent{0};
        CAmount public_received{0};
        std::string public_address;
        bool has_external_public_output{false};
        for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
            if (!wtx.txout_is_change[i] && IsUserVisibleRecipientOutput(wtx.tx->vout[i])) {
                public_sent += wtx.tx->vout[i].nValue;
                if (!wtx.txout_is_mine[i]) {
                    has_external_public_output = true;
                }
            }
            if (wtx.txout_is_mine[i]) {
                public_received += wtx.tx->vout[i].nValue;
                if (public_address.empty() && !std::get_if<CNoDestination>(&wtx.txout_address[i])) {
                    public_address = EncodeDestination(wtx.txout_address[i]);
                }
            }
            if (public_address.empty() && !std::get_if<CNoDestination>(&wtx.txout_address[i])) {
                public_address = EncodeDestination(wtx.txout_address[i]);
            }
        }

        const CAmount private_sent = private_from_me ? wtx.private_debit - private_change_credit - wtx.fee - public_sent : 0;
        const bool mixed_payment = private_sent > 0 && public_sent > 0;
        if (unshield_to_transparent && public_received > 0 && !has_external_public_output && !mixed_payment && private_receive_credit == 0) {
            TransactionRecord sub(hash, nTime);
            sub.involvesWatchAddress = involvesWatchAddress;
            sub.is_private = true;
            sub.type = TransactionRecord::PrivateUnshield;
            sub.address = public_address.empty() ? private_label : public_address;
            sub.debit = -public_received;
            sub.credit = public_received;
            parts.append(sub);
            return parts;
        }

        if (private_from_me || shield_from_transparent) {
            CAmount private_debit{0};
            if (private_from_me) {
                private_debit = wtx.private_debit - private_change_credit - wtx.fee;
            } else {
                private_debit = -wtx.private_value_balance;
            }
            if (private_debit > 0) {
                TransactionRecord sub(hash, nTime);
                sub.involvesWatchAddress = involvesWatchAddress;
                sub.is_private = true;
                if (private_from_me && !mixed_payment && private_receive_credit == 0 && public_sent > 0 && !public_address.empty()) {
                    sub.type = TransactionRecord::PrivateUnshield;
                    sub.address = public_address;
                } else {
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = private_label;
                }
                sub.debit = -private_debit;
                sub.is_multi_recipient = mixed_payment;
                parts.append(sub);
            }
        }
        if (private_receive_credit > 0) {
            TransactionRecord sub(hash, nTime);
            sub.involvesWatchAddress = involvesWatchAddress;
            sub.is_private = true;
            sub.type = TransactionRecord::RecvFromOther;
            sub.address = private_label;
            sub.credit = private_receive_credit;
            parts.append(sub);
        }
        if (!parts.empty() && public_sent == 0) {
            return parts;
        }
    }

    if (fAllFromMe || !any_from_me) {
        for (const isminetype mine : wtx.txout_is_mine)
        {
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
        }

        CAmount nTxFee = wtx.fee;

        if (fAllFromMe && parts.empty() && nDebit > 0 && nCredit > 0) {
            bool has_external_value_output{false};
            CAmount internal_credit{0};
            int internal_output_index{0};
            int internal_output_count{0};
            std::string internal_output_address;
            for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
                const CTxOut& txout = wtx.tx->vout[i];
                const isminetype mine = wtx.txout_is_mine[i];
                if (mine) {
                    internal_credit += txout.nValue;
                    if (IsUserVisibleRecipientOutput(txout)) {
                        ++internal_output_count;
                    }
                    if (internal_output_address.empty() && !std::get_if<CNoDestination>(&wtx.txout_address[i])) {
                        internal_output_index = i;
                        internal_output_address = EncodeDestination(wtx.txout_address[i]);
                    }
                } else if (IsUserVisibleRecipientOutput(txout)) {
                    has_external_value_output = true;
                }
            }
            if (!has_external_value_output && internal_credit > 0) {
                TransactionRecord sub(hash, nTime);
                sub.idx = internal_output_index;
                sub.type = TransactionRecord::InternalTransfer;
                sub.address = internal_output_address;
                sub.credit = internal_credit;
                sub.involvesWatchAddress = involvesWatchAddress;
                sub.is_multi_recipient = internal_output_count > 1;
                parts.append(sub);
                return parts;
            }
        }

        if (fAllFromMe && parts.empty()) {
            CAmount recipient_total{0};
            int recipient_outputs{0};
            int first_recipient_index{0};

            for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
                if (wtx.txout_is_change[i] ||
                    (wtx.txout_is_mine[i] & ISMINE_SPENDABLE) ||
                    !IsUserVisibleRecipientOutput(wtx.tx->vout[i])) {
                    continue;
                }
                if (recipient_outputs == 0) {
                    first_recipient_index = i;
                }
                recipient_total += wtx.tx->vout[i].nValue;
                ++recipient_outputs;
            }

            if (recipient_outputs > 1) {
                TransactionRecord sub(hash, nTime);
                sub.idx = first_recipient_index;
                sub.involvesWatchAddress = involvesWatchAddress;
                sub.type = TransactionRecord::SendToOther;
                sub.is_multi_recipient = true;
                sub.debit = -(recipient_total + nTxFee);
                parts.append(sub);
                return parts;
            }
        }

        for(unsigned int i = 0; i < wtx.tx->vout.size(); i++)
        {
            const CTxOut& txout = wtx.tx->vout[i];
            const isminetype mine = wtx.txout_is_mine[i];

            if (fAllFromMe) {
                // Change is only really possible if we're the sender
                // Otherwise, someone just sent NITO to a change address, which should be shown
                if (wtx.txout_is_change[i] ||
                    (mine & ISMINE_SPENDABLE) ||
                    !IsUserVisibleRecipientOutput(txout)) {
                    continue;
                }

                //
                // Debit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i;
                sub.involvesWatchAddress = involvesWatchAddress;

                if (!std::get_if<CNoDestination>(&wtx.txout_address[i]))
                {
                    // Sent to Nito Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                CAmount nValue = txout.nValue;
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }

            if(mine)
            {
                //
                // Credit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i; // vout index
                sub.credit = txout.nValue;
                sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
                if (wtx.txout_address_is_mine[i])
                {
                    // Received by Nito Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.is_coinbase)
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }

                parts.append(sub);
            }
        }

        if (fAllFromMe && parts.empty() && nTxFee > 0) {
            TransactionRecord sub(hash, nTime);
            sub.idx = 0;
            sub.involvesWatchAddress = involvesWatchAddress;
            sub.type = TransactionRecord::SendToOther;
            sub.address = mapValue["to"];
            sub.debit = -nTxFee;
            parts.append(sub);
        }
    } else {
        //
        // Mixed debit transaction, can't break down payees
        //
        parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
        parts.last().involvesWatchAddress = involvesWatchAddress;
    }

    return parts;
}

TransactionRecord TransactionRecord::decomposePrivateNote(const interfaces::WalletPrivateNote& note)
{
    TransactionRecord sub(note.txid, note.time, TransactionRecord::RecvFromOther, "bech32x", 0, note.amount);
    sub.idx = static_cast<int>(note.action_index);
    sub.is_private = true;
    sub.is_private_note_only = true;
    sub.private_note_cmx = note.cmx;

    interfaces::WalletTxStatus status{};
    status.block_height = note.block_height >= 0 ? note.block_height : std::numeric_limits<int>::max();
    status.blocks_to_maturity = 0;
    status.depth_in_main_chain = note.depth_in_main_chain;
    status.time_received =
        note.time > 0 && note.time <= std::numeric_limits<unsigned int>::max()
            ? static_cast<unsigned int>(note.time)
            : 0;
    status.lock_time = 0;
    status.is_trusted = note.spendable && note.depth_in_main_chain > 0;
    status.is_abandoned = false;
    status.is_coinbase = false;
    status.is_in_main_chain = note.depth_in_main_chain > 0;
    sub.updateStatus(status, note.block_hash, 0, note.time);
    sub.status.needsUpdate = true;
    return sub;
}

void TransactionRecord::updateStatus(const interfaces::WalletTxStatus& wtx, const uint256& block_hash, int numBlocks, int64_t block_time)
{
    // Determine transaction status

    // Sort order, unrecorded transactions sort to the top
    int typesort;
    switch (type) {
    case SendToAddress: case SendToOther: case PrivateUnshield:
        typesort = 2; break;
    case RecvWithAddress: case RecvFromOther:
        typesort = 3; break;
    default:
        typesort = 9;
    }
    status.sortKey = strprintf("%010d-%01d-%010u-%03d-%d",
        wtx.block_height,
        wtx.is_coinbase ? 1 : 0,
        wtx.time_received,
        idx,
        typesort);
    status.countsForBalance = wtx.is_trusted && !(wtx.blocks_to_maturity > 0);
    status.depth = wtx.depth_in_main_chain;
    status.m_cur_block_hash = block_hash;

    // For generated transactions, determine maturity
    if (type == TransactionRecord::Generated) {
        if (wtx.blocks_to_maturity > 0)
        {
            status.status = TransactionStatus::Immature;

            if (wtx.is_in_main_chain)
            {
                status.matures_in = wtx.blocks_to_maturity;
            }
            else
            {
                status.status = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    else
    {
        if (status.depth < 0)
        {
            status.status = TransactionStatus::Conflicted;
        }
        else if (status.depth == 0)
        {
            status.status = TransactionStatus::Unconfirmed;
            if (wtx.is_abandoned)
                status.status = TransactionStatus::Abandoned;
        }
        else if (status.depth < RecommendedNumConfirmations)
        {
            status.status = TransactionStatus::Confirming;
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    status.needsUpdate = false;
}

bool TransactionRecord::statusUpdateNeeded(const uint256& block_hash) const
{
    assert(!block_hash.IsNull());
    return status.m_cur_block_hash != block_hash || status.needsUpdate;
}

QString TransactionRecord::getTxHash() const
{
    return QString::fromStdString(hash.ToString());
}

int TransactionRecord::getOutputIndex() const
{
    return idx;
}
