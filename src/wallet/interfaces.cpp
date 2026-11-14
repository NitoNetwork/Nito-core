// Copyright (c) 2018-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>

#include <common/args.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <key_io.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <scheduler.h>
#include <support/allocators/secure.h>
#include <support/cleanse.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/translation.h>
#include <util/ui_change_type.h>
#include <wallet/coincontrol.h>
#include <wallet/bip39.h>
#include <wallet/context.h>
#include <wallet/feebumper.h>
#include <wallet/fees.h>
#include <wallet/types.h>
#include <wallet/load.h>
#include <wallet/private_wallet.h>
#include <wallet/receive.h>
#include <wallet/rpc/wallet.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <chainparams.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using interfaces::Chain;
using interfaces::FoundBlock;
using interfaces::Handler;
using interfaces::MakeSignalHandler;
using interfaces::Wallet;
using interfaces::WalletAddress;
using interfaces::WalletBalances;
using interfaces::WalletPrivateNote;
using interfaces::WalletLoader;
using interfaces::WalletMigrationResult;
using interfaces::WalletOrderForm;
using interfaces::WalletTx;
using interfaces::WalletTxOut;
using interfaces::WalletTxStatus;
using interfaces::WalletValueMap;

namespace wallet {
// All members of the classes in this namespace are intentionally public, as the
// classes themselves are private.
namespace {
void ClearSecureString(SecureString& value)
{
    if (!value.empty()) memory_cleanse(value.data(), value.size());
    SecureString empty;
    value.swap(empty);
}

struct SecureStringCleanup {
    SecureString& value;
    ~SecureStringCleanup() { ClearSecureString(value); }
};

const bilingual_str& WalletSyncPendingMessage()
{
    static const bilingual_str WALLET_SYNC_PENDING_MESSAGE{
        _("The displayed information may be out of date. Your wallet automatically synchronizes with the Nito network after a connection is established, but this process has not completed yet.")};
    return WALLET_SYNC_PENDING_MESSAGE;
}

static bool PrivateNoteTxIsActive(const CWallet& wallet, const CPrivateWalletNote& note) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const auto it = wallet.mapWallet.find(note.txid);
    if (it != wallet.mapWallet.end()) {
        const CWalletTx& wtx = it->second;
        if (wtx.state<TxStateInMempool>()) return true;

        const auto* confirmed = wtx.state<TxStateConfirmed>();
        if (confirmed == nullptr) return false;
        if (confirmed->confirmed_block_hash != note.block_hash || confirmed->confirmed_block_height != note.block_height) return false;
    }

    if (!note.IsConfirmed()) return false;
    if (!wallet.HaveChain()) return false;

    bool active{false};
    int height{-1};
    return wallet.chain().findBlock(note.block_hash, FoundBlock().inActiveChain(active).height(height)) &&
           active && height == note.block_height;
}

static int GetPrivateNoteDepthForBalance(const CWallet& wallet, const CPrivateWalletNote& note) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (!note.IsConfirmed()) return 0;
    if (!PrivateNoteTxIsActive(wallet, note)) return 0;

    const int depth = wallet.GetLastBlockHeight() - note.block_height + 1;
    return std::max(depth, 0);
}

static bool CanExposePrivateWalletData(const CWallet& wallet, bool display_authorized = false) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    return (!wallet.IsLocked() || display_authorized) &&
        wallet.CanViewPrivateData() &&
        !wallet.IsAvailableBalanceSyncPending() &&
        wallet.HasLastBlockProcessed() &&
        Consensus::PrivateTxActive(Params().GetConsensus(), wallet.GetLastBlockHeight()) &&
        wallet.HaveChain() &&
        wallet.chain().hasOrchardIndex();
}

static void FillPrivateBalances(CWallet& wallet, WalletBalances& result, bool display_authorized = false) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (!CanExposePrivateWalletData(wallet, display_authorized)) return;

    wallet.RefreshPrivateCommitmentIndexes();
    for (const auto& [cmx, note] : wallet.mapPrivateNotes) {
        if (note.spent || note.value <= 0) continue;
        if (!PrivateNoteTxIsActive(wallet, note)) continue;
        result.private_total_unspent += note.value;
        // Activity was already checked above; do not look up the block twice.
        if (note.IsConfirmed() && wallet.GetLastBlockHeight() >= note.block_height && note.IsSpendable()) {
            result.private_balance += note.value;
        } else {
            result.unconfirmed_private_balance += note.value;
        }
    }
}

static int64_t GetWalletTxDisplayTime(const CWallet& wallet, const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::optional<uint256> block_hash;
    if (const auto* confirmed = wtx.state<TxStateConfirmed>()) {
        block_hash = confirmed->confirmed_block_hash;
    } else if (const auto* conflicted = wtx.state<TxStateConflicted>()) {
        block_hash = conflicted->conflicting_block_hash;
    }

    if (block_hash) {
        int64_t block_time{0};
        if (wallet.chain().findBlock(*block_hash, FoundBlock().time(block_time))) {
            if (wtx.nTimeReceived > 0 && wtx.nTimeReceived <= block_time + 300) {
                return wtx.nTimeReceived;
            }
        }
    } else if (wtx.nTimeReceived > 0) {
        return wtx.nTimeReceived;
    }
    return wtx.GetTxTime();
}

static int64_t GetPrivateNoteDisplayTime(const CWallet& wallet, const CPrivateWalletNote& note) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (const auto tx = wallet.mapWallet.find(note.txid); tx != wallet.mapWallet.end()) {
        return GetWalletTxDisplayTime(wallet, tx->second);
    }

    if (note.IsConfirmed() && wallet.HaveChain()) {
        int64_t block_time{0};
        if (wallet.chain().findBlock(note.block_hash, FoundBlock().time(block_time))) {
            return block_time;
        }
    }

    return 0;
}

//! Construct wallet tx struct.
WalletTx MakeWalletTx(CWallet& wallet, const CWalletTx& wtx, bool display_authorized = false)
{
    LOCK(wallet.cs_wallet);
    WalletTx result;
    result.tx = wtx.tx;
    result.txin_is_mine.reserve(wtx.tx->vin.size());
    for (const auto& txin : wtx.tx->vin) {
        result.txin_is_mine.emplace_back(InputIsMine(wallet, txin));
    }
    if (!wtx.IsCoinBase() && !wtx.tx->HasPrivateBundle() && !wtx.tx->vin.empty()) {
        result.txin_addresses_complete = wtx.m_input_addresses.size() == wtx.tx->vin.size();
        std::set<CTxDestination> seen;
        for (const auto& [index, encoded] : wtx.m_input_addresses) {
            const CTxDestination destination = DecodeDestination(encoded);
            if (index >= wtx.tx->vin.size() || !IsValidDestination(destination)) {
                result.txin_addresses_complete = false;
            } else if (seen.insert(destination).second) {
                result.txin_addresses.push_back(destination);
            }
        }
    }
    result.txout_is_mine.reserve(wtx.tx->vout.size());
    result.txout_address.reserve(wtx.tx->vout.size());
    result.txout_address_is_mine.reserve(wtx.tx->vout.size());
    for (const auto& txout : wtx.tx->vout) {
        result.txout_is_mine.emplace_back(wallet.IsMine(txout));
        result.txout_is_change.push_back(OutputIsChange(wallet, txout));
        result.txout_address.emplace_back();
        result.txout_address_is_mine.emplace_back(ExtractDestination(txout.scriptPubKey, result.txout_address.back()) ?
                                                      wallet.IsMine(result.txout_address.back()) :
                                                      ISMINE_NO);
    }
    result.credit = CachedTxGetCredit(wallet, wtx, ISMINE_ALL);
    result.debit = CachedTxGetDebit(wallet, wtx, ISMINE_ALL);
    result.change = CachedTxGetChange(wallet, wtx);
    result.fee = CachedTxGetFee(wallet, wtx, ISMINE_ALL);
    if (CanExposePrivateWalletData(wallet, display_authorized)) {
        result.private_credit = CachedTxGetPrivateCredit(wallet, wtx);
        result.private_external_credit = CachedTxGetPrivateExternalCredit(wallet, wtx);
        result.private_internal_credit = CachedTxGetPrivateInternalCredit(wallet, wtx);
        result.private_debit = CachedTxGetPrivateDebit(wallet, wtx);
        result.private_value_balance = CachedTxGetPrivateValueBalance(wtx);
        result.has_private_bundle = wtx.tx->HasPrivateBundle();
    }
    result.time = GetWalletTxDisplayTime(wallet, wtx);
    result.value_map = wtx.mapValue;
    result.is_coinbase = wtx.IsCoinBase();
    return result;
}

//! Construct wallet tx status struct.
WalletTxStatus MakeWalletTxStatus(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    WalletTxStatus result;
    result.block_height =
        wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height :
        wtx.state<TxStateConflicted>() ? wtx.state<TxStateConflicted>()->conflicting_block_height :
        std::numeric_limits<int>::max();
    result.blocks_to_maturity = wallet.GetTxBlocksToMaturity(wtx);
    result.depth_in_main_chain = wallet.GetTxDepthInMainChain(wtx);
    result.time_received = wtx.nTimeReceived;
    result.lock_time = wtx.tx->nLockTime;
    result.is_trusted = CachedTxIsTrusted(wallet, wtx);
    result.is_abandoned = wtx.isAbandoned();
    result.is_coinbase = wtx.IsCoinBase();
    result.is_in_main_chain = wallet.IsTxInMainChain(wtx);
    return result;
}

WalletTxStatus MakePrivateNoteStatus(const CWallet& wallet, const CPrivateWalletNote& note)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    WalletTxStatus result;
    result.block_height = note.block_height >= 0 ? note.block_height : std::numeric_limits<int>::max();
    result.blocks_to_maturity = 0;
    result.depth_in_main_chain = GetPrivateNoteDepthForBalance(wallet, note);
    const int64_t display_time{GetPrivateNoteDisplayTime(wallet, note)};
    result.time_received =
        display_time > 0 && display_time <= std::numeric_limits<unsigned int>::max()
            ? static_cast<unsigned int>(display_time)
            : 0;
    result.lock_time = 0;
    result.is_trusted = note.IsSpendable() && result.depth_in_main_chain > 0;
    result.is_abandoned = false;
    result.is_coinbase = false;
    result.is_in_main_chain = result.depth_in_main_chain > 0;
    return result;
}

//! Construct wallet TxOut struct.
WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const CWalletTx& wtx,
    int n,
    int depth) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = wtx.tx->vout[n];
    result.time = wtx.GetTxTime();
    result.depth_in_main_chain = depth;
    result.is_spent = wallet.IsSpent(COutPoint(wtx.GetHash(), n));
    return result;
}

WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const COutput& output) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = output.txout;
    result.time = output.time;
    result.depth_in_main_chain = output.depth;
    result.is_spent = wallet.IsSpent(output.outpoint);
    return result;
}

class WalletImpl : public Wallet
{
public:
    explicit WalletImpl(WalletContext& context, const std::shared_ptr<CWallet>& wallet) : m_context(context), m_wallet(wallet) {}

    bool encryptWallet(const SecureString& wallet_passphrase) override
    {
        return m_wallet->EncryptWallet(wallet_passphrase);
    }
    bool isCrypted() override { return m_wallet->IsCrypted(); }
    bool lock() override { return m_wallet->Lock(); }
    bool lockForDisplay() override { return m_wallet->LockForDisplay(); }
    bool unlock(const SecureString& wallet_passphrase, bilingual_str* error) override
    {
        if (!m_wallet->Unlock(wallet_passphrase, error)) return false;
        if (auto catchup = m_wallet->CatchUpWalletAfterUnlock(); !catchup) {
            m_wallet->WalletLogPrintf("Wallet recovery after unlock remains pending: %s\n", util::ErrorString(catchup).original);
        }
        return true;
    }
    bool isLocked() override { return m_wallet->IsLocked(); }
    bool canViewPrivateData() override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->CanViewPrivateData();
    }
    bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
        const SecureString& new_wallet_passphrase) override
    {
        return m_wallet->ChangeWalletPassphrase(old_wallet_passphrase, new_wallet_passphrase);
    }
    void abortRescan() override { m_wallet->AbortRescan(); }
    bool backupWallet(const std::string& filename) override { return m_wallet->BackupWallet(filename); }
    std::string getWalletName() override { return m_wallet->GetName(); }
    util::Result<CTxDestination> getNewDestination(const OutputType type, const std::string& label) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetNewDestination(type, label);
    }
    util::Result<std::string> getNewPrivateAddress(bool internal) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetNewPrivateAddress(internal);
    }
    util::Result<std::string> getHDSeedMnemonic() override
    {
        LOCK(m_wallet->cs_wallet);

        CKey hd_seed;
        bilingual_str error;
        if (!m_wallet->GetPrivateHDSeed(hd_seed, error, /*require_exportable_seed=*/true)) {
            return util::Error{error};
        }
        return EncodeBIP39Mnemonic(hd_seed);
    }
    bool isBIP39PassphraseEnabled() override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsBIP39PassphraseEnabled();
    }
    bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) override
    {
        std::unique_ptr<SigningProvider> provider = m_wallet->GetSolvingProvider(script);
        if (provider) {
            return provider->GetPubKey(address, pub_key);
        }
        return false;
    }
    SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) override
    {
        return m_wallet->SignMessage(message, pkhash, str_sig);
    }
    bool isSpendable(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(dest) & ISMINE_SPENDABLE;
    }
    bool haveWatchOnly() override
    {
        auto spk_man = m_wallet->GetLegacyScriptPubKeyMan();
        if (spk_man) {
            return spk_man->HaveWatchOnly();
        }
        return false;
    };
    bool setAddressBook(const CTxDestination& dest, const std::string& name, const std::optional<AddressPurpose>& purpose) override
    {
        return m_wallet->SetAddressBook(dest, name, purpose);
    }
    bool delAddressBook(const CTxDestination& dest) override
    {
        return m_wallet->DelAddressBook(dest);
    }
    bool getAddress(const CTxDestination& dest,
        std::string* name,
        isminetype* is_mine,
        AddressPurpose* purpose) override
    {
        LOCK(m_wallet->cs_wallet);
        const auto& entry = m_wallet->FindAddressBookEntry(dest, /*allow_change=*/false);
        if (!entry) return false; // addr not found
        if (name) {
            *name = entry->GetLabel();
        }
        std::optional<isminetype> dest_is_mine;
        if (is_mine || purpose) {
            dest_is_mine = m_wallet->IsMine(dest);
        }
        if (is_mine) {
            *is_mine = *dest_is_mine;
        }
        if (purpose) {
            // In very old wallets, address purpose may not be recorded so we derive it from IsMine
            *purpose = entry->purpose.value_or(*dest_is_mine ? AddressPurpose::RECEIVE : AddressPurpose::SEND);
        }
        return true;
    }
    std::vector<WalletAddress> getAddresses() override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletAddress> result;
        m_wallet->ForEachAddrBookEntry([&](const CTxDestination& dest, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) EXCLUSIVE_LOCKS_REQUIRED(m_wallet->cs_wallet) {
            if (is_change) return;
            isminetype is_mine = m_wallet->IsMine(dest);
            // In very old wallets, address purpose may not be recorded so we derive it from IsMine
            result.emplace_back(dest, is_mine, purpose.value_or(is_mine ? AddressPurpose::RECEIVE : AddressPurpose::SEND), label);
        });
        return result;
    }
    std::vector<std::string> getAddressReceiveRequests() override {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetAddressReceiveRequests();
    }
    bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& value) override {
        // Note: The setAddressReceiveRequest interface used by the GUI to store
        // receive requests is a little awkward and could be improved in the
        // future:
        //
        // - The same method is used to save requests and erase them, but
        //   having separate methods could be clearer and prevent bugs.
        //
        // - Request ids are passed as strings even though they are generated as
        //   integers.
        //
        // - Multiple requests can be stored for the same address, but it might
        //   be better to only allow one request or only keep the current one.
        LOCK(m_wallet->cs_wallet);
        WalletBatch batch{m_wallet->GetDatabase()};
        return value.empty() ? m_wallet->EraseAddressReceiveRequest(batch, dest, id)
                             : m_wallet->SetAddressReceiveRequest(batch, dest, id, value);
    }
    bool displayAddress(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->DisplayAddress(dest);
    }
    bool lockCoin(const COutPoint& output, const bool write_to_db) override
    {
        LOCK(m_wallet->cs_wallet);
        std::unique_ptr<WalletBatch> batch = write_to_db ? std::make_unique<WalletBatch>(m_wallet->GetDatabase()) : nullptr;
        return m_wallet->LockCoin(output, batch.get());
    }
    bool unlockCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        std::unique_ptr<WalletBatch> batch = std::make_unique<WalletBatch>(m_wallet->GetDatabase());
        return m_wallet->UnlockCoin(output, batch.get());
    }
    bool isLockedCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsLockedCoin(output);
    }
    void listLockedCoins(std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ListLockedCoins(outputs);
    }
    util::Result<CTransactionRef> createTransaction(const std::vector<CRecipient>& recipients,
        const CCoinControl& coin_control,
        bool sign,
        int& change_pos,
        CAmount& fee,
        std::vector<PSBTProprietary>* private_psbt_records) override
    {
        LOCK(m_wallet->cs_wallet);
        if (m_wallet->IsAvailableBalanceSyncPending()) {
            return util::Error{WalletSyncPendingMessage()};
        }
        auto res = CreateTransaction(*m_wallet, recipients, change_pos == -1 ? std::nullopt : std::make_optional(change_pos),
                                     coin_control, sign);
        if (!res) return util::Error{util::ErrorString(res)};
        const auto& txr = *res;
        fee = txr.fee;
        change_pos = txr.change_pos ? *txr.change_pos : -1;
        if (private_psbt_records) {
            *private_psbt_records = txr.private_psbt_records;
        }

        return txr.tx;
    }
    util::Result<void> commitTransaction(CTransactionRef tx,
        WalletValueMap value_map,
        WalletOrderForm order_form,
        const std::vector<CRecipient>* recipients) override
    {
        LOCK(m_wallet->cs_wallet);
        if (tx->m_private_bundle && recipients && !recipients->empty()) {
            CCoinControl control;
            control.m_private_tx_source = tx->vin.empty() ? CCoinControl::PrivateTxSource::PRIVATE_NOTES
                                                         : CCoinControl::PrivateTxSource::TRANSPARENT_COINS;
            std::vector<uint256> spent_notes;
            for (const auto& action : tx->m_private_bundle->effects.actions) {
                const auto it = m_wallet->mapPrivateNoteNullifiers.find(action.nullifier);
                if (it != m_wallet->mapPrivateNoteNullifiers.end()) spent_notes.push_back(it->second);
            }
            // Use the final signed txid, including transactions finalized from a PSBT.
            const auto metadata = feebumper::AddPrivateBumpMetadata(*m_wallet, tx->GetHash(), value_map,
                                                                   control, *recipients, spent_notes);
            if (!metadata) return util::Error{util::ErrorString(metadata)};
        }
        return m_wallet->CommitTransaction(std::move(tx), std::move(value_map), std::move(order_form));
    }
    bool transactionCanBeAbandoned(const uint256& txid) override { return m_wallet->TransactionCanBeAbandoned(txid); }
    bool abandonTransaction(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->AbandonTransaction(txid);
    }
    bool transactionCanBeBumped(const uint256& txid) override
    {
        return feebumper::TransactionCanBeBumped(*m_wallet.get(), txid);
    }
    bool createBumpTransaction(const uint256& txid,
        const CCoinControl& coin_control,
        std::vector<bilingual_str>& errors,
        CAmount& old_fee,
        CAmount& new_fee,
        CMutableTransaction& mtx) override
    {
        std::vector<CTxOut> outputs; // just an empty list of new recipients for now
        return feebumper::CreateRateBumpTransaction(*m_wallet.get(), txid, coin_control, errors, old_fee, new_fee, mtx, /* require_mine= */ true, outputs) == feebumper::Result::OK;
    }
    bool signBumpTransaction(CMutableTransaction& mtx) override { return feebumper::SignTransaction(*m_wallet.get(), mtx); }
    bool commitBumpTransaction(const uint256& txid,
        CMutableTransaction&& mtx,
        std::vector<bilingual_str>& errors,
        uint256& bumped_txid) override
    {
        return feebumper::CommitTransaction(*m_wallet.get(), txid, std::move(mtx), errors, bumped_txid) ==
               feebumper::Result::OK;
    }
    CTransactionRef getTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return mi->second.tx;
        }
        return {};
    }
    WalletTx getWalletTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end() && m_wallet->ShouldShowTransaction(mi->second)) {
            return MakeWalletTx(*m_wallet, mi->second, m_private_data_display_authorized.load());
        }
        return {};
    }
    std::set<WalletTx> getWalletTxs() override
    {
        LOCK(m_wallet->cs_wallet);
        std::set<WalletTx> result;
        for (const auto& entry : m_wallet->mapWallet) {
            if (!m_wallet->ShouldShowTransaction(entry.second)) continue;
            result.emplace(MakeWalletTx(*m_wallet, entry.second, m_private_data_display_authorized.load()));
        }
        return result;
    }
    bool tryGetTxStatus(const uint256& txid,
        interfaces::WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi == m_wallet->mapWallet.end() || !m_wallet->ShouldShowTransaction(mi->second)) {
            return false;
        }
        num_blocks = m_wallet->GetLastBlockHeight();
        block_time = -1;
        CHECK_NONFATAL(m_wallet->chain().findBlock(m_wallet->GetLastBlockHash(), FoundBlock().time(block_time)));
        tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
        return true;
    }
    bool tryGetPrivateNoteStatus(const uint256& cmx,
        interfaces::WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        if (!CanExposePrivateWalletData(*m_wallet, m_private_data_display_authorized.load())) {
            return false;
        }
        m_wallet->RefreshPrivateCommitmentIndexes();
        auto note_it = m_wallet->mapPrivateNotes.find(cmx);
        if (note_it == m_wallet->mapPrivateNotes.end()) {
            return false;
        }
        const CPrivateWalletNote& note = note_it->second;
        if (!PrivateNoteTxIsActive(*m_wallet, note)) {
            return false;
        }
        num_blocks = m_wallet->GetLastBlockHeight();
        block_time = -1;
        CHECK_NONFATAL(m_wallet->chain().findBlock(m_wallet->GetLastBlockHash(), FoundBlock().time(block_time)));
        tx_status = MakePrivateNoteStatus(*m_wallet, note);
        return true;
    }
    WalletTx getWalletTxDetails(const uint256& txid,
        WalletTxStatus& tx_status,
        WalletOrderForm& order_form,
        bool& in_mempool,
        int& num_blocks) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end() && m_wallet->ShouldShowTransaction(mi->second)) {
            num_blocks = m_wallet->GetLastBlockHeight();
            in_mempool = mi->second.InMempool();
            order_form = mi->second.vOrderForm;
            tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
            return MakeWalletTx(*m_wallet, mi->second, m_private_data_display_authorized.load());
        }
        return {};
    }
    TransactionError fillPSBT(int sighash_type,
        bool sign,
        bool bip32derivs,
        size_t* n_signed,
        PartiallySignedTransaction& psbtx,
        bool& complete,
        std::optional<uint256> private_intent_hash) override
    {
        return m_wallet->FillPSBT(psbtx, complete, sighash_type, sign, bip32derivs, n_signed, /*finalize=*/true, private_intent_hash);
    }
    WalletBalances getBalances() override
    {
        LOCK(m_wallet->cs_wallet);
        const auto bal = GetBalance(*m_wallet);
        WalletBalances result;
        result.available_balance_sync_pending = m_wallet->IsAvailableBalanceSyncPending();
        result.balance = bal.m_mine_trusted;
        result.unconfirmed_balance = bal.m_mine_untrusted_pending;
        result.immature_balance = bal.m_mine_immature;
        FillPrivateBalances(*m_wallet, result, m_private_data_display_authorized.load());
        result.have_watch_only = haveWatchOnly();
        if (result.have_watch_only) {
            result.watch_only_balance = bal.m_watchonly_trusted;
            result.unconfirmed_watch_only_balance = bal.m_watchonly_untrusted_pending;
            result.immature_watch_only_balance = bal.m_watchonly_immature;
        }
        return result;
    }
    bool tryGetBalances(WalletBalances& balances, uint256& block_hash) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        block_hash = m_wallet->GetLastBlockHash();
        balances = getBalances();
        return true;
    }
    void setPrivateDataDisplayAuthorized(bool authorized) override
    {
        m_private_data_display_authorized.store(authorized);
    }
    CAmount getBalance() override
    {
        LOCK(m_wallet->cs_wallet);
        return GetBalance(*m_wallet).m_mine_trusted;
    }
    CAmount getAvailableBalance(const CCoinControl& coin_control) override
    {
        LOCK(m_wallet->cs_wallet);
        if (m_wallet->IsAvailableBalanceSyncPending()) return 0;
        if (coin_control.m_private_tx_source == CCoinControl::PrivateTxSource::PRIVATE_NOTES) {
            if (!CanExposePrivateWalletData(*m_wallet, m_private_data_display_authorized.load())) return 0;
            if (coin_control.HasSelectedPrivateNotes()) {
                m_wallet->RefreshPrivateCommitmentIndexes();
                CAmount total_amount{0};
                for (const uint256& cmx : coin_control.ListSelectedPrivateNotes()) {
                    const auto it = m_wallet->mapPrivateNotes.find(cmx);
                    if (it == m_wallet->mapPrivateNotes.end()) continue;
                    const CPrivateWalletNote& note = it->second;
                    if (!note.IsSpendable() || GetPrivateNoteDepthForBalance(*m_wallet, note) <= 0) continue;
                    if (!MoneyAddSigned(total_amount, note.value, total_amount)) {
                        return 0;
                    }
                }
                return total_amount;
            }
            WalletBalances balances;
            FillPrivateBalances(*m_wallet, balances, m_private_data_display_authorized.load());
            return balances.private_balance;
        }

        CAmount total_amount = 0;
        // Fetch selected coins total amount
        if (coin_control.HasSelected()) {
            FastRandomContext rng{};
            CoinSelectionParams params(rng);
            // Note: for now, swallow any error.
            if (auto res = FetchSelectedInputs(*m_wallet, coin_control, params)) {
                total_amount += res->total_amount;
            }
        }

        // And fetch the wallet available coins
        if (coin_control.m_allow_other_inputs) {
            total_amount += AvailableCoins(*m_wallet, &coin_control).GetTotalAmount();
        }

        return total_amount;
    }
    isminetype txinIsMine(const CTxIn& txin) override
    {
        LOCK(m_wallet->cs_wallet);
        return InputIsMine(*m_wallet, txin);
    }
    isminetype txoutIsMine(const CTxOut& txout) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(txout);
    }
    CAmount getDebit(const CTxIn& txin, isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetDebit(txin, filter);
    }
    CAmount getCredit(const CTxOut& txout, isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return OutputGetCredit(*m_wallet, txout, filter);
    }
    CoinsList listCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        CoinsList result;
        for (const auto& entry : ListCoins(*m_wallet)) {
            auto& group = result[entry.first];
            for (const auto& coin : entry.second) {
                group.emplace_back(coin.outpoint,
                    MakeWalletTxOut(*m_wallet, coin));
            }
        }
        return result;
    }

    std::vector<WalletPrivateNote> listPrivateCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        if (!CanExposePrivateWalletData(*m_wallet, m_private_data_display_authorized.load())) return {};

        m_wallet->RefreshPrivateCommitmentIndexes();
        std::vector<WalletPrivateNote> result;
        result.reserve(m_wallet->mapPrivateNotes.size());
        for (const auto& [cmx, note] : m_wallet->mapPrivateNotes) {
            if (note.spent || note.value <= 0) continue;
            if (!PrivateNoteTxIsActive(*m_wallet, note)) continue;

            WalletPrivateNote out;
            out.cmx = note.cmx;
            out.txid = note.txid;
            out.block_hash = note.block_hash;
            out.amount = note.value;
            out.block_height = note.block_height;
            out.depth_in_main_chain = GetPrivateNoteDepthForBalance(*m_wallet, note);
            out.account = note.account;
            out.internal = note.internal;
            out.diversifier_index = note.diversifier_index;
            out.action_index = note.action_index;
            out.spendable = out.depth_in_main_chain > 0 && note.IsSpendable();
            out.time = GetPrivateNoteDisplayTime(*m_wallet, note);

            if (note.recipient_raw.size() == NITO_ORCHARD_RAW_ADDRESS_SIZE) {
                std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> raw{};
                std::copy(note.recipient_raw.begin(), note.recipient_raw.end(), raw.begin());
                out.address = EncodeNitoPrivateAddress(raw, Params());
            }

            result.push_back(std::move(out));
        }
        return result;
    }

    std::vector<WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletTxOut> result;
        result.reserve(outputs.size());
        for (const auto& output : outputs) {
            result.emplace_back();
            auto it = m_wallet->mapWallet.find(output.hash);
            if (it != m_wallet->mapWallet.end()) {
                int depth = m_wallet->GetTxDepthInMainChain(it->second);
                if (depth >= 0) {
                    result.back() = MakeWalletTxOut(*m_wallet, it->second, output.n, depth);
                }
            }
        }
        return result;
    }
    CAmount getRequiredFee(unsigned int tx_bytes) override { return GetRequiredFee(*m_wallet, tx_bytes); }
    CAmount getMinimumFee(unsigned int tx_bytes,
        const CCoinControl& coin_control,
        int* returned_target,
        FeeReason* reason) override
    {
        FeeCalculation fee_calc;
        CAmount result;
        result = GetMinimumFee(*m_wallet, tx_bytes, coin_control, &fee_calc);
        if (returned_target) *returned_target = fee_calc.returnedTarget;
        if (reason) *reason = fee_calc.reason;
        return result;
    }
    unsigned int getConfirmTarget() override { return m_wallet->m_confirm_target; }
    bool hdEnabled() override { return m_wallet->IsHDEnabled(); }
    bool canGetAddresses() override { return m_wallet->CanGetAddresses(); }
    bool hasExternalSigner() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER); }
    bool privateKeysDisabled() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS); }
    bool taprootEnabled() override {
        if (m_wallet->IsLegacy()) return false;
        auto spk_man = m_wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/false);
        return spk_man != nullptr;
    }
    OutputType getDefaultAddressType() override { return m_wallet->m_default_address_type; }
    CAmount getDefaultMaxTxFee() override { return m_wallet->m_default_max_tx_fee; }
    void remove() override
    {
        RemoveWallet(m_context, m_wallet, /*load_on_start=*/false);
    }
    bool isLegacy() override { return m_wallet->IsLegacy(); }
    std::unique_ptr<Handler> handleUnload(UnloadFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyUnload.connect(fn));
    }
    std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) override
    {
        return MakeSignalHandler(m_wallet->ShowProgress.connect(fn));
    }
    std::unique_ptr<Handler> handleStatusChanged(StatusChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyStatusChanged.connect([fn](CWallet*) { fn(); }));
    }
    std::unique_ptr<Handler> handleAddressBookChanged(AddressBookChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyAddressBookChanged.connect(
            [fn](const CTxDestination& address, const std::string& label, bool is_mine,
                 AddressPurpose purpose, ChangeType status) { fn(address, label, is_mine, purpose, status); }));
    }
    std::unique_ptr<Handler> handleTransactionChanged(TransactionChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyTransactionChanged.connect(
            [fn](const uint256& txid, ChangeType status) { fn(txid, status); }));
    }
    std::unique_ptr<Handler> handleWatchOnlyChanged(WatchOnlyChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyWatchonlyChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyCanGetAddressesChanged.connect(fn));
    }
    CWallet* wallet() override { return m_wallet.get(); }

    WalletContext& m_context;
    std::shared_ptr<CWallet> m_wallet;
    std::atomic<bool> m_private_data_display_authorized{false};
};

class WalletLoaderImpl : public WalletLoader
{
public:
    WalletLoaderImpl(Chain& chain, ArgsManager& args)
    {
        m_context.chain = &chain;
        m_context.args = &args;
    }
    ~WalletLoaderImpl() override { UnloadWallets(m_context); }

    //! ChainClient methods
    void registerRpcs() override
    {
        for (const CRPCCommand& command : GetWalletRPCCommands()) {
            m_rpc_commands.emplace_back(command.category, command.name, [this, &command](const JSONRPCRequest& request, UniValue& result, bool last_handler) {
                JSONRPCRequest wallet_request = request;
                wallet_request.context = &m_context;
                return command.actor(wallet_request, result, last_handler);
            }, command.argNames, command.unique_id);
            m_rpc_handlers.emplace_back(m_context.chain->handleRpc(m_rpc_commands.back()));
        }
    }
    bool verify() override { return VerifyWallets(m_context); }
    bool load() override { return LoadWallets(m_context); }
    void start(CScheduler& scheduler) override
    {
        m_context.scheduler = &scheduler;
        return StartWallets(m_context);
    }
    void flush() override { return FlushWallets(m_context); }
    void stop() override { return StopWallets(m_context); }
    void setMockTime(int64_t time) override { return SetMockTime(time); }
    void schedulerMockForward(std::chrono::seconds delta) override { Assert(m_context.scheduler)->MockForward(delta); }

    //! WalletLoader methods
    util::Result<std::unique_ptr<Wallet>> createWallet(const std::string& name,
                                                       const SecureString& wallet_passphrase,
                                                       SecureString bip39_passphrase,
                                                       uint64_t wallet_creation_flags,
                                                       std::vector<bilingual_str>& warnings) override
    {
        const SecureStringCleanup bip39_cleanup{bip39_passphrase};
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_create = true;
        options.create_flags = wallet_creation_flags;
        options.create_passphrase = wallet_passphrase;
        options.create_bip39_passphrase = std::move(bip39_passphrase);
        bilingual_str error;
        const std::shared_ptr<CWallet> created_wallet{CreateWallet(m_context, name, /*load_on_start=*/false, options, status, error, warnings)};
        ClearSecureString(options.create_bip39_passphrase);
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, created_wallet)};
        if (wallet) {
            return wallet;
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> createWalletFromMnemonic(const std::string& name,
                                                                   const SecureString& wallet_passphrase,
                                                                   SecureString mnemonic,
                                                                   SecureString bip39_passphrase,
                                                                   uint64_t wallet_creation_flags,
                                                                   std::vector<bilingual_str>& warnings,
                                                                   WalletLoader::RestoreProgressFn progress) override
    {
        const SecureStringCleanup mnemonic_cleanup{mnemonic};
        const SecureStringCleanup bip39_cleanup{bip39_passphrase};
        auto report_progress = [&](const bilingual_str& title, int value) {
            if (progress) progress(title.translated, value);
        };
        report_progress(_("Preparing wallet recovery..."), 0);

        if (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS) {
            return util::Error{_("A wallet restored from a recovery phrase must have private keys enabled.")};
        }
        if (wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) {
            return util::Error{_("A wallet restored from a recovery phrase cannot use an external signer.")};
        }

        auto normalized_passphrase{NormalizeBIP39Passphrase(bip39_passphrase)};
        if (!normalized_passphrase) {
            return util::Error{util::ErrorString(normalized_passphrase)};
        }
        ClearSecureString(*normalized_passphrase);

        std::string mnemonic_text{mnemonic.begin(), mnemonic.end()};
        ClearSecureString(mnemonic);
        auto seed_key = DecodeBIP39Mnemonic(mnemonic_text);
        if (!mnemonic_text.empty()) memory_cleanse(mnemonic_text.data(), mnemonic_text.size());
        if (!seed_key) {
            return util::Error{util::ErrorString(seed_key)};
        }

        if (m_context.chain) {
            const std::optional<int> chain_height{m_context.chain->getHeight()};
            if (chain_height && *chain_height > 0) {
                const int private_activation_height{Params().GetConsensus().privateTxActivationHeight};
                const uint256 chain_tip{m_context.chain->getBlockHash(*chain_height)};
                if (!m_context.chain->hasBlocks(chain_tip, 0, *chain_height)) {
                    return util::Error{PrunedWalletRecoveryError()};
                }
                if (!m_context.chain->hasTransparentHistoryIndex()) {
                    return util::Error{_("A recovery phrase requires -transparenthistoryindex=1 when restoring an existing chain.")};
                }
                if (private_activation_height >= 0 && *chain_height >= private_activation_height &&
                    !m_context.chain->hasOrchardIndex()) {
                    return util::Error{_("A recovery phrase requires -orchardindex=1 after private activation.")};
                }
            }
        }

        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_create = true;
        options.create_flags = (wallet_creation_flags | WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET) & ~WALLET_FLAG_DISABLE_PRIVATE_KEYS & ~WALLET_FLAG_EXTERNAL_SIGNER;
        options.create_passphrase = wallet_passphrase;

        bilingual_str error;
        std::shared_ptr<CWallet> wallet{CreateWallet(m_context, name, /*load_on_start=*/false, options, status, error, warnings)};
        if (!wallet) {
            return util::Error{error};
        }
        CWallet::ScanProgressFn history_restore_progress;
        if (progress) {
            history_restore_progress = [&](int value) {
                static constexpr int HISTORY_RESTORE_PROGRESS_BEGIN{5};
                static constexpr int HISTORY_RESTORE_PROGRESS_END{99};
                const int clamped_value{std::clamp(value, 0, 100)};
                const int mapped_value{HISTORY_RESTORE_PROGRESS_BEGIN +
                    (clamped_value * (HISTORY_RESTORE_PROGRESS_END - HISTORY_RESTORE_PROGRESS_BEGIN)) / 100};
                report_progress(_("Restoring complete wallet history..."), mapped_value);
            };
        }

        const bool relock = wallet->IsCrypted();
        if (relock && !wallet->Unlock(wallet_passphrase)) {
            RemoveWallet(m_context, wallet, /*load_on_start=*/false);
            return util::Error{_("Wallet created but could not be unlocked to restore the recovery phrase.")};
        }

        const int64_t restore_birth_time{Params().GenesisBlock().GetBlockTime()};

        try {
            LOCK(wallet->cs_wallet);
            wallet->SetupDescriptorScriptPubKeyMans(*seed_key, bip39_passphrase, restore_birth_time);
        } catch (const std::exception& e) {
            ClearSecureString(bip39_passphrase);
            if (relock) wallet->Lock();
            return util::Error{strprintf(_("Wallet created but recovery phrase restore failed: %s"), e.what())};
        }
        ClearSecureString(bip39_passphrase);

        wallet->BlockUntilSyncedToCurrentChain();
        int recovery_target_height{0};
        uint256 recovery_target_block{Params().GenesisBlock().GetHash()};
        {
            LOCK(wallet->cs_wallet);
            if (wallet->GetLastBlockHeight() >= 0 && !wallet->GetLastBlockHash().IsNull()) {
                recovery_target_height = wallet->GetLastBlockHeight();
                recovery_target_block = wallet->GetLastBlockHash();
            }
        }
        SeedHistoryState recovery_state{SeedHistoryState::AvailableBalance(
            recovery_target_height,
            recovery_target_block,
            /*orchard_applicable=*/true)};
        recovery_state.MarkHistory(/*orchard=*/false, SeedRecoveryStatus::PENDING, recovery_target_height, recovery_target_block);
        recovery_state.MarkHistory(/*orchard=*/true, SeedRecoveryStatus::PENDING, recovery_target_height, recovery_target_block);
        if (!wallet->SetSeedHistoryState(recovery_state)) {
            if (relock) wallet->Lock();
            return util::Error{_("Wallet created but recovery history state could not be saved.")};
        }

        const bool discovery_ready{wallet->TopUpSeedRestoreKeyPool()};
        if (!discovery_ready) {
            recovery_state.MarkFunds(/*orchard=*/false, SeedRecoveryStatus::FAILED, recovery_target_height, recovery_target_block);
            recovery_state.MarkFunds(/*orchard=*/true, SeedRecoveryStatus::FAILED, recovery_target_height, recovery_target_block);
            if (!wallet->SetSeedHistoryState(recovery_state)) {
                if (relock) wallet->Lock();
                return util::Error{_("Wallet roots were saved, but address discovery and its failure state could not be persisted.")};
            }
            recovery_state.MarkHistory(/*orchard=*/false, SeedRecoveryStatus::FAILED, recovery_target_height, recovery_target_block);
            recovery_state.MarkHistory(/*orchard=*/true, SeedRecoveryStatus::FAILED, recovery_target_height, recovery_target_block);
            wallet->SetSeedHistoryState(recovery_state);
            if (relock) wallet->Lock();
            return util::Error{_("The wallet and its recovery roots were saved, but address discovery could not be prepared.")};
        }

        report_progress(_("Restoring complete wallet history..."), 5);
        if (auto restored = wallet->RestoreSeedHistory(
                /*wait_for_indexes=*/true,
                /*show_progress=*/false,
                history_restore_progress);
            !restored) {
            if (relock) wallet->Lock();
            return util::Error{strprintf(
                _("Wallet created, but complete recovery could not finish: %s"),
                util::ErrorString(restored))};
        }
        report_progress(_("Wallet recovery complete."), 100);

        if (relock) wallet->Lock();

        std::unique_ptr<Wallet> wallet_interface{MakeWallet(m_context, wallet)};
        if (wallet_interface) {
            return wallet_interface;
        }
        return util::Error{_("Wallet restored from recovery phrase but could not be opened.")};
    }
    util::Result<std::unique_ptr<Wallet>> loadWallet(const std::string& name, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_existing = true;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, LoadWallet(m_context, name, /*load_on_start=*/false, options, status, error, warnings))};
        if (wallet) {
            return wallet;
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> restoreWallet(const fs::path& backup_file, const std::string& wallet_name, std::vector<bilingual_str>& warnings) override
    {
        DatabaseStatus status;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, RestoreWallet(m_context, backup_file, wallet_name, /*load_on_start=*/false, status, error, warnings))};
        if (wallet) {
            return wallet;
        } else {
            return util::Error{error};
        }
    }
    util::Result<WalletMigrationResult> migrateWallet(const std::string& name, const SecureString& passphrase) override
    {
        auto res = wallet::MigrateLegacyToDescriptor(name, passphrase, m_context);
        if (!res) return util::Error{util::ErrorString(res)};
        WalletMigrationResult out{
            .wallet = MakeWallet(m_context, res->wallet),
            .watchonly_wallet_name = res->watchonly_wallet ? std::make_optional(res->watchonly_wallet->GetName()) : std::nullopt,
            .solvables_wallet_name = res->solvables_wallet ? std::make_optional(res->solvables_wallet->GetName()) : std::nullopt,
            .backup_path = res->backup_path,
        };
        return out;
    }
    std::string getWalletDir() override
    {
        return fs::PathToString(GetWalletDir());
    }
    std::vector<std::string> listWalletDir() override
    {
        std::vector<std::string> paths;
        for (auto& path : ListDatabases(GetWalletDir())) {
            paths.push_back(fs::PathToString(path));
        }
        return paths;
    }
    std::vector<std::unique_ptr<Wallet>> getWallets() override
    {
        std::vector<std::unique_ptr<Wallet>> wallets;
        for (const auto& wallet : GetWallets(m_context)) {
            wallets.emplace_back(MakeWallet(m_context, wallet));
        }
        return wallets;
    }
    std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) override
    {
        return HandleLoadWallet(m_context, std::move(fn));
    }
    WalletContext* context() override  { return &m_context; }

    WalletContext m_context;
    const std::vector<std::string> m_wallet_filenames;
    std::vector<std::unique_ptr<Handler>> m_rpc_handlers;
    std::list<CRPCCommand> m_rpc_commands;
};
} // namespace
} // namespace wallet

namespace interfaces {
std::unique_ptr<Wallet> MakeWallet(wallet::WalletContext& context, const std::shared_ptr<wallet::CWallet>& wallet) { return wallet ? std::make_unique<wallet::WalletImpl>(context, wallet) : nullptr; }

std::unique_ptr<WalletLoader> MakeWalletLoader(Chain& chain, ArgsManager& args)
{
    return std::make_unique<wallet::WalletLoaderImpl>(chain, args);
}
} // namespace interfaces
