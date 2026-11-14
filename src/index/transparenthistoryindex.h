// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_TRANSPARENTHISTORYINDEX_H
#define BITCOIN_INDEX_TRANSPARENTHISTORYINDEX_H

#include <index/base.h>

#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <vector>

class CBlockIndex;
class CScript;
class TransparentHistoryIndexTestAccess;

namespace interfaces {
class Chain;
struct TransparentHistoryEntry;
} // namespace interfaces

static constexpr bool DEFAULT_TRANSPARENTHISTORYINDEX{true};

/**
 * Local transparent script history index for wallet history rebuilds.
 *
 * The index stores public transparent scriptPubKey receive/spend events by
 * active-chain height. It does not store wallet seeds, xpubs, descriptors,
 * labels, Orchard data, or any wallet-specific ownership state.
 */
class TransparentHistoryIndex final : public BaseIndex
{
private:
    friend class TransparentHistoryIndexTestAccess;

    class DB;
    class PendingUpdate;

    std::unique_ptr<DB> m_db;
    std::unique_ptr<PendingUpdate> m_pending;

    bool AllowPrune() const override { return false; }

protected:
    bool CustomInit(const std::optional<interfaces::BlockKey>& block) override;
    bool CustomAppend(const interfaces::BlockInfo& block) override;
    bool CommitOnAppend() const override { return true; }
    bool CustomCommit(CDBBatch& batch) override;
    bool CustomRewind(const interfaces::BlockKey& current_tip, const interfaces::BlockKey& new_tip) override;

    BaseIndex::DB& GetDB() const LIFETIMEBOUND override;

public:
    explicit TransparentHistoryIndex(std::unique_ptr<interfaces::Chain> chain,
                                     size_t n_cache_size,
                                     bool f_memory = false,
                                     bool f_wipe = false);
    ~TransparentHistoryIndex() override;

    bool LookupScripts(const std::set<CScript>& scripts,
                       int start_height,
                       int stop_height,
                       std::vector<interfaces::TransparentHistoryEntry>& entries) const;
};

TransparentHistoryIndex* GetTransparentHistoryIndex();

bool InitTransparentHistoryIndex(std::function<std::unique_ptr<interfaces::Chain>()> make_chain,
                                 size_t n_cache_size,
                                 bool f_memory = false,
                                 bool f_wipe = false);

void DestroyTransparentHistoryIndex();

#endif // BITCOIN_INDEX_TRANSPARENTHISTORYINDEX_H
