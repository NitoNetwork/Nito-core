// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_ORCHARDINDEX_H
#define BITCOIN_INDEX_ORCHARDINDEX_H

#include <index/base.h>
#include <kernel/cs_main.h>
#include <primitives/transaction.h>

#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace interfaces {
class Chain;
struct OrchardIndexedTransaction;
} // namespace interfaces

static constexpr bool DEFAULT_ORCHARDINDEX = true;

class CBlockIndex;
class uint256;
class OrchardIndexTestAccess;

/**
 * Local index of transactions carrying Nito Orchard private bundles.
 *
 * The index stores compact public Orchard effects and their position in each
 * active-chain block, plus complete public Orchard transactions for wallet
 * history hydration after block pruning. It never stores wallet seeds, viewing keys, decrypted
 * notes, nullifier ownership, or address mappings.
 */
class OrchardIndex final : public BaseIndex
{
private:
    friend class OrchardIndexTestAccess;

    class DB;

    std::unique_ptr<DB> m_db;
    const int m_activation_height;

    bool AllowPrune() const override { return true; }

protected:
    bool CustomInit(const std::optional<interfaces::BlockKey>& block) override
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    bool CustomAppend(const interfaces::BlockInfo& block) override;
    bool CommitOnAppend() const override { return true; }
    bool CustomCommit(CDBBatch& batch) override;
    bool CustomRewind(const interfaces::BlockKey& current_tip, const interfaces::BlockKey& new_tip) override;

    BaseIndex::DB& GetDB() const LIFETIMEBOUND override;

public:
    explicit OrchardIndex(std::unique_ptr<interfaces::Chain> chain,
                          size_t n_cache_size,
                          bool f_memory = false,
                          bool f_wipe = false);
    ~OrchardIndex() override;

    bool LookupBlockTransactions(const CBlockIndex* block_index, std::vector<interfaces::OrchardIndexedTransaction>& txs) const;
    CTransactionRef LookupTransaction(const CBlockIndex* block_index, int32_t position) const;
    bool LookupCommitmentIndex(const uint256& commitment,
                               uint64_t& commitment_index,
                               uint256& root,
                               uint64_t& commitment_count) const;
    bool LookupMerkleAuthPaths(const std::vector<uint64_t>& commitment_indices,
                               std::vector<std::vector<uint256>>& auth_paths,
                               uint256& root,
                               uint64_t& commitment_count) const;
};

OrchardIndex* GetOrchardIndex();

bool InitOrchardIndex(std::function<std::unique_ptr<interfaces::Chain>()> make_chain,
                      size_t n_cache_size,
                      bool f_memory = false,
                      bool f_wipe = false);

void DestroyOrchardIndex();

#endif // BITCOIN_INDEX_ORCHARDINDEX_H
