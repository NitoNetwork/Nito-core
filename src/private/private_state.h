// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIVATE_PRIVATE_STATE_H
#define BITCOIN_PRIVATE_PRIVATE_STATE_H

#include <consensus/amount.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class CBlock;
class CCoinsViewCache;
class CTransaction;

struct CPrivateTxUndo
{
    bool has_private_bundle{false};
    uint64_t previous_commitment_count{0};
    CAmount previous_value_pool{0};
    CAmount connected_value_pool{0};
    uint256 previous_root;
    uint256 connected_root;
    std::vector<unsigned char> previous_frontier;
    std::vector<unsigned char> connected_frontier;
    std::vector<uint256> added_nullifiers;
    std::vector<uint64_t> added_commitment_indices;

    SERIALIZE_METHODS(CPrivateTxUndo, obj)
    {
        READWRITE(obj.has_private_bundle, VARINT(obj.previous_commitment_count), obj.previous_value_pool,
                  obj.connected_value_pool, obj.previous_root, obj.connected_root,
                  obj.previous_frontier, obj.connected_frontier,
                  obj.added_nullifiers, obj.added_commitment_indices);
    }
};

struct CPrivateBlockUndo
{
    std::vector<CPrivateTxUndo> vtxundo;

    SERIALIZE_METHODS(CPrivateBlockUndo, obj) { READWRITE(obj.vtxundo); }
};

bool BlockHasPrivateTransactions(const CBlock& block);
bool ComputePrivateRootForCommitments(const std::vector<uint256>& commitments, uint256& root_out, std::string& error);
bool AppendPrivateCommitmentsToFrontier(const std::vector<unsigned char>& frontier_in, const std::vector<uint256>& commitments, uint256& root_out, std::vector<unsigned char>& frontier_out, std::string& error);
bool GetPrivateEmptyRoot(uint256& root_out, std::string& error);
bool CheckPrivateValuePoolTransition(CAmount previous_value_pool, CAmount private_value_balance, CAmount& connected_value_pool, std::string& error);
bool ApplyPrivateTransaction(const CTransaction& tx, CCoinsViewCache& view, CPrivateTxUndo& undo, std::string& error);
bool UndoPrivateTransaction(CCoinsViewCache& view, const CPrivateTxUndo& undo, std::string& error);

#endif // BITCOIN_PRIVATE_PRIVATE_STATE_H
