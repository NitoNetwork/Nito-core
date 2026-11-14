// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <private/private_state.h>

#include <coins.h>
#include <private/orchard_ffi.h>
#include <primitives/block.h>
#include <primitives/private_transaction.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace {
static constexpr size_t PRIVATE_FRONTIER_MAX_SIZE = 1 + 8 + 32 + 1 + (32 * 32);

const uint8_t* Bytes(const uint256& value)
{
    return reinterpret_cast<const uint8_t*>(value.begin());
}

} // namespace

bool ComputePrivateRootForCommitments(const std::vector<uint256>& commitments, uint256& root_out, std::string& error)
{
    std::vector<uint8_t> flat;
    flat.reserve(commitments.size() * 32);
    for (const auto& cmx : commitments) {
        flat.insert(flat.end(), Bytes(cmx), Bytes(cmx) + 32);
    }

    std::array<uint8_t, 32> root{};
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_compute_root(
        flat.empty() ? nullptr : flat.data(),
        commitments.size(),
        root.data(),
        ffi_error.data(),
        ffi_error.size());
    if (code != 0) {
        error = ffi_error.data();
        return false;
    }
    std::memcpy(root_out.begin(), root.data(), 32);
    return true;
}

bool AppendPrivateCommitmentsToFrontier(const std::vector<unsigned char>& frontier_in, const std::vector<uint256>& commitments, uint256& root_out, std::vector<unsigned char>& frontier_out, std::string& error)
{
    std::vector<uint8_t> flat;
    flat.reserve(commitments.size() * 32);
    for (const auto& cmx : commitments) {
        flat.insert(flat.end(), Bytes(cmx), Bytes(cmx) + 32);
    }

    std::array<uint8_t, 32> root{};
    std::vector<uint8_t> next_frontier(PRIVATE_FRONTIER_MAX_SIZE);
    size_t next_frontier_len{0};
    std::array<char, 256> ffi_error{};
    const int32_t code = nito_orchard_frontier_append(
        frontier_in.empty() ? nullptr : frontier_in.data(),
        frontier_in.size(),
        flat.empty() ? nullptr : flat.data(),
        commitments.size(),
        root.data(),
        next_frontier.data(),
        next_frontier.size(),
        &next_frontier_len,
        ffi_error.data(),
        ffi_error.size());
    if (code != 0) {
        error = ffi_error.data();
        return false;
    }
    if (next_frontier_len > next_frontier.size()) {
        error = "private frontier length exceeds buffer";
        return false;
    }
    next_frontier.resize(next_frontier_len);
    std::memcpy(root_out.begin(), root.data(), 32);
    frontier_out.assign(next_frontier.begin(), next_frontier.end());
    return true;
}

bool GetPrivateEmptyRoot(uint256& root_out, std::string& error)
{
    const std::vector<uint256> empty;
    return ComputePrivateRootForCommitments(empty, root_out, error);
}

bool BlockHasPrivateTransactions(const CBlock& block)
{
    for (const auto& tx : block.vtx) {
        if (tx->HasPrivateBundle()) return true;
    }
    return false;
}

bool CheckPrivateValuePoolTransition(CAmount previous_value_pool, CAmount private_value_balance, CAmount& connected_value_pool, std::string& error)
{
    connected_value_pool = 0;
    if (!MoneyRange(previous_value_pool)) {
        error = "private value pool previous amount out of range";
        return false;
    }
    if (!MoneyRangeSigned(private_value_balance)) {
        error = "private value balance out of range";
        return false;
    }

    const CAmount pool_delta{-private_value_balance};
    if (!MoneyAddSigned(previous_value_pool, pool_delta, connected_value_pool)) {
        error = "private value pool exceeds money range";
        return false;
    }
    if (connected_value_pool < 0) {
        error = "private value pool would become negative";
        return false;
    }
    if (!MoneyRange(connected_value_pool)) {
        error = "private value pool exceeds money range";
        return false;
    }
    return true;
}

bool ApplyPrivateTransaction(const CTransaction& tx, CCoinsViewCache& view, CPrivateTxUndo& undo, std::string& error)
{
    if (!tx.HasPrivateBundle()) return true;

    const CPrivateBundle& bundle = *tx.m_private_bundle;
    if (!view.HavePrivateAnchor(bundle.effects.anchor)) {
        error = "private anchor unknown";
        return false;
    }

    for (const auto& action : bundle.effects.actions) {
        if (view.HavePrivateNullifier(action.nullifier)) {
            error = "private nullifier already spent";
            return false;
        }
    }

    uint64_t previous_count{0};
    if (!view.GetPrivateCommitmentCount(previous_count)) {
        error = "private commitment count missing";
        return false;
    }

    uint256 previous_root;
    if (!view.GetPrivateRoot(previous_root)) {
        error = "private root missing";
        return false;
    }

    std::vector<unsigned char> previous_frontier;
    if (!view.GetPrivateFrontier(previous_frontier)) {
        error = "private frontier missing";
        return false;
    }
    if (previous_frontier.empty() && previous_count > 0) {
        error = "private frontier missing with existing commitments";
        return false;
    }
    if (bundle.effects.actions.size() > std::numeric_limits<uint64_t>::max() - previous_count) {
        error = "private commitment count overflow";
        return false;
    }

    CAmount previous_value_pool{0};
    if (!view.GetPrivateValuePool(previous_value_pool)) {
        error = "private value pool missing";
        return false;
    }
    CAmount connected_value_pool{0};
    if (!CheckPrivateValuePoolTransition(previous_value_pool, bundle.GetValueBalance(), connected_value_pool, error)) {
        return false;
    }

    undo.has_private_bundle = true;
    undo.previous_commitment_count = previous_count;
    undo.previous_value_pool = previous_value_pool;
    undo.connected_value_pool = connected_value_pool;
    undo.previous_root = previous_root;
    undo.previous_frontier = previous_frontier;
    undo.added_nullifiers.reserve(bundle.effects.actions.size());
    undo.added_commitment_indices.reserve(bundle.effects.actions.size());

    std::vector<uint256> appended_commitments;
    appended_commitments.reserve(bundle.effects.actions.size());
    for (const auto& action : bundle.effects.actions) {
        const uint64_t index = previous_count + static_cast<uint64_t>(appended_commitments.size());
        appended_commitments.push_back(action.cmx);
        undo.added_nullifiers.push_back(action.nullifier);
        undo.added_commitment_indices.push_back(index);
    }

    uint256 connected_root;
    std::vector<unsigned char> connected_frontier;
    if (!AppendPrivateCommitmentsToFrontier(previous_frontier, appended_commitments, connected_root, connected_frontier, error)) {
        return false;
    }
    undo.connected_root = connected_root;
    undo.connected_frontier = connected_frontier;

    for (size_t i = 0; i < bundle.effects.actions.size(); ++i) {
        const auto& action = bundle.effects.actions[i];
        view.AddPrivateNullifier(action.nullifier);
        view.AddPrivateCommitment(undo.added_commitment_indices[i], action.cmx);
    }
    view.AddPrivateAnchor(connected_root);
    view.SetPrivateCommitmentCount(previous_count + static_cast<uint64_t>(appended_commitments.size()));
    view.SetPrivateRoot(connected_root);
    view.SetPrivateFrontier(connected_frontier);
    view.SetPrivateValuePool(connected_value_pool);
    return true;
}

bool UndoPrivateTransaction(CCoinsViewCache& view, const CPrivateTxUndo& undo, std::string& error)
{
    if (!undo.has_private_bundle) return true;

    uint256 current_root;
    if (!view.GetPrivateRoot(current_root)) {
        error = "private root missing during undo";
        return false;
    }
    if (current_root != undo.connected_root) {
        error = "private undo root mismatch";
        return false;
    }
    uint64_t current_count{0};
    if (!view.GetPrivateCommitmentCount(current_count)) {
        error = "private commitment count missing during undo";
        return false;
    }
    if (undo.added_commitment_indices.size() > std::numeric_limits<uint64_t>::max() - undo.previous_commitment_count) {
        error = "private undo commitment count overflow";
        return false;
    }
    const uint64_t expected_count = undo.previous_commitment_count + static_cast<uint64_t>(undo.added_commitment_indices.size());
    if (current_count != expected_count) {
        error = "private undo commitment count mismatch";
        return false;
    }
    std::vector<unsigned char> current_frontier;
    if (!view.GetPrivateFrontier(current_frontier)) {
        error = "private frontier missing during undo";
        return false;
    }
    if (current_frontier != undo.connected_frontier) {
        error = "private undo frontier mismatch";
        return false;
    }
    CAmount current_value_pool{0};
    if (!view.GetPrivateValuePool(current_value_pool)) {
        error = "private value pool missing during undo";
        return false;
    }
    if (current_value_pool != undo.connected_value_pool) {
        error = "private undo value pool mismatch";
        return false;
    }

    for (const auto& nf : undo.added_nullifiers) {
        view.ErasePrivateNullifier(nf);
    }
    for (const uint64_t index : undo.added_commitment_indices) {
        view.ErasePrivateCommitment(index);
    }
    view.ErasePrivateAnchor(undo.connected_root);
    view.SetPrivateCommitmentCount(undo.previous_commitment_count);
    view.SetPrivateRoot(undo.previous_root);
    view.SetPrivateFrontier(undo.previous_frontier);
    view.SetPrivateValuePool(undo.previous_value_pool);
    return true;
}
