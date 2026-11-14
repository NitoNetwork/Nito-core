// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <index/orchardindex.h>
#include <index/transparenthistoryindex.h>
#include <interfaces/chain.h>
#include <node/blockstorage.h>
#include <private/orchard_verifier.h>
#include <primitives/block.h>
#include <primitives/private_transaction.h>
#include <primitives/transaction.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <test/util/logging.h>
#include <uint256.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class OrchardIndexTestAccess
{
public:
    static CDBWrapper& Storage(OrchardIndex& index)
    {
        return index.GetDB();
    }

    static bool Append(OrchardIndex& index, const interfaces::BlockInfo& block)
    {
        return index.CustomAppend(block);
    }

    static bool Rewind(OrchardIndex& index, const interfaces::BlockKey& current_tip, const interfaces::BlockKey& new_tip)
    {
        return index.CustomRewind(current_tip, new_tip);
    }

    static bool Commit(OrchardIndex& index, const CBlockLocator& locator)
    {
        auto& db{index.GetDB()};
        CDBBatch batch{db};
        if (!index.CustomCommit(batch)) return false;
        db.WriteBestBlock(batch, locator);
        return db.WriteBatch(batch);
    }
};

class TransparentHistoryIndexTestAccess
{
public:
    static bool Append(TransparentHistoryIndex& index, const interfaces::BlockInfo& block)
    {
        return index.CustomAppend(block);
    }

    static bool Rewind(TransparentHistoryIndex& index, const interfaces::BlockKey& current_tip, const interfaces::BlockKey& new_tip)
    {
        return index.CustomRewind(current_tip, new_tip);
    }

    static bool Commit(TransparentHistoryIndex& index, const CBlockLocator& locator)
    {
        auto& db{index.GetDB()};
        CDBBatch batch{db};
        if (!index.CustomCommit(batch)) return false;
        db.WriteBestBlock(batch, locator);
        return db.WriteBatch(batch);
    }
};

namespace {

CPrivateActionEffects MakeIndexedAction(uint8_t tag)
{
    CPrivateActionEffects action;
    action.cv = uint256{static_cast<uint8_t>(tag + 1)};
    action.nullifier = uint256{static_cast<uint8_t>(tag + 2)};
    action.rk = uint256{static_cast<uint8_t>(tag + 3)};
    action.cmx = uint256{static_cast<uint8_t>(tag + 4)};
    action.ephemeral_key.assign(PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE, tag);
    action.enc_ciphertext.assign(PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE, tag);
    action.out_ciphertext.assign(PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE, tag);
    return action;
}

CBlock MakeIndexedBlock(uint8_t tag, uint256& commitment)
{
    CMutableTransaction tx;
    tx.m_private_bundle.emplace();
    tx.m_private_bundle->effects.actions.push_back(MakeIndexedAction(tag));
    commitment = tx.m_private_bundle->effects.actions.front().cmx;

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(std::move(tx)));
    return block;
}

void CheckAuthPaths(OrchardIndex& index, const std::vector<uint256>& commitments)
{
    std::vector<uint64_t> positions;
    positions.reserve(commitments.size());
    for (uint64_t position{0}; position < commitments.size(); ++position) {
        positions.push_back(position);
    }

    std::vector<std::vector<uint256>> actual_paths;
    uint256 actual_root;
    uint64_t actual_count{0};
    BOOST_REQUIRE(index.LookupMerkleAuthPaths(positions, actual_paths, actual_root, actual_count));
    BOOST_REQUIRE_EQUAL(actual_count, commitments.size());
    BOOST_REQUIRE_EQUAL(actual_paths.size(), commitments.size());

    for (uint32_t position{0}; position < commitments.size(); ++position) {
        std::vector<uint256> expected_path;
        uint256 expected_root;
        std::string error;
        BOOST_REQUIRE(ComputePrivateOrchardAuthPath(commitments, position, expected_path, expected_root, error) ==
                      PrivateOrchardBuildResult::OK);
        BOOST_CHECK_EQUAL(actual_root, expected_root);
        BOOST_CHECK_EQUAL_COLLECTIONS(actual_paths[position].begin(), actual_paths[position].end(),
                                      expected_path.begin(), expected_path.end());
    }
}

struct OrchardIndexTestingSetup : public TestChain100Setup
{
    OrchardIndexTestingSetup()
        : TestChain100Setup{ChainType::REGTEST, {"-privateactivationheight=1", "-debug=bench"}}
    {
    }

    const CBlockIndex* BlockAt(int height) const
    {
        LOCK(cs_main);
        return Assert(m_node.chainman)->ActiveChain()[height];
    }

    std::vector<uint256> Populate(OrchardIndex& index, int stop_height)
    {
        BOOST_REQUIRE(index.Init());
        BOOST_REQUIRE(OrchardIndexTestAccess::Commit(index, ::GetLocator(BlockAt(0))));

        std::vector<uint256> commitments;
        commitments.reserve(stop_height);
        for (int height{1}; height <= stop_height; ++height) {
            const CBlockIndex* block_index{BlockAt(height)};
            const uint256 block_hash{block_index->GetBlockHash()};
            const uint256 prev_hash{BlockAt(height - 1)->GetBlockHash()};
            uint256 commitment;
            const CBlock block{MakeIndexedBlock(static_cast<uint8_t>(height), commitment)};
            interfaces::BlockInfo info{block_hash};
            info.prev_hash = &prev_hash;
            info.height = height;
            info.data = &block;
            BOOST_REQUIRE(OrchardIndexTestAccess::Append(index, info));
            BOOST_REQUIRE(OrchardIndexTestAccess::Commit(index, ::GetLocator(block_index)));
            commitments.push_back(commitment);
        }
        return commitments;
    }
};

struct PreActivationIndexTestingSetup : public TestChain100Setup
{
    PreActivationIndexTestingSetup()
        : TestChain100Setup{ChainType::REGTEST, {"-privateactivationheight=1000"}}
    {
        // Finish fixture block notifications before simulating incompatible index data.
        SyncWithValidationInterfaceQueue();
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(orchardindex_tests)

BOOST_FIXTURE_TEST_CASE(activation_change_reinitializes_empty_checkpoint_durably, PreActivationIndexTestingSetup)
{
    const CBlockIndex* tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())};
    {
        OrchardIndex index{interfaces::MakeChain(m_node), 1 << 20, false, true};
        BOOST_REQUIRE(index.Init());
        BOOST_REQUIRE(OrchardIndexTestAccess::Commit(index, ::GetLocator(tip)));
        index.Stop();
        // Simulate an older, still pre-activation build using this same database.
        BOOST_REQUIRE(OrchardIndexTestAccess::Storage(index).Write(uint8_t{'A'}, 500));
    }
    {
        ASSERT_DEBUG_LOG("Reinitialized empty Orchard index for activation height change (500 -> 1000)");
        OrchardIndex index{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(index.Init());
        BOOST_CHECK(index.GetSummary().best_block_hash == tip->GetBlockHash());
        int height{0};
        BOOST_REQUIRE(OrchardIndexTestAccess::Storage(index).Read(uint8_t{'A'}, height));
        BOOST_CHECK_EQUAL(height, 1000);
        // No background sync or subsequent commit: Init itself must persist it.
        index.Stop();
    }
    {
        bool reset_again{false};
        DebugLogHelper log{"Reinitialized empty Orchard index", [&](const std::string* line) {
            if (line) reset_again = true;
            return false;
        }};
        OrchardIndex reopened{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(reopened.Init());
        BOOST_CHECK(reopened.GetSummary().best_block_hash == tip->GetBlockHash());
        BOOST_CHECK(!reset_again);
        reopened.Stop();
    }
}

BOOST_FIXTURE_TEST_CASE(activation_change_preserves_unsafe_or_inconsistent_index, PreActivationIndexTestingSetup)
{
    const CBlockIndex* tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())};
    // Each post-activation record family must prevent an automatic reset,
    // even if the persisted current frontier still appears empty after a crash.
    for (const uint8_t prefix : {'h', 'H', 'm', 'S', 'c', 't', 'V', 'A', 's', 'B', 'L'}) {
        BOOST_TEST_CONTEXT("incompatible record " << prefix) {
            OrchardIndex index{interfaces::MakeChain(m_node), 1 << 20, true, true};
            BOOST_REQUIRE(index.Init());
            BOOST_REQUIRE(OrchardIndexTestAccess::Commit(index, ::GetLocator(tip)));
            index.Stop();
            CDBWrapper& db{OrchardIndexTestAccess::Storage(index)};
            const int old_height{prefix == 'A' ? tip->nHeight : 500};
            BOOST_REQUIRE(db.Write(uint8_t{'A'}, old_height));
            if (prefix == 'V') {
                BOOST_REQUIRE(db.Write(prefix, uint32_t{999}));
            } else if (prefix == 's') {
                BOOST_REQUIRE(db.Erase(prefix));
            } else if (prefix == 'B') {
                BOOST_REQUIRE(db.Write(prefix, ::GetLocator(tip->pprev)));
            } else if (prefix == 'L') {
                WITH_LOCK(cs_main, BOOST_REQUIRE(m_node.chainman->m_blockman.MarkNitoPrivateActivationObserved()));
            } else if (prefix != 'A') {
                BOOST_REQUIRE(db.Write(std::make_pair(prefix, uint32_t{1}), uint32_t{123}));
            }
            int prepared_height{0};
            BOOST_REQUIRE(db.Read(uint8_t{'A'}, prepared_height));
            BOOST_REQUIRE_EQUAL(prepared_height, old_height);
            if (prefix == 'L') {
                BOOST_REQUIRE(m_node.chainman->m_blockman.NitoPrivateActivationObserved());
            }
            BOOST_CHECK(!index.Init());
            int stored_height{0};
            BOOST_REQUIRE(db.Read(uint8_t{'A'}, stored_height));
            BOOST_CHECK_EQUAL(stored_height, old_height);
            if (prefix != 'V' && prefix != 'A' && prefix != 's' && prefix != 'B' && prefix != 'L') {
                uint32_t value{0};
                BOOST_REQUIRE(db.Read(std::make_pair(prefix, uint32_t{1}), value));
                BOOST_CHECK_EQUAL(value, 123U);
            }
            index.Stop();
        }
    }
}

BOOST_FIXTURE_TEST_CASE(multi_commitment_append_checkpoint_recovery, OrchardIndexTestingSetup)
{
    std::vector<uint256> original;
    std::vector<uint256> extended;
    CMutableTransaction tx;
    tx.m_private_bundle.emplace();
    for (uint8_t tag = 40; tag < 90; ++tag) tx.m_private_bundle->effects.actions.push_back(MakeIndexedAction(tag));
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));
    const auto* tip = BlockAt(8);
    const auto* ancestor = BlockAt(7);
    const auto prev_hash = ancestor->GetBlockHash();
    const auto block_hash = tip->GetBlockHash();
    interfaces::BlockInfo info{block_hash};
    info.prev_hash = &prev_hash;
    info.height = tip->nHeight;
    info.data = &block;

    {
        OrchardIndex index{interfaces::MakeChain(m_node), 1 << 20, false, true};
        original = Populate(index, 7);
        extended = original;
        for (const auto& action : tx.m_private_bundle->effects.actions) extended.push_back(action.cmx);
        DebugLogHelper measurement{"orchardindex: append height=8", [](const std::string* line) {
            if (line) BOOST_TEST_MESSAGE(*line);
            return true;
        }};
        BOOST_REQUIRE(OrchardIndexTestAccess::Append(index, info));
        // The append overwrote partial subtrees, but its locator was not committed.
        index.Stop();
    }
    {
        OrchardIndex index{interfaces::MakeChain(m_node), 1 << 20, false, false};
        BOOST_REQUIRE(index.Init());
        CheckAuthPaths(index, original);
        BOOST_REQUIRE(OrchardIndexTestAccess::Append(index, info));
        BOOST_REQUIRE(OrchardIndexTestAccess::Commit(index, ::GetLocator(tip)));
        CheckAuthPaths(index, extended);
        const auto stored_tx = index.LookupTransaction(tip, 0);
        BOOST_REQUIRE(stored_tx);
        BOOST_CHECK_EQUAL(stored_tx->GetWitnessHash(), block.vtx[0]->GetWitnessHash());
        BOOST_CHECK(!index.LookupTransaction(tip, 1));
        BOOST_CHECK(!index.LookupTransaction(nullptr, 0));
        index.Stop();
    }
    {
        OrchardIndex index{interfaces::MakeChain(m_node), 1 << 20, false, false};
        BOOST_REQUIRE(index.Init());
        CheckAuthPaths(index, extended);
        const auto stored_tx = index.LookupTransaction(tip, 0);
        BOOST_REQUIRE(stored_tx);
        BOOST_CHECK_EQUAL(stored_tx->GetWitnessHash(), block.vtx[0]->GetWitnessHash());
        BOOST_REQUIRE(OrchardIndexTestAccess::Rewind(index,
            {tip->GetBlockHash(), tip->nHeight}, {ancestor->GetBlockHash(), ancestor->nHeight}));
        BOOST_REQUIRE(OrchardIndexTestAccess::Commit(index, ::GetLocator(ancestor)));
        CheckAuthPaths(index, original);
        index.Stop();
    }
    {
        OrchardIndex index{interfaces::MakeChain(m_node), 1 << 20, false, false};
        BOOST_REQUIRE(index.Init());
        CheckAuthPaths(index, original);
        index.Stop();
    }
}

BOOST_FIXTURE_TEST_CASE(rewind_frontier_is_not_published_before_locator, OrchardIndexTestingSetup)
{
    std::vector<uint256> commitments;
    {
        OrchardIndex index{interfaces::MakeChain(m_node), 1 << 20, /*f_memory=*/false, /*f_wipe=*/true};
        commitments = Populate(index, 7);
        CheckAuthPaths(index, commitments);

        const CBlockIndex* current_tip{BlockAt(7)};
        const CBlockIndex* new_tip{BlockAt(5)};
        BOOST_REQUIRE(OrchardIndexTestAccess::Rewind(
            index,
            {current_tip->GetBlockHash(), current_tip->nHeight},
            {new_tip->GetBlockHash(), new_tip->nHeight}));

        // Simulate an abrupt stop after rewind preparation but before BaseIndex
        // commits the subclass state and locator. Persisted reads must still
        // expose the complete pre-rewind state, never a mixed pair.
        CheckAuthPaths(index, commitments);
        index.Stop();
    }

    {
        OrchardIndex reopened{interfaces::MakeChain(m_node), 1 << 20, /*f_memory=*/false, /*f_wipe=*/false};
        BOOST_REQUIRE(reopened.Init());
        CheckAuthPaths(reopened, commitments);
        reopened.Stop();
    }
}

BOOST_FIXTURE_TEST_CASE(missing_locator_tip_recovers_from_persisted_ancestor, OrchardIndexTestingSetup)
{
    const uint256 missing_tip_hash{GetRandHash()};
    const CBlockIndex* persisted_ancestor{BlockAt(6)};
    std::vector<uint256> commitments;

    {
        OrchardIndex index{interfaces::MakeChain(m_node), 1 << 20, /*f_memory=*/false, /*f_wipe=*/true};
        commitments = Populate(index, persisted_ancestor->nHeight);

        const uint256 prev_hash{persisted_ancestor->GetBlockHash()};
        uint256 ignored_commitment;
        const CBlock block{MakeIndexedBlock(42, ignored_commitment)};
        interfaces::BlockInfo info{missing_tip_hash};
        info.prev_hash = &prev_hash;
        info.height = persisted_ancestor->nHeight + 1;
        info.data = &block;
        BOOST_REQUIRE(OrchardIndexTestAccess::Append(index, info));

        CBlockLocator interrupted_locator;
        interrupted_locator.vHave = {missing_tip_hash, persisted_ancestor->GetBlockHash(), BlockAt(0)->GetBlockHash()};
        BOOST_REQUIRE(OrchardIndexTestAccess::Commit(index, interrupted_locator));
        index.Stop();
    }

    {
        OrchardIndex recovered{interfaces::MakeChain(m_node), 1 << 20, /*f_memory=*/false, /*f_wipe=*/false};
        BOOST_REQUIRE(recovered.Init());
        BOOST_CHECK_EQUAL(recovered.GetSummary().best_block_height, persisted_ancestor->nHeight);
        CheckAuthPaths(recovered, commitments);
        recovered.Stop();
    }

    // The repaired locator/state pair must itself survive another restart.
    {
        OrchardIndex reopened{interfaces::MakeChain(m_node), 1 << 20, /*f_memory=*/false, /*f_wipe=*/false};
        BOOST_REQUIRE(reopened.Init());
        BOOST_CHECK_EQUAL(reopened.GetSummary().best_block_height, persisted_ancestor->nHeight);
        CheckAuthPaths(reopened, commitments);
        reopened.Stop();
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(transparenthistoryindex_tests)

BOOST_FIXTURE_TEST_CASE(rewind_rejects_height_inverse_from_another_block, OrchardIndexTestingSetup)
{
    TransparentHistoryIndex index{interfaces::MakeChain(m_node), 1 << 20, /*f_memory=*/true, /*f_wipe=*/true};
    BOOST_REQUIRE(index.Init());
    BOOST_REQUIRE(TransparentHistoryIndexTestAccess::Commit(index, ::GetLocator(BlockAt(0))));

    const CBlockIndex* block1_index{BlockAt(1)};
    const CBlockIndex* block2_index{BlockAt(2)};
    CBlock block1;
    CBlock block2;
    BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlockFromDisk(block1, *block1_index));
    BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlockFromDisk(block2, *block2_index));

    const uint256 genesis_hash{BlockAt(0)->GetBlockHash()};
    const uint256 block1_hash{block1_index->GetBlockHash()};
    const uint256 block2_hash{block2_index->GetBlockHash()};
    interfaces::BlockInfo block1_info{block1_hash};
    block1_info.prev_hash = &genesis_hash;
    block1_info.height = 1;
    block1_info.data = &block1;
    BOOST_REQUIRE(TransparentHistoryIndexTestAccess::Append(index, block1_info));
    BOOST_REQUIRE(TransparentHistoryIndexTestAccess::Commit(index, ::GetLocator(block1_index)));

    // Test-only corruption fixture: overwrite height 1 with a different known
    // block hash. A rewind for the real block 1 must refuse to erase it.
    interfaces::BlockInfo mismatched_info{block2_hash};
    mismatched_info.prev_hash = &genesis_hash;
    mismatched_info.height = 1;
    mismatched_info.data = &block2;
    BOOST_REQUIRE(TransparentHistoryIndexTestAccess::Append(index, mismatched_info));
    BOOST_REQUIRE(TransparentHistoryIndexTestAccess::Commit(index, ::GetLocator(block2_index)));

    BOOST_REQUIRE(TransparentHistoryIndexTestAccess::Rewind(
        index,
        {block1_index->GetBlockHash(), block1_index->nHeight},
        {BlockAt(0)->GetBlockHash(), 0}));
    BOOST_CHECK(!TransparentHistoryIndexTestAccess::Commit(index, ::GetLocator(BlockAt(0))));
    index.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
