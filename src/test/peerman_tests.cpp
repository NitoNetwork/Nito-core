// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <node/miner.h>
#include <net_processing.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <algorithm>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(peerman_tests, RegTestingSetup)

/** Window, in blocks, for connecting to NODE_NETWORK_LIMITED peers */
static constexpr int64_t NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS = 144;

static void mineBlock(const node::NodeContext& node, std::chrono::seconds block_time)
{
    auto curr_time = GetTime<std::chrono::seconds>();
    auto consensus = node.chainman->GetConsensus();
    const auto min_block_time = WITH_LOCK(::cs_main, return std::chrono::seconds{node.chainman->ActiveChain().Tip()->GetBlockTime() + 2 * consensus.nPowTargetSpacing + 1});
    SetMockTime(std::max(block_time, min_block_time)); // update time so the block is created with a valid Nito retarget window
    CBlock block = node::BlockAssembler{node.chainman->ActiveChainstate(), nullptr}.CreateNewBlock(CScript() << OP_TRUE)->block;
    const CBlockIndex* tip = WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip());
    block.nBits = GetNextWorkRequired(tip, &block, consensus);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) ++block.nNonce;
    block.fChecked = true; // little speedup
    SetMockTime(curr_time); // process block at current time
    Assert(node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    SyncWithValidationInterfaceQueue(); // drain events queue
}

// Verifying when network-limited peer connections are desirable based on the node's proximity to the tip
BOOST_AUTO_TEST_CASE(connections_desirable_service_flags)
{
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, {});
    auto consensus = m_node.chainman->GetParams().GetConsensus();
    const auto expected_desirable = [&](ServiceFlags base) {
        const int active_height{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height())};
        return Consensus::PrivateTxActive(consensus, active_height) ? ServiceFlags(base | NODE_NITO_PRIVATE) : base;
    };

    // Check we start connecting to full nodes
    ServiceFlags peer_flags{NODE_WITNESS | NODE_NETWORK_LIMITED};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == expected_desirable(ServiceFlags(NODE_NETWORK | NODE_WITNESS)));

    // Make peerman aware of the initial best block and verify we accept limited peers when we start close to the tip time.
    auto tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    uint64_t tip_block_time = tip->GetBlockTime();
    int tip_block_height = tip->nHeight;
    peerman->SetBestBlock(tip_block_height, std::chrono::seconds{tip_block_time});

    SetMockTime(tip_block_time + 1); // Set node time to tip time
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == expected_desirable(ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS)));

    // Check we don't disallow limited peers connections when we are behind but still recoverable (below the connection safety window)
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS - 1)});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == expected_desirable(ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS)));

    // Check we disallow limited peers connections when we are further than the limited peers safety window.
    // Move three spacings ahead so the next Nito-valid block timestamp can advance by two spacings
    // while still remaining outside the limited peer safety window.
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * 3});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == expected_desirable(ServiceFlags(NODE_NETWORK | NODE_WITNESS)));

    // By now, we tested that the connections desirable services flags change based on the node's time proximity to the tip.
    // Now, perform the same tests for when the node receives a block.
    RegisterValidationInterface(peerman.get());

    // First, verify a block in the past doesn't enable limited peers connections
    // At this point, our time is far enough ahead that the next Nito-valid block still looks stale.
    mineBlock(m_node, /*block_time=*/std::chrono::seconds{tip_block_time + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == expected_desirable(ServiceFlags(NODE_NETWORK | NODE_WITNESS)));

    // Verify a block close to the tip enables limited peers connections
    mineBlock(m_node, /*block_time=*/GetTime<std::chrono::seconds>());
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == expected_desirable(ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS)));

    // Lastly, verify the stale tip checks can disallow limited peers connections after not receiving blocks for a prolonged period.
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == expected_desirable(ServiceFlags(NODE_NETWORK | NODE_WITNESS)));
}

BOOST_AUTO_TEST_SUITE_END()
