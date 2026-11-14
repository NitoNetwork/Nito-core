// Copyright (c) 2017-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <consensus/private_tx_verify.h>
#include <consensus/tx_verify.h>
#include <key_io.h>
#include <policy/v3_policy.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <private/private_state.h>
#include <private/orchard_verifier.h>
#include <primitives/private_transaction.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_AUTO_TEST_SUITE(txvalidation_tests)

/**
 * Ensure that the mempool won't accept coinbase transactions.
 */
BOOST_FIXTURE_TEST_CASE(tx_mempool_reject_coinbase, TestChain100Setup)
{
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CMutableTransaction coinbaseTx;

    coinbaseTx.nVersion = 1;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vout.resize(1);
    coinbaseTx.vin[0].scriptSig = CScript() << OP_11 << OP_EQUAL;
    coinbaseTx.vout[0].nValue = 1 * CENT;
    coinbaseTx.vout[0].scriptPubKey = scriptPubKey;

    BOOST_CHECK(CTransaction(coinbaseTx).IsCoinBase());

    LOCK(cs_main);

    unsigned int initialPoolSize = m_node.mempool->size();
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(coinbaseTx));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);

    // Check that the transaction hasn't been added to mempool.
    BOOST_CHECK_EQUAL(m_node.mempool->size(), initialPoolSize);

    // Check that the validation state reflects the unsuccessful attempt.
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "coinbase");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

// Generate a number of random, nonexistent outpoints.
static inline std::vector<COutPoint> random_outpoints(size_t num_outpoints) {
    std::vector<COutPoint> outpoints;
    for (size_t i{0}; i < num_outpoints; ++i) {
        outpoints.emplace_back(Txid::FromUint256(GetRandHash()), 0);
    }
    return outpoints;
}

static inline std::vector<CPubKey> random_keys(size_t num_keys) {
    std::vector<CPubKey> keys;
    keys.reserve(num_keys);
    for (size_t i{0}; i < num_keys; ++i) {
        CKey key;
        key.MakeNewKey(true);
        keys.emplace_back(key.GetPubKey());
    }
    return keys;
}

// Creates a placeholder tx (not valid) with 25 outputs. Specify the nVersion and the inputs.
static inline CTransactionRef make_tx(const std::vector<COutPoint>& inputs, int32_t version)
{
    CMutableTransaction mtx = CMutableTransaction{};
    mtx.nVersion = version;
    mtx.vin.resize(inputs.size());
    mtx.vout.resize(25);
    for (size_t i{0}; i < inputs.size(); ++i) {
        mtx.vin[i].prevout = inputs[i];
    }
    for (auto i{0}; i < 25; ++i) {
        mtx.vout[i].scriptPubKey = CScript() << OP_TRUE;
        mtx.vout[i].nValue = 10000;
    }
    return MakeTransactionRef(mtx);
}

static CPrivateActionEffects MakePrivateSanityAction(uint8_t tag)
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

static CPrivateBundle MakePrivateSanityBundle(size_t action_count, size_t proof_size)
{
    CPrivateBundle bundle;
    for (size_t i{0}; i < action_count; ++i) {
        bundle.effects.actions.push_back(MakePrivateSanityAction(static_cast<uint8_t>(i + 1)));
    }
    bundle.auth.emplace();
    bundle.auth->binding_sig.assign(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE, 1);
    bundle.auth->proof.assign(proof_size, 2);
    bundle.auth->actions_auth.resize(action_count);
    for (auto& action_auth : bundle.auth->actions_auth) {
        action_auth.spend_auth_sig.assign(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE, 3);
    }
    return bundle;
}

BOOST_AUTO_TEST_CASE(private_orchard_proof_size_sanity)
{
    BOOST_CHECK_EQUAL(PrivateOrchardExpectedProofSize(1), 4992);
    BOOST_CHECK_EQUAL(PrivateOrchardExpectedProofSize(2), 7264);

    {
        TxValidationState state;
        const CPrivateBundle bundle{MakePrivateSanityBundle(2, PrivateOrchardExpectedProofSize(2))};
        BOOST_CHECK(CheckPrivateBundleSanity(bundle, state));
    }

    {
        TxValidationState state;
        const CPrivateBundle bundle{MakePrivateSanityBundle(2, PrivateOrchardExpectedProofSize(2) + 1)};
        BOOST_CHECK(!CheckPrivateBundleSanity(bundle, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-private-proof-size");
    }

    {
        TxValidationState state;
        const CPrivateBundle bundle{MakePrivateSanityBundle(2, PrivateOrchardExpectedProofSize(2) - 1)};
        BOOST_CHECK(!CheckPrivateBundleSanity(bundle, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-private-proof-size");
    }
}

BOOST_AUTO_TEST_CASE(private_orchard_verifier_rejects_malformed_buffers_before_ffi)
{
    auto check_rejected = [](CPrivateBundle bundle, const std::string& expected_error) {
        CMutableTransaction mtx;
        mtx.m_private_bundle = std::move(bundle);
        std::string error;
        BOOST_CHECK(VerifyPrivateOrchardBundle(CTransaction{mtx}, error) == PrivateOrchardVerifyResult::BadEncoding);
        BOOST_CHECK_EQUAL(error, expected_error);
    };

    {
        CPrivateBundle bundle{MakePrivateSanityBundle(1, PrivateOrchardExpectedProofSize(1))};
        bundle.effects.actions[0].ephemeral_key = std::vector<unsigned char>(PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE - 1, 1);
        check_rejected(std::move(bundle), "private verifier ephemeral key size mismatch");
    }
    {
        CPrivateBundle bundle{MakePrivateSanityBundle(1, PrivateOrchardExpectedProofSize(1))};
        bundle.effects.actions[0].enc_ciphertext = std::vector<unsigned char>(PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE - 1, 1);
        check_rejected(std::move(bundle), "private verifier encrypted ciphertext size mismatch");
    }
    {
        CPrivateBundle bundle{MakePrivateSanityBundle(1, PrivateOrchardExpectedProofSize(1))};
        bundle.effects.actions[0].out_ciphertext = std::vector<unsigned char>(PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE - 1, 1);
        check_rejected(std::move(bundle), "private verifier outgoing ciphertext size mismatch");
    }
    {
        CPrivateBundle bundle{MakePrivateSanityBundle(1, PrivateOrchardExpectedProofSize(1))};
        bundle.auth->actions_auth[0].spend_auth_sig = std::vector<unsigned char>(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE - 1, 1);
        check_rejected(std::move(bundle), "private verifier spend authorization size mismatch");
    }
    {
        CPrivateBundle bundle{MakePrivateSanityBundle(1, PrivateOrchardExpectedProofSize(1))};
        bundle.auth->proof = std::vector<unsigned char>(PrivateOrchardExpectedProofSize(1) - 1, 1);
        check_rejected(std::move(bundle), "private verifier proof size mismatch");
    }
    {
        CPrivateBundle bundle{MakePrivateSanityBundle(1, PrivateOrchardExpectedProofSize(1))};
        bundle.auth->binding_sig = std::vector<unsigned char>(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE - 1, 1);
        check_rejected(std::move(bundle), "private verifier binding signature size mismatch");
    }
}

BOOST_AUTO_TEST_CASE(private_orchard_engine_failure_is_not_consensus_invalidity)
{
    TxValidationState engine_state;
    BOOST_CHECK(!SetPrivateBundleProofValidationState(PrivateOrchardVerifyResult::EngineError, "ffi unavailable", engine_state));
    BOOST_CHECK(engine_state.IsError());
    BOOST_CHECK(!engine_state.IsInvalid());
    BOOST_CHECK_EQUAL(engine_state.GetRejectReason(), "private-orchard-engine: ffi unavailable");

    TxValidationState proof_state;
    BOOST_CHECK(!SetPrivateBundleProofValidationState(PrivateOrchardVerifyResult::BadProof, "invalid proof", proof_state));
    BOOST_CHECK(proof_state.IsInvalid());
    BOOST_CHECK(!proof_state.IsError());
    BOOST_CHECK(proof_state.GetResult() == TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(proof_state.GetRejectReason(), "bad-private-orchard-proof");
}

BOOST_AUTO_TEST_CASE(private_orchard_proof_verification_can_be_deferred)
{
    CMutableTransaction mtx;
    mtx.m_private_bundle = MakePrivateSanityBundle(1, PrivateOrchardExpectedProofSize(1));
    mtx.m_private_bundle->effects.value_balance = -1;
    const CTransaction tx{mtx};
    CCoinsView base;
    CCoinsViewCache inputs{&base};
    CAmount fee{0};

    ResetPrivateOrchardProofVerificationCount();
    TxValidationState deferred_state;
    BOOST_CHECK(!Consensus::CheckTxInputs(
        tx,
        deferred_state,
        inputs,
        /*nSpendHeight=*/1,
        fee,
        /*check_private_proofs=*/false));
    BOOST_CHECK_EQUAL(deferred_state.GetRejectReason(), "bad-txns-in-belowout");
    BOOST_CHECK_EQUAL(GetPrivateOrchardProofVerificationCount(), 0);

    TxValidationState proof_state;
    BOOST_CHECK(!Consensus::CheckTxInputs(
        tx,
        proof_state,
        inputs,
        /*nSpendHeight=*/1,
        fee,
        /*check_private_proofs=*/true));
    BOOST_CHECK_EQUAL(GetPrivateOrchardProofVerificationCount(), 1);
}

BOOST_AUTO_TEST_CASE(private_orchard_proof_cache_reuses_only_exact_valid_authorization)
{
    std::array<unsigned char, 32> spending_key{};
    spending_key[0] = 1;
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> recipient_raw{};
    std::string error;
    BOOST_REQUIRE(DerivePrivateOrchardRawAddress(
        Span<const unsigned char>{spending_key.data(), spending_key.size()},
        /*diversifier_index=*/0,
        recipient_raw,
        error) == PrivateOrchardBuildResult::OK);

    uint256 anchor;
    BOOST_REQUIRE(GetPrivateEmptyRoot(anchor, error));

    CMutableTransaction mtx;
    auto sighash_callback = [&mtx](const CPrivateBundle& effects_bundle, uint256& sighash_out, std::string& sighash_error) {
        CMutableTransaction sighash_tx{mtx};
        sighash_tx.m_private_bundle = effects_bundle;
        sighash_out = PrivateBundleSighash(sighash_tx);
        sighash_error.clear();
        return true;
    };
    CPrivateBundle bundle;
    BOOST_REQUIRE(BuildPrivateOrchardOutputBundleWithSighashCallback(
        Span<const unsigned char>{recipient_raw.data(), recipient_raw.size()},
        /*value=*/1,
        anchor,
        sighash_callback,
        bundle,
        error) == PrivateOrchardBuildResult::OK);
    mtx.m_private_bundle = std::move(bundle);
    const CTransaction tx{mtx};

    BOOST_REQUIRE(InitPrivateOrchardProofCache(/*max_size_bytes=*/1 << 20));
    ResetPrivateOrchardProofVerificationCount();

    TxValidationState first_state;
    BOOST_REQUIRE(CheckPrivateBundleProofs(tx, first_state, PrivateProofCacheMode::STORE));
    BOOST_CHECK_EQUAL(GetPrivateOrchardProofVerificationCount(), 1);

    TxValidationState retained_state;
    BOOST_REQUIRE(CheckPrivateBundleProofs(tx, retained_state, PrivateProofCacheMode::STORE));
    BOOST_CHECK_EQUAL(GetPrivateOrchardProofVerificationCount(), 1);

    TxValidationState consumed_state;
    BOOST_REQUIRE(CheckPrivateBundleProofs(tx, consumed_state, PrivateProofCacheMode::ERASE));
    BOOST_CHECK_EQUAL(GetPrivateOrchardProofVerificationCount(), 1);

    TxValidationState miss_after_consume_state;
    BOOST_REQUIRE(CheckPrivateBundleProofs(tx, miss_after_consume_state, PrivateProofCacheMode::ERASE));
    // CuckooCache consumption marks the entry as replaceable rather than
    // deleting it synchronously, matching the signature-cache semantics.
    BOOST_CHECK_EQUAL(GetPrivateOrchardProofVerificationCount(), 1);

    CMutableTransaction altered_auth{tx};
    altered_auth.m_private_bundle->auth->proof[0] ^= 1;
    TxValidationState altered_state;
    BOOST_CHECK(!CheckPrivateBundleProofs(CTransaction{altered_auth}, altered_state, PrivateProofCacheMode::STORE));
    BOOST_CHECK_EQUAL(GetPrivateOrchardProofVerificationCount(), 2);
}

BOOST_AUTO_TEST_CASE(private_orchard_cpu_cost_is_priced_and_bounded_by_block_weight)
{
    BOOST_CHECK_EQUAL(GetPrivateOrchardVerificationCost(std::numeric_limits<size_t>::max()),
                      std::numeric_limits<int64_t>::max());

    CMutableTransaction one_action;
    one_action.m_private_bundle = MakePrivateSanityBundle(1, PrivateOrchardExpectedProofSize(1));
    const CTransaction one_action_tx{one_action};
    BOOST_CHECK_EQUAL(GetPrivateOrchardVerificationCost(/*action_count=*/1), 6000);
    BOOST_CHECK_EQUAL(GetVirtualTransactionSize(one_action_tx), 6000);
    const CTxMemPoolEntry one_action_entry{
        MakeTransactionRef(one_action_tx),
        /*fee=*/0,
        /*time=*/0,
        /*entry_height=*/0,
        /*entry_sequence=*/0,
        /*spends_coinbase=*/false,
        /*sigops_cost=*/0,
        LockPoints{}};
    BOOST_CHECK_EQUAL(one_action_entry.GetTxSize(), 6000);

    CMutableTransaction ten_actions;
    ten_actions.m_private_bundle = MakePrivateSanityBundle(10, PrivateOrchardExpectedProofSize(10));
    const CTransaction ten_action_tx{ten_actions};
    BOOST_CHECK_EQUAL(GetPrivateOrchardVerificationCost(/*action_count=*/10), 15000);
    BOOST_CHECK_EQUAL(GetVirtualTransactionSize(ten_action_tx), 15000);

    CMutableTransaction fifty_actions;
    fifty_actions.m_private_bundle = MakePrivateSanityBundle(50, PrivateOrchardExpectedProofSize(50));
    const CTransaction fifty_action_tx{fifty_actions};
    BOOST_CHECK_GT(GetVirtualTransactionSize(fifty_action_tx), GetPrivateOrchardVerificationCost(/*action_count=*/50));

    // A one-action bundle has the highest verification-cost/weight ratio.
    // For every currently valid action count, its real serialized weight is
    // sufficient to keep a full block below the explicit Orchard CPU bound.
    for (size_t action_count{1}; action_count <= MAX_PRIVATE_ORCHARD_ACTIONS; ++action_count) {
        CMutableTransaction candidate;
        candidate.m_private_bundle = MakePrivateSanityBundle(action_count, PrivateOrchardExpectedProofSize(action_count));
        const int64_t weight{GetTransactionWeight(CTransaction{candidate})};
        const int64_t cost{GetPrivateOrchardVerificationCost(action_count)};
        BOOST_CHECK_LE(cost * 8662, weight * 6000);
    }
    BOOST_CHECK_LE((static_cast<int64_t>(MAX_BLOCK_WEIGHT) * 6000 + 8661) / 8662,
                   MAX_BLOCK_PRIVATE_ORCHARD_VERIFY_COST);
}

BOOST_AUTO_TEST_CASE(private_orchard_network_proof_verification_rate_is_bounded)
{
    const auto start{std::chrono::microseconds{0}};
    PrivateOrchardProofRateLimiter limiter{start};
    const int64_t maximum_transaction_cost{
        GetPrivateOrchardVerificationCost(MAX_PRIVATE_ORCHARD_ACTIONS)};

    BOOST_CHECK(limiter.TryAcquire(maximum_transaction_cost, start));
    BOOST_CHECK(limiter.TryAcquire(maximum_transaction_cost, start));
    BOOST_CHECK(!limiter.TryAcquire(maximum_transaction_cost, start));

    const auto one_second_later{start + std::chrono::seconds{1}};
    BOOST_CHECK(limiter.TryAcquire(maximum_transaction_cost, one_second_later));
    BOOST_CHECK(!limiter.TryAcquire(maximum_transaction_cost, one_second_later));

    // A backwards clock adjustment must not mint verification capacity.
    BOOST_CHECK(!limiter.TryAcquire(maximum_transaction_cost, start));
}

struct PrivateActivatedChain100Setup : TestChain100Setup {
    PrivateActivatedChain100Setup()
        : TestChain100Setup{ChainType::REGTEST, {"-privateactivationheight=1"}}
    {
    }
};

BOOST_FIXTURE_TEST_CASE(private_underfee_auth_variants_never_verify_orchard_proofs, PrivateActivatedChain100Setup)
{
    const CTransactionRef& funding{m_coinbase_txns.front()};
    CScript destination{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    CMutableTransaction underfee{CreateValidMempoolTransaction(
        funding,
        /*input_vout=*/0,
        /*input_height=*/0,
        coinbaseKey,
        destination,
        /*output_amount=*/funding->vout[0].nValue,
        /*submit=*/false)};

    underfee.m_private_bundle = MakePrivateSanityBundle(1, PrivateOrchardExpectedProofSize(1));
    std::string root_error;
    BOOST_REQUIRE(GetPrivateEmptyRoot(underfee.m_private_bundle->effects.anchor, root_error));
    underfee.m_private_bundle->effects.value_balance = 0;

    ResetPrivateOrchardProofVerificationCount();
    constexpr uint32_t AUTH_VARIANTS{512};
    for (uint32_t variant{0}; variant < AUTH_VARIANTS; ++variant) {
        CMutableTransaction candidate{underfee};
        auto& auth{*candidate.m_private_bundle->auth};
        auth.binding_sig[0] = static_cast<unsigned char>(variant);
        auth.binding_sig[1] = static_cast<unsigned char>(variant >> 8);
        auth.actions_auth[0].spend_auth_sig[0] = static_cast<unsigned char>(variant ^ 0xa5);

        const MempoolAcceptResult result{WITH_LOCK(
            cs_main,
            return m_node.chainman->ProcessTransaction(MakeTransactionRef(candidate)))};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "min relay fee not met");
        BOOST_CHECK_EQUAL(GetPrivateOrchardProofVerificationCount(), 0);
    }
}

BOOST_AUTO_TEST_CASE(private_value_pool_transition_invariants)
{
    CAmount connected_value_pool{0};
    std::string error;

    BOOST_CHECK(CheckPrivateValuePoolTransition(/*previous_value_pool=*/0, /*private_value_balance=*/-10 * COIN, connected_value_pool, error));
    BOOST_CHECK_EQUAL(connected_value_pool, 10 * COIN);

    BOOST_CHECK(CheckPrivateValuePoolTransition(/*previous_value_pool=*/10 * COIN, /*private_value_balance=*/3 * COIN, connected_value_pool, error));
    BOOST_CHECK_EQUAL(connected_value_pool, 7 * COIN);

    BOOST_CHECK(CheckPrivateValuePoolTransition(/*previous_value_pool=*/10 * COIN, /*private_value_balance=*/0, connected_value_pool, error));
    BOOST_CHECK_EQUAL(connected_value_pool, 10 * COIN);

    BOOST_CHECK(!CheckPrivateValuePoolTransition(/*previous_value_pool=*/0, /*private_value_balance=*/1, connected_value_pool, error));
    BOOST_CHECK_EQUAL(error, "private value pool would become negative");

    BOOST_CHECK(!CheckPrivateValuePoolTransition(/*previous_value_pool=*/-1, /*private_value_balance=*/0, connected_value_pool, error));
    BOOST_CHECK_EQUAL(error, "private value pool previous amount out of range");

    BOOST_CHECK(!CheckPrivateValuePoolTransition(/*previous_value_pool=*/MAX_MONEY + 1, /*private_value_balance=*/0, connected_value_pool, error));
    BOOST_CHECK_EQUAL(error, "private value pool previous amount out of range");

    BOOST_CHECK(!CheckPrivateValuePoolTransition(/*previous_value_pool=*/MAX_MONEY, /*private_value_balance=*/-1, connected_value_pool, error));
    BOOST_CHECK_EQUAL(error, "private value pool exceeds money range");

    BOOST_CHECK(!CheckPrivateValuePoolTransition(/*previous_value_pool=*/0, /*private_value_balance=*/MAX_MONEY + 1, connected_value_pool, error));
    BOOST_CHECK_EQUAL(error, "private value balance out of range");
}

BOOST_FIXTURE_TEST_CASE(version3_tests, RegTestingSetup)
{
    // Test V3 policy helper functions
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    std::set<Txid> empty_conflicts_set;
    CTxMemPool::setEntries empty_ancestors;

    auto mempool_tx_v3 = make_tx(random_outpoints(1), /*version=*/3);
    pool.addUnchecked(entry.FromTx(mempool_tx_v3));
    auto mempool_tx_v2 = make_tx(random_outpoints(1), /*version=*/2);
    pool.addUnchecked(entry.FromTx(mempool_tx_v2));
    // Default values.
    CTxMemPool::Limits m_limits{};

    // Cannot spend from an unconfirmed v3 transaction unless this tx is also v3.
    {
        // mempool_tx_v3
        //      ^
        // tx_v2_from_v3
        auto tx_v2_from_v3 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}}, /*version=*/2);
        auto ancestors_v2_from_v3{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v2_from_v3), m_limits)};
        const auto expected_error_str{strprintf("non-v3 tx %s (wtxid=%s) cannot spend from v3 tx %s (wtxid=%s)",
            tx_v2_from_v3->GetHash().ToString(), tx_v2_from_v3->GetWitnessHash().ToString(),
            mempool_tx_v3->GetHash().ToString(), mempool_tx_v3->GetWitnessHash().ToString())};
        BOOST_CHECK(*SingleV3Checks(tx_v2_from_v3, *ancestors_v2_from_v3, empty_conflicts_set, GetVirtualTransactionSize(*tx_v2_from_v3)) == expected_error_str);

        Package package_v3_v2{mempool_tx_v3, tx_v2_from_v3};
        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_v2_from_v3, GetVirtualTransactionSize(*tx_v2_from_v3), package_v3_v2, empty_ancestors), expected_error_str);
        CTxMemPool::setEntries entries_mempool_v3{pool.GetIter(mempool_tx_v3->GetHash().ToUint256()).value()};
        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_v2_from_v3, GetVirtualTransactionSize(*tx_v2_from_v3), {tx_v2_from_v3}, entries_mempool_v3), expected_error_str);

        // mempool_tx_v3  mempool_tx_v2
        //            ^    ^
        //    tx_v2_from_v2_and_v3
        auto tx_v2_from_v2_and_v3 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}, COutPoint{mempool_tx_v2->GetHash(), 0}}, /*version=*/2);
        auto ancestors_v2_from_both{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v2_from_v2_and_v3), m_limits)};
        const auto expected_error_str_2{strprintf("non-v3 tx %s (wtxid=%s) cannot spend from v3 tx %s (wtxid=%s)",
            tx_v2_from_v2_and_v3->GetHash().ToString(), tx_v2_from_v2_and_v3->GetWitnessHash().ToString(),
            mempool_tx_v3->GetHash().ToString(), mempool_tx_v3->GetWitnessHash().ToString())};
        BOOST_CHECK(*SingleV3Checks(tx_v2_from_v2_and_v3, *ancestors_v2_from_both, empty_conflicts_set, GetVirtualTransactionSize(*tx_v2_from_v2_and_v3))
                    == expected_error_str_2);

        Package package_v3_v2_v2{mempool_tx_v3, mempool_tx_v2, tx_v2_from_v2_and_v3};
        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_v2_from_v2_and_v3, GetVirtualTransactionSize(*tx_v2_from_v2_and_v3), package_v3_v2_v2, empty_ancestors), expected_error_str_2);
    }

    // V3 cannot spend from an unconfirmed non-v3 transaction.
    {
        // mempool_tx_v2
        //      ^
        // tx_v3_from_v2
        auto tx_v3_from_v2 = make_tx({COutPoint{mempool_tx_v2->GetHash(), 0}}, /*version=*/3);
        auto ancestors_v3_from_v2{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_from_v2), m_limits)};
        const auto expected_error_str{strprintf("v3 tx %s (wtxid=%s) cannot spend from non-v3 tx %s (wtxid=%s)",
            tx_v3_from_v2->GetHash().ToString(), tx_v3_from_v2->GetWitnessHash().ToString(),
            mempool_tx_v2->GetHash().ToString(), mempool_tx_v2->GetWitnessHash().ToString())};
        BOOST_CHECK(*SingleV3Checks(tx_v3_from_v2, *ancestors_v3_from_v2,  empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_from_v2)) == expected_error_str);

        Package package_v2_v3{mempool_tx_v2, tx_v3_from_v2};
        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_v3_from_v2, GetVirtualTransactionSize(*tx_v3_from_v2), package_v2_v3, empty_ancestors), expected_error_str);
        CTxMemPool::setEntries entries_mempool_v2{pool.GetIter(mempool_tx_v2->GetHash().ToUint256()).value()};
        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_v3_from_v2, GetVirtualTransactionSize(*tx_v3_from_v2), {tx_v3_from_v2}, entries_mempool_v2), expected_error_str);

        // mempool_tx_v3  mempool_tx_v2
        //            ^    ^
        //    tx_v3_from_v2_and_v3
        auto tx_v3_from_v2_and_v3 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}, COutPoint{mempool_tx_v2->GetHash(), 0}}, /*version=*/3);
        auto ancestors_v3_from_both{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_from_v2_and_v3), m_limits)};
        const auto expected_error_str_2{strprintf("v3 tx %s (wtxid=%s) cannot spend from non-v3 tx %s (wtxid=%s)",
            tx_v3_from_v2_and_v3->GetHash().ToString(), tx_v3_from_v2_and_v3->GetWitnessHash().ToString(),
            mempool_tx_v2->GetHash().ToString(), mempool_tx_v2->GetWitnessHash().ToString())};
        BOOST_CHECK(*SingleV3Checks(tx_v3_from_v2_and_v3, *ancestors_v3_from_both, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_from_v2_and_v3))
                    == expected_error_str_2);

        // tx_v3_from_v2_and_v3 also violates V3_ANCESTOR_LIMIT.
        const auto expected_error_str_3{strprintf("tx %s (wtxid=%s) would have too many ancestors",
            tx_v3_from_v2_and_v3->GetHash().ToString(), tx_v3_from_v2_and_v3->GetWitnessHash().ToString())};
        Package package_v3_v2_v3{mempool_tx_v3, mempool_tx_v2, tx_v3_from_v2_and_v3};
        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_v3_from_v2_and_v3, GetVirtualTransactionSize(*tx_v3_from_v2_and_v3), package_v3_v2_v3, empty_ancestors), expected_error_str_3);
    }
    // V3 from V3 is ok, and non-V3 from non-V3 is ok.
    {
        // mempool_tx_v3
        //      ^
        // tx_v3_from_v3
        auto tx_v3_from_v3 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}}, /*version=*/3);
        auto ancestors_v3{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_from_v3), m_limits)};
        BOOST_CHECK(SingleV3Checks(tx_v3_from_v3, *ancestors_v3, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_from_v3))
                    == std::nullopt);

        Package package_v3_v3{mempool_tx_v3, tx_v3_from_v3};
        BOOST_CHECK(PackageV3Checks(tx_v3_from_v3, GetVirtualTransactionSize(*tx_v3_from_v3), package_v3_v3, empty_ancestors) == std::nullopt);

        // mempool_tx_v2
        //      ^
        // tx_v2_from_v2
        auto tx_v2_from_v2 = make_tx({COutPoint{mempool_tx_v2->GetHash(), 0}}, /*version=*/2);
        auto ancestors_v2{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v2_from_v2), m_limits)};
        BOOST_CHECK(SingleV3Checks(tx_v2_from_v2, *ancestors_v2, empty_conflicts_set, GetVirtualTransactionSize(*tx_v2_from_v2))
                    == std::nullopt);

        Package package_v2_v2{mempool_tx_v2, tx_v2_from_v2};
        BOOST_CHECK(PackageV3Checks(tx_v2_from_v2, GetVirtualTransactionSize(*tx_v2_from_v2), package_v2_v2, empty_ancestors) == std::nullopt);
    }

    // Tx spending v3 cannot have too many mempool ancestors
    // Configuration where the tx has multiple direct parents.
    {
        Package package_multi_parents;
        std::vector<COutPoint> mempool_outpoints;
        mempool_outpoints.emplace_back(mempool_tx_v3->GetHash(), 0);
        package_multi_parents.emplace_back(mempool_tx_v3);
        for (size_t i{0}; i < 2; ++i) {
            auto mempool_tx = make_tx(random_outpoints(i + 1), /*version=*/3);
            pool.addUnchecked(entry.FromTx(mempool_tx));
            mempool_outpoints.emplace_back(mempool_tx->GetHash(), 0);
            package_multi_parents.emplace_back(mempool_tx);
        }
        auto tx_v3_multi_parent = make_tx(mempool_outpoints, /*version=*/3);
        package_multi_parents.emplace_back(tx_v3_multi_parent);
        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_multi_parent), m_limits)};
        BOOST_CHECK_EQUAL(ancestors->size(), 3);
        const auto expected_error_str{strprintf("tx %s (wtxid=%s) would have too many ancestors",
            tx_v3_multi_parent->GetHash().ToString(), tx_v3_multi_parent->GetWitnessHash().ToString())};
        BOOST_CHECK_EQUAL(*SingleV3Checks(tx_v3_multi_parent, *ancestors, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_multi_parent)),
                          expected_error_str);

        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_v3_multi_parent, GetVirtualTransactionSize(*tx_v3_multi_parent), package_multi_parents, empty_ancestors),
                          expected_error_str);
    }

    // Configuration where the tx is in a multi-generation chain.
    {
        Package package_multi_gen;
        CTransactionRef middle_tx;
        auto last_outpoint{random_outpoints(1)[0]};
        for (size_t i{0}; i < 2; ++i) {
            auto mempool_tx = make_tx({last_outpoint}, /*version=*/3);
            pool.addUnchecked(entry.FromTx(mempool_tx));
            last_outpoint = COutPoint{mempool_tx->GetHash(), 0};
            package_multi_gen.emplace_back(mempool_tx);
            if (i == 1) middle_tx = mempool_tx;
        }
        auto tx_v3_multi_gen = make_tx({last_outpoint}, /*version=*/3);
        package_multi_gen.emplace_back(tx_v3_multi_gen);
        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_multi_gen), m_limits)};
        const auto expected_error_str{strprintf("tx %s (wtxid=%s) would have too many ancestors",
            tx_v3_multi_gen->GetHash().ToString(), tx_v3_multi_gen->GetWitnessHash().ToString())};
        BOOST_CHECK_EQUAL(*SingleV3Checks(tx_v3_multi_gen, *ancestors, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_multi_gen)),
                          expected_error_str);

        // Middle tx is what triggers a failure for the grandchild:
        BOOST_CHECK_EQUAL(*PackageV3Checks(middle_tx, GetVirtualTransactionSize(*middle_tx), package_multi_gen, empty_ancestors), expected_error_str);
        BOOST_CHECK(PackageV3Checks(tx_v3_multi_gen, GetVirtualTransactionSize(*tx_v3_multi_gen), package_multi_gen, empty_ancestors) == std::nullopt);
    }

    // Tx spending v3 cannot be too large in virtual size.
    auto many_inputs{random_outpoints(100)};
    many_inputs.emplace_back(mempool_tx_v3->GetHash(), 0);
    {
        auto tx_v3_child_big = make_tx(many_inputs, /*version=*/3);
        const auto vsize{GetVirtualTransactionSize(*tx_v3_child_big)};
        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_child_big), m_limits)};
        const auto expected_error_str{strprintf("v3 child tx %s (wtxid=%s) is too big: %u > %u virtual bytes",
            tx_v3_child_big->GetHash().ToString(), tx_v3_child_big->GetWitnessHash().ToString(), vsize, V3_CHILD_MAX_VSIZE)};
        BOOST_CHECK_EQUAL(*SingleV3Checks(tx_v3_child_big, *ancestors, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_child_big)),
                          expected_error_str);

        Package package_child_big{mempool_tx_v3, tx_v3_child_big};
        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_v3_child_big, GetVirtualTransactionSize(*tx_v3_child_big), package_child_big, empty_ancestors),
                          expected_error_str);
    }

    // Tx spending v3 cannot have too many sigops.
    // This child has 10 P2WSH multisig inputs.
    auto multisig_outpoints{random_outpoints(10)};
    multisig_outpoints.emplace_back(mempool_tx_v3->GetHash(), 0);
    auto keys{random_keys(2)};
    CScript script_multisig;
    script_multisig << OP_1;
    for (const auto& key : keys) {
        script_multisig << ToByteVector(key);
    }
    script_multisig << OP_2 << OP_CHECKMULTISIG;
    {
        CMutableTransaction mtx_many_sigops = CMutableTransaction{};
        mtx_many_sigops.nVersion = 3;
        for (const auto& outpoint : multisig_outpoints) {
            mtx_many_sigops.vin.emplace_back(outpoint);
            mtx_many_sigops.vin.back().scriptWitness.stack.emplace_back(script_multisig.begin(), script_multisig.end());
        }
        mtx_many_sigops.vout.resize(1);
        mtx_many_sigops.vout.back().scriptPubKey = CScript() << OP_TRUE;
        mtx_many_sigops.vout.back().nValue = 10000;
        auto tx_many_sigops{MakeTransactionRef(mtx_many_sigops)};

        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_many_sigops), m_limits)};
        // legacy uses fAccurate = false, and the maximum number of multisig keys is used
        const int64_t total_sigops{static_cast<int64_t>(tx_many_sigops->vin.size()) * static_cast<int64_t>(script_multisig.GetSigOpCount(/*fAccurate=*/false))};
        BOOST_CHECK_EQUAL(total_sigops, tx_many_sigops->vin.size() * MAX_PUBKEYS_PER_MULTISIG);
        const int64_t bip141_vsize{GetVirtualTransactionSize(*tx_many_sigops)};
        // Weight limit is not reached...
        BOOST_CHECK(SingleV3Checks(tx_many_sigops, *ancestors, empty_conflicts_set, bip141_vsize) == std::nullopt);
        // ...but sigop limit is.
        const auto expected_error_str{strprintf("v3 child tx %s (wtxid=%s) is too big: %u > %u virtual bytes",
            tx_many_sigops->GetHash().ToString(), tx_many_sigops->GetWitnessHash().ToString(),
            total_sigops * DEFAULT_BYTES_PER_SIGOP / WITNESS_SCALE_FACTOR, V3_CHILD_MAX_VSIZE)};
        BOOST_CHECK_EQUAL(*SingleV3Checks(tx_many_sigops, *ancestors, empty_conflicts_set,
                                        GetVirtualTransactionSize(*tx_many_sigops, /*nSigOpCost=*/total_sigops, /*bytes_per_sigop=*/ DEFAULT_BYTES_PER_SIGOP)),
                    expected_error_str);

        Package package_child_sigops{mempool_tx_v3, tx_many_sigops};
        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_many_sigops, total_sigops * DEFAULT_BYTES_PER_SIGOP / WITNESS_SCALE_FACTOR, package_child_sigops, empty_ancestors),
                          expected_error_str);
    }

    // Parent + child with v3 in the mempool. Child is allowed as long as it is under V3_CHILD_MAX_VSIZE.
    auto tx_mempool_v3_child = make_tx({COutPoint{mempool_tx_v3->GetHash(), 0}}, /*version=*/3);
    {
        BOOST_CHECK(GetTransactionWeight(*tx_mempool_v3_child) <= V3_CHILD_MAX_VSIZE * WITNESS_SCALE_FACTOR);
        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_mempool_v3_child), m_limits)};
        BOOST_CHECK(SingleV3Checks(tx_mempool_v3_child, *ancestors, empty_conflicts_set, GetVirtualTransactionSize(*tx_mempool_v3_child)) == std::nullopt);
        pool.addUnchecked(entry.FromTx(tx_mempool_v3_child));

        Package package_v3_1p1c{mempool_tx_v3, tx_mempool_v3_child};
        BOOST_CHECK(PackageV3Checks(tx_mempool_v3_child, GetVirtualTransactionSize(*tx_mempool_v3_child), package_v3_1p1c, empty_ancestors) == std::nullopt);
    }

    // A v3 transaction cannot have more than 1 descendant.
    // Configuration where tx has multiple direct children.
    {
        auto tx_v3_child2 = make_tx({COutPoint{mempool_tx_v3->GetHash(), 1}}, /*version=*/3);
        auto ancestors{pool.CalculateMemPoolAncestors(entry.FromTx(tx_v3_child2), m_limits)};
        const auto expected_error_str{strprintf("tx %s (wtxid=%s) would exceed descendant count limit",
            mempool_tx_v3->GetHash().ToString(), mempool_tx_v3->GetWitnessHash().ToString())};
        BOOST_CHECK_EQUAL(*SingleV3Checks(tx_v3_child2, *ancestors, empty_conflicts_set, GetVirtualTransactionSize(*tx_v3_child2)),
                          expected_error_str);
        // If replacing the child, make sure there is no double-counting.
        BOOST_CHECK(SingleV3Checks(tx_v3_child2, *ancestors, {tx_mempool_v3_child->GetHash()}, GetVirtualTransactionSize(*tx_v3_child2))
                    == std::nullopt);

        Package package_v3_1p2c{mempool_tx_v3, tx_mempool_v3_child, tx_v3_child2};
        BOOST_CHECK_EQUAL(*PackageV3Checks(tx_v3_child2, GetVirtualTransactionSize(*tx_v3_child2), package_v3_1p2c, empty_ancestors),
                          expected_error_str);
    }

    // Configuration where tx has multiple generations of descendants is not tested because that is
    // equivalent to the tx with multiple generations of ancestors.
}

BOOST_AUTO_TEST_SUITE_END()
