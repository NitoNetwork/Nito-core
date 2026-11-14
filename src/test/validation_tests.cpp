// Copyright (c) 2014-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <signet.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>

#include <string>
#include <vector>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(v3_chain_compatibility_parameters)
{
    const auto main_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    BOOST_CHECK_EQUAL(main_params->GetConsensus().nLegacyP2SHActivationHeight, 750000);
    BOOST_CHECK_EQUAL(main_params->GetConsensus().privateTxActivationHeight, 1165432);
    BOOST_CHECK(!Consensus::PrivateTxActive(main_params->GetConsensus(), 1042400));
    BOOST_CHECK(!Consensus::PrivateTxActive(main_params->GetConsensus(), 1165431));
    BOOST_CHECK(Consensus::PrivateTxActive(main_params->GetConsensus(), 1165432));
    BOOST_CHECK(Consensus::PrivateTxActive(main_params->GetConsensus(), 1165433));
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1042399, main_params->GetConsensus()), 256 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1042400, main_params->GetConsensus()), 128 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1165431, main_params->GetConsensus()), 128 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1165432, main_params->GetConsensus()), 128 * COIN);
    BOOST_CHECK_EQUAL(main_params->Checkpoints().GetHeight(), 790000);
    BOOST_CHECK_EQUAL(main_params->Checkpoints().mapCheckpoints.rbegin()->second,
                      uint256S("0x000000000000003313c51ea30df5cce1be4095e6303ddf865516d72a63f9f8fd"));
    BOOST_CHECK_EQUAL(main_params->GenesisBlock().GetHash(),
                      uint256S("0x00000000103d1acbedc9bb8ff2af8cb98a751965e784b4e1f978f3d5544c6c3c"));
    BOOST_CHECK(main_params->MessageStart() == MessageStartChars({0xb6, 0xc0, 0xc0, 0xb6}));

    const auto testnet_params{CreateChainParams(*m_node.args, ChainType::TESTNET)};
    BOOST_CHECK_EQUAL(testnet_params->GetConsensus().nLegacyP2SHActivationHeight, 0);
    BOOST_CHECK_EQUAL(testnet_params->GetConsensus().privateTxActivationHeight, 0);
    BOOST_CHECK(Consensus::PrivateTxActive(testnet_params->GetConsensus(), 0));
    BOOST_CHECK_EQUAL(testnet_params->GetDefaultPort(), 8840);
    BOOST_CHECK_EQUAL(testnet_params->Bech32HRP(), "tn");
    BOOST_CHECK(testnet_params->MessageStart() == MessageStartChars({0xcd, 0x9b, 0x72, 0x1a}));
    BOOST_CHECK(testnet_params->MessageStart() != MessageStartChars({0xb6, 0xb6, 0xb6, 0xdb}));
    BOOST_CHECK(testnet_params->FixedSeeds().empty());
    BOOST_CHECK(testnet_params->DNSSeeds() == std::vector<std::string>({
        "t1.testnet.nito.network.",
        "t2.testnet.nito.network.",
        "t3.testnet.nito.network.",
        "testnet-seed.nito.network.",
    }));
    BOOST_CHECK_EQUAL(testnet_params->Checkpoints().GetHeight(), 0);
    BOOST_CHECK_EQUAL(testnet_params->GenesisBlock().GetHash(),
                      uint256S("0x00000000ddbcc1487e98d0e27fcc235129c543e6b6066df0cc0d157a0e02312b"));

    const auto signet_params{CreateChainParams(*m_node.args, ChainType::SIGNET)};
    BOOST_CHECK_EQUAL(signet_params->GenesisBlock().GetHash(),
                      uint256S("0x000000000f6d536ea0023ea9f4ca69d79d80b902aff664e154c028b4d15f320a"));
    BOOST_CHECK(testnet_params->MessageStart() != signet_params->MessageStart());

    const auto regtest_params{CreateChainParams(*m_node.args, ChainType::REGTEST)};
    BOOST_CHECK_EQUAL(regtest_params->GetConsensus().nLegacyP2SHActivationHeight, 0);
    BOOST_CHECK_EQUAL(regtest_params->Checkpoints().GetHeight(), 0);
    BOOST_CHECK_EQUAL(regtest_params->GenesisBlock().GetHash(),
                      uint256S("0x00000000883439521559eaee4bf336fa07101ccecbd1a1d9eb095f60954f5c0c"));
    BOOST_CHECK(regtest_params->MessageStart() == MessageStartChars({0xfa, 0xbf, 0xb5, 0xda}));
    BOOST_CHECK(testnet_params->MessageStart() != regtest_params->MessageStart());
    BOOST_CHECK(testnet_params->MessageStart() != main_params->MessageStart());
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, consensus), 512 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(529999, consensus), 512 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(530000, consensus), 256 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1042399, consensus), 256 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1042400, consensus), 128 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1576799, consensus), 128 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1576800, consensus), 64 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(5255999, consensus), 64 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(5256000, consensus), 32 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(10511999, consensus), 32 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(10512000, consensus), 16 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(26279999, consensus), 16 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(26280000, consensus), 2 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(105120000, consensus), 2 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(105120001, consensus), 0);
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 14000000; nHeight += 1000) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        BOOST_CHECK(nSubsidy <= 512 * COIN);
        nSum += nSubsidy * 1000;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, CAmount{93049600000000000});
}

BOOST_AUTO_TEST_CASE(signet_parse_tests)
{
    ArgsManager signet_argsman;
    signet_argsman.ForceSetArg("-signetchallenge", "51"); // set challenge to OP_TRUE
    const auto signet_params = CreateChainParams(signet_argsman, ChainType::SIGNET);
    CBlock block;
    BOOST_CHECK(signet_params->GetConsensus().signet_challenge == std::vector<uint8_t>{OP_TRUE});
    CScript challenge{OP_TRUE};

    // empty block is invalid
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no witness commitment
    CMutableTransaction cb;
    cb.vout.emplace_back(0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));
    block.vtx.push_back(MakeTransactionRef(cb)); // Add dummy tx to exercise merkle root code
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no header is treated valid
    std::vector<uint8_t> witness_commitment_section_141{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) {
        witness_commitment_section_141.push_back(0xff);
    }
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no data after header, valid
    std::vector<uint8_t> witness_commitment_section_325{0xec, 0xc7, 0xda, 0xa2};
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Premature end of data, invalid
    witness_commitment_section_325.push_back(0x01);
    witness_commitment_section_325.push_back(0x51);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // has data, valid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Extraneous data, invalid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));
}

//! Test retrieval of valid assumeutxo values.
BOOST_AUTO_TEST_CASE(test_assumeutxo)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    const auto snapshot_hash = AssumeutxoHash{uint256S("0x40ab1706d1e841c7f42ff1a2fd8ac750e5d638ee383cf4f99b4756e7e0213158")};
    const auto snapshot_blockhash = uint256S("0x16a581fc2da8f5ad8594b178a0df854ef88a3a892808b7e1ccfad8ea27deb577");
    const auto snapshot_data = params->AssumeutxoForHeight(110);
    BOOST_REQUIRE(snapshot_data);
    BOOST_CHECK_EQUAL(snapshot_data->height, 110);
    BOOST_CHECK_EQUAL(snapshot_data->hash_serialized.ToString(), snapshot_hash.ToString());
    BOOST_CHECK_EQUAL(snapshot_data->nChainTx, 111);
    BOOST_CHECK_EQUAL(snapshot_data->blockhash.ToString(), snapshot_blockhash.ToString());

    const auto snapshot_data_by_hash = params->AssumeutxoForBlockhash(snapshot_blockhash);
    BOOST_REQUIRE(snapshot_data_by_hash);
    BOOST_CHECK_EQUAL(snapshot_data_by_hash->height, 110);

    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = params->AssumeutxoForHeight(empty);
        BOOST_CHECK(!out);
    }

    BOOST_CHECK(!params->AssumeutxoForBlockhash(uint256S("0x696e92821f65549c7ee134edceeeeaaa4105647a3c4fd9f298c0aec0ab50425c")));
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.fChecked = false;
        block.m_checked_witness_commitment = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        if (include_witness) {
            coinbase.vin[0].scriptWitness.stack.resize(1);
            coinbase.vin[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vin[0].scriptWitness.stack.resize(1);
            mtx.vin[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.vin[0].scriptWitness.stack[0].empty());
            ++mtx.vin[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.vin[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

BOOST_AUTO_TEST_SUITE_END()
