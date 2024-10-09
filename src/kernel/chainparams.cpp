// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Nito/Core Genesis 8-4";
    const CScript genesisOutputScript = CScript() << ParseHex("04b337f4030e93f0f931bd78a8643b741245897c800e6e0294eed379c01cb6dc4381b2dd1bfe03f7a6cef7ee6641b2c2ea978f1e89694e19902d13ac7f0a453da0") << OP_CHECKSIG;
    
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 21024000; // 40 years
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256S("0x00"), SCRIPT_VERIFY_NONE);
        consensus.script_flag_exceptions.emplace( // Taproot exception
            uint256S("0x00"), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
        consensus.BIP34Height = 500;
        consensus.BIP34Hash = uint256S("0x000000000004adf966243218249371a3223ace6a1f38ce47ccbe407d8f7db31f");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1; 
        consensus.CSVHeight = 1; 
        consensus.SegwitHeight = 1; 
        consensus.MinBIP9WarningHeight = 1; 
        consensus.powLimit = uint256S("0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90%
        consensus.nMinerConfirmationWindow = 2016; // 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00000000000000235fdb9836cce1353efe564744ab97da7b67b04e4fa38f8515");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb6;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xb6;
        nDefaultPort = 8820;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 2;
        m_assumed_chain_state_size = 2;

        

        genesis = CreateGenesisBlock(1724234444, 3982125265, 0x1d00ffff, 1, 512 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00000000103d1acbedc9bb8ff2af8cb98a751965e784b4e1f978f3d5544c6c3c"));
        assert(genesis.hashMerkleRoot == uint256S("0x90b863a727d4abf9838e8df221052e418d70baf996e2cea3211e8df4da1bb131"));


        vSeeds.emplace_back("1.nitonetwork.org.");
        vSeeds.emplace_back("2.nitonetwork.org.");
        vSeeds.emplace_back("3.nitonode.com.");
        vSeeds.emplace_back("seed.nitonetwork.link.");
        vSeeds.emplace_back("seed.nitopool.fr.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "nito";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 1, uint256S("0x00000000005269c67470137d81d135b81fbaffe8dbc546b15b0299a591b89d16")},
                { 10, uint256S("0x00000000003652db95d9518d9e8f5f0729080cf6cc425e0c65d03faa1d0316dd")},
                { 100, uint256S("0x000000000009e93bc343e97c0ccef77eb6592d98a039d2e15a4157cd5b826138")},
                {1000, uint256S("0x0000000000062f63d314c901d27f867844106121404230b7f1dbff5bf3a3bfac")},
                {5000, uint256S("0x000000000000f4bddf4aa95e25c96410846b06fc6c3ab90ffefe64c291d117e2")},
                {10000, uint256S("0x00000000000000322b892cc337a5c572b1d637aebc2c039784a3ee317651c10c")},
                {11000, uint256S("0x00000000000000636ed5b3c682d8ed61f6fcd0f9315f6f43a171791e7d7756b8")},
                {22000, uint256S("0x000000000000001c460b80c7db3244b9b620ead3eb00916da2aa4cf7da463cda")},
                {33000, uint256S("0x000000000000006eaae87964dd0a674fa82c4b384018bb995ebc517bfea5b5f9")},
                {44000, uint256S("0x000000000000007e192444cf0a245205f687531605e545fe95fed05ac90676f1")},
                {55000, uint256S("0x000000000000000510e1e3c86d4d8194224d6754c53e1c6c85f8ae48d436a905")},
                {66000, uint256S("0x0000000000000086a3f3821354088404f13902313506db7254d975a943c47a08")},

            }
        };


        m_assumeutxo_data = {
            // TODO to be specified in a future patch.
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000000001a0a448d6cf2546b06801389cc030b2b18c6491266815
            .nTime    = 1714772864,
            .nTxCount = 0,
            .dTxRate  = 0,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 21024000; // 40 years
        consensus.script_flag_exceptions.emplace(uint256S("0x0"), SCRIPT_VERIFY_NONE);// BIP16 exception
        consensus.BIP34Height = 500;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1; 
        consensus.BIP66Height = 1; 
        consensus.CSVHeight = 1; 
        consensus.SegwitHeight = 1; 
        consensus.MinBIP9WarningHeight = 1; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00"); // 2550000

        pchMessageStart[0] = 0xb6;
        pchMessageStart[1] = 0xb6;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        nDefaultPort = 8840;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 2;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(1723939322, 2666429272, 0x1d00ffff, 1, 512 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00000000ddbcc1487e98d0e27fcc235129c543e6b6066df0cc0d157a0e02312b"));
        assert(genesis.hashMerkleRoot == uint256S("0x90b863a727d4abf9838e8df221052e418d70baf996e2cea3211e8df4da1bb131"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("t1.nitonetwork.org.");
        vSeeds.emplace_back("t2.nitonetwork.org.");
        vSeeds.emplace_back("t3.nitonode.com.");
        vSeeds.emplace_back("testnet.nitonetwork.link.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tn";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 0, uint256S("0x00000000ddbcc1487e98d0e27fcc235129c543e6b6066df0cc0d157a0e02312b")},
            }
        };

        m_assumeutxo_data = {

        };

        chainTxData = ChainTxData{

        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!options.challenge) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            //vSeeds.emplace_back("seed.nitocoin.com.");

            // Hardcoded nodes can be removed once there are more DNS seeds
            //vSeeds.emplace_back("123.123.123.123");

            consensus.nMinimumChainWork = uint256S("0x00");
            consensus.defaultAssumeValid = uint256S("0x00"); // 180000
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{

            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 21024000; // 40 years
        consensus.BIP34Height = 500;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 8860;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1723968640, 3007861367, 0x1d00ffff, 1, 512 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000000000f6d536ea0023ea9f4ca69d79d80b902aff664e154c028b4d15f320a"));
        assert(genesis.hashMerkleRoot == uint256S("0x90b863a727d4abf9838e8df221052e418d70baf996e2cea3211e8df4da1bb131"));

        vFixedSeeds.clear();

        m_assumeutxo_data = {
            {

            }
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tn";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */

class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 21024000;
        consensus.BIP34Height = 500; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 1;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 8880;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateGenesisBlock(1723968610, 3659418711, 0x1d00ffff, 1, 512 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00000000883439521559eaee4bf336fa07101ccecbd1a1d9eb095f60954f5c0c"));
        assert(genesis.hashMerkleRoot == uint256S("0x90b863a727d4abf9838e8df221052e418d70baf996e2cea3211e8df4da1bb131"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                { 0, uint256S("0x00000000883439521559eaee4bf336fa07101ccecbd1a1d9eb095f60954f5c0c")},

            }
        };

        m_assumeutxo_data = {

        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "nrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}
