// Copyright (c) 2013-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <hash.h>
#include <primitives/private_transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/data/sighash.json.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <array>
#include <iostream>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

// Old script.cpp SignatureHash function
uint256 static SignatureHashOld(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    if (nIn >= txTo.vin.size())
    {
        return uint256::ONE;
    }
    CMutableTransaction txTmp(txTo);

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    FindAndDelete(scriptCode, CScript(OP_CODESEPARATOR));

    // Blank out other inputs' signatures
    for (unsigned int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCode;

    // Blank out some of the outputs
    if ((nHashType & 0x1f) == SIGHASH_NONE)
    {
        // Wildcard payee
        txTmp.vout.clear();

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        // Only lock-in the txout payee at same index as txin
        unsigned int nOut = nIn;
        if (nOut >= txTmp.vout.size())
        {
            return uint256::ONE;
        }
        txTmp.vout.resize(nOut+1);
        for (unsigned int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (nHashType & SIGHASH_ANYONECANPAY)
    {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }

    // Serialize and hash
    HashWriter ss{};
    ss << TX_NO_WITNESS(txTmp) << nHashType;
    return ss.GetHash();
}

void static RandomScript(CScript &script) {
    static const opcodetype oplist[] = {OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF, OP_VERIF, OP_RETURN, OP_CODESEPARATOR};
    script = CScript();
    int ops = (InsecureRandRange(10));
    for (int i=0; i<ops; i++)
        script << oplist[InsecureRandRange(std::size(oplist))];
}

void static RandomTransaction(CMutableTransaction& tx, bool fSingle)
{
    tx.nVersion = int(InsecureRand32());
    tx.vin.clear();
    tx.vout.clear();
    tx.nLockTime = (InsecureRandBool()) ? InsecureRand32() : 0;
    int ins = (InsecureRandBits(2)) + 1;
    int outs = fSingle ? ins : (InsecureRandBits(2)) + 1;
    for (int in = 0; in < ins; in++) {
        tx.vin.emplace_back();
        CTxIn &txin = tx.vin.back();
        txin.prevout.hash = Txid::FromUint256(InsecureRand256());
        txin.prevout.n = InsecureRandBits(2);
        RandomScript(txin.scriptSig);
        txin.nSequence = (InsecureRandBool()) ? InsecureRand32() : std::numeric_limits<uint32_t>::max();
    }
    for (int out = 0; out < outs; out++) {
        tx.vout.emplace_back();
        CTxOut &txout = tx.vout.back();
        txout.nValue = InsecureRandMoneyAmount();
        RandomScript(txout.scriptPubKey);
    }
}

BOOST_FIXTURE_TEST_SUITE(sighash_tests, BasicTestingSetup)

namespace {

CPrivateBundle MakePrivateSighashBundle()
{
    CPrivateActionEffects action;
    action.cv = uint256S("01");
    action.nullifier = uint256S("02");
    action.rk = uint256S("03");
    action.cmx = uint256S("04");
    action.ephemeral_key.assign(PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE, 0x05);
    action.enc_ciphertext.assign(PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE, 0x06);
    action.out_ciphertext.assign(PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE, 0x07);

    CPrivateBundle bundle;
    bundle.effects.anchor = uint256S("08");
    bundle.effects.value_balance = 9;
    bundle.effects.actions.push_back(std::move(action));
    return bundle;
}

std::vector<CPrivateBundle> MakePrivateSighashMutations(const CPrivateBundle& original)
{
    std::vector<CPrivateBundle> mutations;
    auto add = [&](auto&& mutate) {
        CPrivateBundle changed{original};
        mutate(changed.effects);
        BOOST_REQUIRE(changed.GetEffectsHash() != original.GetEffectsHash());
        mutations.push_back(std::move(changed));
    };

    add([](CPrivateEffects& effects) { ++effects.version; });
    add([](CPrivateEffects& effects) { effects.flags ^= PRIVATE_ORCHARD_OUTPUTS_ENABLED; });
    add([](CPrivateEffects& effects) { effects.anchor = uint256S("09"); });
    add([](CPrivateEffects& effects) { ++effects.value_balance; });
    add([](CPrivateEffects& effects) { ++effects.actions[0].version; });
    add([](CPrivateEffects& effects) { effects.actions[0].cv = uint256S("0a"); });
    add([](CPrivateEffects& effects) { effects.actions[0].nullifier = uint256S("0b"); });
    add([](CPrivateEffects& effects) { effects.actions[0].rk = uint256S("0c"); });
    add([](CPrivateEffects& effects) { effects.actions[0].cmx = uint256S("0d"); });
    add([](CPrivateEffects& effects) { effects.actions[0].ephemeral_key[0] ^= 1; });
    add([](CPrivateEffects& effects) { effects.actions[0].enc_ciphertext[0] ^= 1; });
    add([](CPrivateEffects& effects) { effects.actions[0].out_ciphertext[0] ^= 1; });
    return mutations;
}

} // namespace

BOOST_AUTO_TEST_CASE(private_effects_are_bound_by_all_transparent_sighashes)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 10;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256S("11")), 0}, CScript{}, 12);
    tx.vout.emplace_back(13, CScript{} << OP_TRUE);
    tx.m_private_bundle = MakePrivateSighashBundle();

    const CTxOut spent_output{14, CScript{} << OP_1 << std::vector<unsigned char>(32, 0x15)};
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent_output}, /*force=*/true);

    CMutableTransaction auth_changed{tx};
    auth_changed.m_private_bundle->auth.emplace();
    auth_changed.m_private_bundle->auth->actions_auth.resize(1);
    auth_changed.m_private_bundle->auth->actions_auth[0].spend_auth_sig.assign(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE, 0x16);
    auth_changed.m_private_bundle->auth->proof.assign(PrivateOrchardExpectedProofSize(1), 0x17);
    auth_changed.m_private_bundle->auth->binding_sig.assign(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE, 0x18);

    const std::array<int, 6> ecdsa_hash_types{
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
    };
    const std::array<uint8_t, 7> taproot_hash_types{
        SIGHASH_DEFAULT,
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
    };
    const CScript script_code{CScript{} << OP_DUP << OP_TRUE};
    const auto mutations{MakePrivateSighashMutations(*tx.m_private_bundle)};

    for (const SigVersion sig_version : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        for (const int hash_type : ecdsa_hash_types) {
            const uint256 original{SignatureHash(script_code, tx, 0, hash_type, spent_output.nValue, sig_version, &txdata)};
            const uint256 auth_only{SignatureHash(script_code, auth_changed, 0, hash_type, spent_output.nValue, sig_version)};
            BOOST_CHECK_EQUAL(original, auth_only);

            SigHashCache cache;
            BOOST_CHECK_EQUAL(original, SignatureHash(script_code, tx, 0, hash_type, spent_output.nValue, sig_version, &txdata, &cache));
            BOOST_CHECK_EQUAL(original, SignatureHash(script_code, tx, 0, hash_type, spent_output.nValue, sig_version, &txdata, &cache));

            for (const CPrivateBundle& mutation : mutations) {
                CMutableTransaction changed{tx};
                changed.m_private_bundle = mutation;
                BOOST_CHECK_NE(original, SignatureHash(script_code, changed, 0, hash_type, spent_output.nValue, sig_version));
            }
        }
    }

    for (const uint8_t hash_type : taproot_hash_types) {
        ScriptExecutionData original_exec;
        original_exec.m_annex_init = true;
        original_exec.m_annex_present = false;
        uint256 original;
        BOOST_REQUIRE(SignatureHashSchnorr(original, original_exec, tx, 0, hash_type, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));

        PrecomputedTransactionData auth_data;
        auth_data.Init(auth_changed, std::vector<CTxOut>{spent_output}, /*force=*/true);
        ScriptExecutionData auth_exec;
        auth_exec.m_annex_init = true;
        auth_exec.m_annex_present = false;
        uint256 auth_only;
        BOOST_REQUIRE(SignatureHashSchnorr(auth_only, auth_exec, auth_changed, 0, hash_type, SigVersion::TAPROOT, auth_data, MissingDataBehavior::FAIL));
        BOOST_CHECK_EQUAL(original, auth_only);

        for (const CPrivateBundle& mutation : mutations) {
            CMutableTransaction changed{tx};
            changed.m_private_bundle = mutation;
            PrecomputedTransactionData changed_data;
            changed_data.Init(changed, std::vector<CTxOut>{spent_output}, /*force=*/true);
            ScriptExecutionData changed_exec;
            changed_exec.m_annex_init = true;
            changed_exec.m_annex_present = false;
            uint256 changed_hash;
            BOOST_REQUIRE(SignatureHashSchnorr(changed_hash, changed_exec, changed, 0, hash_type, SigVersion::TAPROOT, changed_data, MissingDataBehavior::FAIL));
            BOOST_CHECK_NE(original, changed_hash);
        }
    }

    CMutableTransaction single_without_output{tx};
    single_without_output.vout.clear();
    const uint256 single_original{SignatureHash(script_code, single_without_output, 0, SIGHASH_SINGLE, spent_output.nValue, SigVersion::BASE)};
    BOOST_CHECK_NE(single_original, uint256::ONE);
    for (const CPrivateBundle& mutation : mutations) {
        CMutableTransaction changed{single_without_output};
        changed.m_private_bundle = mutation;
        BOOST_CHECK_NE(single_original, SignatureHash(script_code, changed, 0, SIGHASH_SINGLE, spent_output.nValue, SigVersion::BASE));
    }
}

BOOST_AUTO_TEST_CASE(sighash_midstate_cache_matches_uncached)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(42, CScript{} << OP_TRUE);
    const CScript script_a{CScript{} << OP_DUP << OP_TRUE};
    const CScript script_b{CScript{} << OP_DROP << OP_TRUE};
    const std::array<int, 10> hash_types{
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        0x21,
        0x42,
        0x63,
        0x83,
    };

    for (const SigVersion sig_version : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        SigHashCache cache;
        for (const int hash_type : hash_types) {
            for (const CScript* script : {&script_a, &script_b}) {
                const uint256 expected{SignatureHash(*script, tx, 0, hash_type, 42, sig_version)};
                BOOST_CHECK(SignatureHash(*script, tx, 0, hash_type, 42, sig_version, nullptr, &cache) == expected);
                // Exercise the cache-hit path as well as the initial store.
                BOOST_CHECK(SignatureHash(*script, tx, 0, hash_type, 42, sig_version, nullptr, &cache) == expected);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(witness_paths_do_not_mix_base_and_witness_sighash_cache)
{
    struct TrackingSignatureChecker final : BaseSignatureChecker {
        mutable int base_checks{0};
        mutable int witness_checks{0};

        bool CheckECDSASignature(const std::vector<unsigned char>&,
                                 const std::vector<unsigned char>&,
                                 const CScript&,
                                 SigVersion sigversion) const override
        {
            if (sigversion == SigVersion::BASE) ++base_checks;
            if (sigversion == SigVersion::WITNESS_V0) ++witness_checks;
            return true;
        }
    };

    std::vector<unsigned char> pubkey(33, 0x11);
    pubkey.front() = 0x02;
    const std::vector<unsigned char> signature{0x01};
    const CScript witness_program{CScript{} << OP_0 << ToByteVector(Hash160(pubkey))};
    const CScript p2sh_program{CScript{} << OP_HASH160 << ToByteVector(Hash160(witness_program)) << OP_EQUAL};
    CScriptWitness witness;
    witness.stack = {signature, pubkey};
    constexpr unsigned int flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS};

    for (const auto& [script_sig, script_pubkey] : std::array<std::pair<CScript, CScript>, 2>{
             std::pair{CScript{}, witness_program},
             std::pair{CScript{} << ToByteVector(witness_program), p2sh_program},
         }) {
        TrackingSignatureChecker checker;
        ScriptError error;
        BOOST_REQUIRE(VerifyScript(script_sig, script_pubkey, &witness, flags, checker, &error));
        BOOST_CHECK_EQUAL(checker.base_checks, 0);
        BOOST_CHECK_EQUAL(checker.witness_checks, 1);
    }
}

BOOST_AUTO_TEST_CASE(sighash_test)
{
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "[\n";
    std::cout << "\t[\"raw_transaction, script, input_index, hashType, signature_hash (result)\"],\n";
    int nRandomTests = 500;
    #else
    int nRandomTests = 50000;
    #endif
    for (int i=0; i<nRandomTests; i++) {
        int nHashType{int(InsecureRand32())};
        CMutableTransaction txTo;
        RandomTransaction(txTo, (nHashType & 0x1f) == SIGHASH_SINGLE);
        CScript scriptCode;
        RandomScript(scriptCode);
        int nIn = InsecureRandRange(txTo.vin.size());

        uint256 sh, sho;
        sho = SignatureHashOld(scriptCode, CTransaction(txTo), nIn, nHashType);
        sh = SignatureHash(scriptCode, txTo, nIn, nHashType, 0, SigVersion::BASE);
        #if defined(PRINT_SIGHASH_JSON)
        DataStream ss;
        ss << TX_WITH_WITNESS(txTo);

        std::cout << "\t[\"" ;
        std::cout << HexStr(ss) << "\", \"";
        std::cout << HexStr(scriptCode) << "\", ";
        std::cout << nIn << ", ";
        std::cout << nHashType << ", \"";
        std::cout << sho.GetHex() << "\"]";
        if (i+1 != nRandomTests) {
          std::cout << ",";
        }
        std::cout << "\n";
        #endif
        BOOST_CHECK(sh == sho);
    }
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "]\n";
    #endif
}

// Goal: check that SignatureHash generates correct hash
BOOST_AUTO_TEST_CASE(sighash_from_data)
{
    UniValue tests = read_json(json_tests::sighash);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        if (test.size() == 1) continue; // comment

        std::string raw_tx, raw_script, sigHashHex;
        int nIn, nHashType;
        uint256 sh;
        CTransactionRef tx;
        CScript scriptCode = CScript();

        try {
          // deserialize test data
          raw_tx = test[0].get_str();
          raw_script = test[1].get_str();
          nIn = test[2].getInt<int>();
          nHashType = test[3].getInt<int>();
          sigHashHex = test[4].get_str();

          DataStream stream(ParseHex(raw_tx));
          stream >> TX_WITH_WITNESS(tx);

          TxValidationState state;
          BOOST_CHECK_MESSAGE(CheckTransaction(*tx, state), strTest);
          BOOST_CHECK(state.IsValid());

          std::vector<unsigned char> raw = ParseHex(raw_script);
          scriptCode.insert(scriptCode.end(), raw.begin(), raw.end());
        } catch (...) {
          BOOST_ERROR("Bad test, couldn't deserialize data: " << strTest);
          continue;
        }

        sh = SignatureHash(scriptCode, *tx, nIn, nHashType, 0, SigVersion::BASE);
        BOOST_CHECK_MESSAGE(sh.GetHex() == sigHashHex, strTest);
    }
}
BOOST_AUTO_TEST_SUITE_END()
