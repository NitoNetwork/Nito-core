// Copyright (c) 2012-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <algorithm>
#include <array>
#include <future>
#include <chrono>
#include <memory>
#include <stdint.h>
#include <vector>

#include <addresstype.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <kernel/chain.h>
#include <node/blockstorage.h>
#include <policy/policy.h>
#include <rpc/server.h>
#include <script/solver.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/bip39.h>
#include <wallet/bip39_seed.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/feebumper.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

using node::MAX_BLOCKFILE_SIZE;

namespace wallet {
RPCHelpMan importmulti();
RPCHelpMan dumpwallet();
RPCHelpMan importwallet();

// Ensure that fee levels defined in the wallet are at least as high
// as the default levels for node policy.
static_assert(DEFAULT_TRANSACTION_MINFEE >= DEFAULT_MIN_RELAY_TX_FEE, "wallet minimum fee is smaller than default relay fee");
static_assert(WALLET_INCREMENTAL_RELAY_FEE >= DEFAULT_INCREMENTAL_RELAY_FEE, "wallet incremental fee is smaller than default incremental relay fee");

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

static bool HasMockRecordType(const MockableData& records, const std::string& expected_type);

BOOST_AUTO_TEST_CASE(bip39_optional_passphrase_vectors)
{
    static const std::string mnemonic{"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"};
    auto to_bytes = [](const BIP39Seed& seed) {
        std::vector<unsigned char> bytes;
        bytes.reserve(seed.size());
        for (const std::byte value : seed) bytes.push_back(std::to_integer<unsigned char>(value));
        return bytes;
    };

    auto implicit_empty{DeriveBIP39SeedFromMnemonic(mnemonic)};
    BOOST_REQUIRE(implicit_empty);
    const SecureString empty_passphrase;
    auto explicit_empty{DeriveBIP39SeedFromMnemonic(mnemonic, empty_passphrase)};
    BOOST_REQUIRE(explicit_empty);
    const auto empty_expected{ParseHex("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")};
    const auto implicit_empty_bytes{to_bytes(*implicit_empty)};
    const auto explicit_empty_bytes{to_bytes(*explicit_empty)};
    BOOST_CHECK_EQUAL_COLLECTIONS(implicit_empty_bytes.begin(), implicit_empty_bytes.end(), empty_expected.begin(), empty_expected.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(explicit_empty_bytes.begin(), explicit_empty_bytes.end(), empty_expected.begin(), empty_expected.end());
    BOOST_CHECK(*implicit_empty == *explicit_empty);

    const SecureString trezor_passphrase{"TREZOR"};
    auto trezor_seed{DeriveBIP39SeedFromMnemonic(mnemonic, trezor_passphrase)};
    BOOST_REQUIRE(trezor_seed);
    const auto trezor_expected{ParseHex("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")};
    const auto trezor_bytes{to_bytes(*trezor_seed)};
    BOOST_CHECK_EQUAL_COLLECTIONS(trezor_bytes.begin(), trezor_bytes.end(), trezor_expected.begin(), trezor_expected.end());

    static const std::string mnemonic_24{
        "legal winner thank year wave sausage worth useful legal winner thank year "
        "wave sausage worth useful legal winner thank year wave sausage worth title"};
    auto trezor_seed_24{DeriveBIP39SeedFromMnemonic(mnemonic_24, trezor_passphrase)};
    BOOST_REQUIRE(trezor_seed_24);
    const auto trezor_expected_24{ParseHex("bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87")};
    const auto trezor_bytes_24{to_bytes(*trezor_seed_24)};
    BOOST_CHECK_EQUAL_COLLECTIONS(trezor_bytes_24.begin(), trezor_bytes_24.end(), trezor_expected_24.begin(), trezor_expected_24.end());

    const SecureString composed{"caf\xc3\xa9"};
    const SecureString decomposed{"cafe\xcc\x81"};
    auto composed_seed{DeriveBIP39SeedFromMnemonic(mnemonic, composed)};
    auto decomposed_seed{DeriveBIP39SeedFromMnemonic(mnemonic, decomposed)};
    BOOST_REQUIRE(composed_seed);
    BOOST_REQUIRE(decomposed_seed);
    BOOST_CHECK(*composed_seed == *decomposed_seed);

    // BIP39's published Japanese normalization passphrase exercises
    // compatibility decomposition, combining marks, and non-Latin text.
    const SecureString unicode_passphrase{"㍍ガバヴァぱばぐゞちぢ十人十色"};
    auto unicode_seed{DeriveBIP39SeedFromMnemonic(mnemonic, unicode_passphrase)};
    BOOST_REQUIRE(unicode_seed);
    const auto unicode_expected{ParseHex("ba553eedefe76e67e2602dc20184c564010859faada929a090dd2c57aacb204ceefd15404ab50ef3e8dbeae5195aeae64b0def4d2eead1cdc728a33ced520ffd")};
    const auto unicode_bytes{to_bytes(*unicode_seed)};
    BOOST_CHECK_EQUAL_COLLECTIONS(unicode_bytes.begin(), unicode_bytes.end(), unicode_expected.begin(), unicode_expected.end());

    const SecureString different_case{"trezor"};
    const SecureString trailing_space{"TREZOR "};
    auto different_case_seed{DeriveBIP39SeedFromMnemonic(mnemonic, different_case)};
    auto trailing_space_seed{DeriveBIP39SeedFromMnemonic(mnemonic, trailing_space)};
    BOOST_REQUIRE(different_case_seed);
    BOOST_REQUIRE(trailing_space_seed);
    BOOST_CHECK(*different_case_seed != *trezor_seed);
    BOOST_CHECK(*trailing_space_seed != *trezor_seed);

    ClearBIP39Seed(*implicit_empty);
    ClearBIP39Seed(*explicit_empty);
    ClearBIP39Seed(*trezor_seed);
    ClearBIP39Seed(*trezor_seed_24);
    ClearBIP39Seed(*composed_seed);
    ClearBIP39Seed(*decomposed_seed);
    ClearBIP39Seed(*unicode_seed);
    ClearBIP39Seed(*different_case_seed);
    ClearBIP39Seed(*trailing_space_seed);
}

BOOST_AUTO_TEST_CASE(bip39_optional_passphrase_validation)
{
    SecureString invalid_utf8;
    invalid_utf8.push_back(static_cast<char>(0xc3));
    invalid_utf8.push_back('(');
    BOOST_CHECK(!NormalizeBIP39Passphrase(invalid_utf8));

    SecureString embedded_nul{"left"};
    embedded_nul.push_back('\0');
    embedded_nul.append("right");
    BOOST_CHECK(!NormalizeBIP39Passphrase(embedded_nul));

    const SecureString maximum(MAX_BIP39_PASSPHRASE_SIZE, 'x');
    auto normalized_maximum{NormalizeBIP39Passphrase(maximum)};
    BOOST_REQUIRE(normalized_maximum);
    BOOST_CHECK_EQUAL(normalized_maximum->size(), MAX_BIP39_PASSPHRASE_SIZE);

    const SecureString excessive(MAX_BIP39_PASSPHRASE_SIZE + 1, 'x');
    BOOST_CHECK(!NormalizeBIP39Passphrase(excessive));

    SecureString expands_after_nfkd;
    for (size_t i = 0; i < MAX_BIP39_PASSPHRASE_SIZE / 2; ++i) {
        expands_after_nfkd.append("\xc3\xa9");
    }
    BOOST_CHECK_EQUAL(expands_after_nfkd.size(), MAX_BIP39_PASSPHRASE_SIZE);
    BOOST_CHECK(!NormalizeBIP39Passphrase(expands_after_nfkd));
}

BOOST_AUTO_TEST_CASE(bip39_derived_seed_record_authentication)
{
    const CKey mnemonic_entropy{GenerateRandomKey()};
    BIP39Seed seed{};
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::byte>(i);
    }

    auto clear_record{CreateBIP39DerivedSeedRecord(
        mnemonic_entropy.GetPubKey().GetID(), PrivateSeedScope::FULL_WALLET,
        /*passphrase_enabled=*/true, seed)};
    BOOST_REQUIRE(clear_record);
    BOOST_CHECK(clear_record->PassphraseEnabled());
    BOOST_CHECK(ValidateBIP39DerivedSeedRecord(*clear_record));

    auto clear_seed{ExtractBIP39DerivedSeed(*clear_record)};
    BOOST_REQUIRE(clear_seed);
    BOOST_CHECK_EQUAL(clear_seed->size(), seed.size());
    BOOST_CHECK(std::equal(clear_seed->begin(), clear_seed->end(), reinterpret_cast<const unsigned char*>(seed.data())));

    CKeyingMaterial master_key(WALLET_CRYPTO_KEY_SIZE);
    for (size_t i = 0; i < master_key.size(); ++i) master_key[i] = static_cast<unsigned char>(0xa0 + i);
    auto encrypted_record{EncryptBIP39DerivedSeedRecord(*clear_record, master_key)};
    BOOST_REQUIRE(encrypted_record);
    BOOST_CHECK_EQUAL(encrypted_record->protection, BIP39_DERIVED_SEED_ENCRYPTED);
    BOOST_CHECK(ValidateBIP39DerivedSeedRecord(*encrypted_record));

    auto decrypted_seed{ExtractBIP39DerivedSeed(*encrypted_record, &master_key)};
    BOOST_REQUIRE(decrypted_seed);
    BOOST_CHECK(std::equal(decrypted_seed->begin(), decrypted_seed->end(), reinterpret_cast<const unsigned char*>(seed.data())));

    CKeyingMaterial wrong_master_key{master_key};
    wrong_master_key[0] ^= 0x01;
    BOOST_CHECK(!ExtractBIP39DerivedSeed(*encrypted_record, &wrong_master_key));

    CBIP39DerivedSeedRecord tampered_encrypted{*encrypted_record};
    tampered_encrypted.payload[0] ^= 0x01;
    BOOST_CHECK(!ExtractBIP39DerivedSeed(tampered_encrypted, &master_key));

    CBIP39DerivedSeedRecord tampered_clear{*clear_record};
    tampered_clear.payload[0] ^= 0x01;
    BOOST_CHECK(!ValidateBIP39DerivedSeedRecord(tampered_clear));

    memory_cleanse(clear_seed->data(), clear_seed->size());
    memory_cleanse(decrypted_seed->data(), decrypted_seed->size());
    memory_cleanse(master_key.data(), master_key.size());
    memory_cleanse(wrong_master_key.data(), wrong_master_key.size());
    ClearBIP39Seed(seed);
}

BOOST_AUTO_TEST_CASE(bip39_descriptor_setup_failure_is_restart_safe)
{
    const SecureString bip39_passphrase{"descriptor setup atomicity"};
    for (const std::string& failed_type : {DBKeys::BIP39_DERIVED_SEED, DBKeys::PRIVATE_CHAIN, DBKeys::FLAGS}) {
        BOOST_TEST_CONTEXT("failed descriptor record=" << failed_type) {
            const CKey mnemonic_entropy{GenerateRandomKey()};
            MockableData failed_records;
            {
                CWallet wallet(m_node.chain.get(), "bip39-descriptor-setup-failure", CreateMockableWalletDatabase());
                wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
                wallet.SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
                MockableDatabase& database{GetMockableDatabase(wallet)};
                const MockableData baseline_records{database.m_records};
                database.m_fail_key_type = failed_type;
                {
                    LOCK(wallet.cs_wallet);
                    BOOST_CHECK_THROW(wallet.SetupDescriptorScriptPubKeyMans(mnemonic_entropy, bip39_passphrase), std::runtime_error);
                    BOOST_CHECK(wallet.GetAllScriptPubKeyMans().empty());
                    BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED));
                    BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
                }
                BOOST_CHECK(database.m_records == baseline_records);
                BOOST_CHECK(!HasMockRecordType(database.m_records, DBKeys::BIP39_DERIVED_SEED));
                BOOST_CHECK(!HasMockRecordType(database.m_records, DBKeys::PRIVATE_CHAIN));
                failed_records = database.m_records;
            }

            MockableData activated_records;
            {
                CWallet wallet(m_node.chain.get(), "bip39-descriptor-setup-retry", CreateMockableWalletDatabase(failed_records));
                BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
                LOCK(wallet.cs_wallet);
                BOOST_CHECK(wallet.GetAllScriptPubKeyMans().empty());
                BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
                wallet.SetupDescriptorScriptPubKeyMans(mnemonic_entropy, bip39_passphrase);
                BOOST_CHECK(!wallet.GetAllScriptPubKeyMans().empty());
                BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
                BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED));
                activated_records = GetMockableDatabase(wallet).m_records;
            }

            {
                CWallet wallet(m_node.chain.get(), "bip39-descriptor-setup-restarted", CreateMockableWalletDatabase(activated_records));
                BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
                LOCK(wallet.cs_wallet);
                BOOST_CHECK(!wallet.GetAllScriptPubKeyMans().empty());
                BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED));
                BOOST_CHECK(wallet.IsBIP39PassphraseEnabled());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(bip39_encrypt_wallet_failure_is_restart_safe)
{
    const CKey mnemonic_entropy{GenerateRandomKey()};
    const SecureString bip39_passphrase{"wallet encryption atomicity"};
    const SecureString wallet_passphrase{"wallet.dat encryption password"};
    MockableData clear_records;
    {
        CWallet wallet(m_node.chain.get(), "bip39-encrypt-failure", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetupDescriptorScriptPubKeyMans(mnemonic_entropy, bip39_passphrase);
        }
        MockableDatabase& database{GetMockableDatabase(wallet)};
        clear_records = database.m_records;
        database.m_fail_key_type = DBKeys::BIP39_DERIVED_SEED;
        BOOST_CHECK(!wallet.EncryptWallet(wallet_passphrase));
        BOOST_CHECK(!wallet.IsCrypted());
        BOOST_CHECK(database.m_records == clear_records);
        {
            LOCK(wallet.cs_wallet);
            BIP39Seed seed{};
            BIP39SeedGuard seed_cleanup{seed};
            bilingual_str error;
            BOOST_REQUIRE(wallet.GetBIP39DerivedSeed(seed, error));
        }
    }

    MockableData encrypted_records;
    {
        CWallet wallet(m_node.chain.get(), "bip39-encrypt-retry", CreateMockableWalletDatabase(clear_records));
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        BOOST_CHECK(!wallet.IsCrypted());
        BOOST_REQUIRE(wallet.EncryptWallet(wallet_passphrase));
        BOOST_CHECK(wallet.IsLocked());
        encrypted_records = GetMockableDatabase(wallet).m_records;
    }

    {
        CWallet wallet(m_node.chain.get(), "bip39-encrypt-restarted", CreateMockableWalletDatabase(encrypted_records));
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        BOOST_CHECK(wallet.IsLocked());
        BOOST_REQUIRE(wallet.Unlock(wallet_passphrase));
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(wallet.IsBIP39PassphraseEnabled());
    }
}

BOOST_AUTO_TEST_CASE(bip39_derived_seed_wallet_encryption_roundtrip)
{
    const CKey mnemonic_entropy{GenerateRandomKey()};
    const SecureString bip39_passphrase{"correct horse battery staple"};
    const SecureString wallet_passphrase{"wallet encryption password"};
    const SecureString changed_wallet_passphrase{"changed wallet encryption password"};
    auto expected_seed{DeriveBIP39SeedFromEntropyKey(mnemonic_entropy, bip39_passphrase)};
    BOOST_REQUIRE(expected_seed);

    MockableData encrypted_records;
    {
        CWallet wallet(m_node.chain.get(), "bip39-encryption", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetupDescriptorScriptPubKeyMans(mnemonic_entropy, bip39_passphrase);
            BOOST_CHECK(wallet.IsBIP39PassphraseEnabled());

            CBIP39DerivedSeedRecord record;
            BOOST_REQUIRE(WalletBatch(wallet.GetDatabase()).ReadBIP39DerivedSeed(record));
            BOOST_CHECK_EQUAL(record.protection, BIP39_DERIVED_SEED_CLEAR);
        }

        BOOST_REQUIRE(wallet.EncryptWallet(wallet_passphrase));
        BOOST_CHECK(wallet.IsLocked());
        CBIP39DerivedSeedRecord record;
        BOOST_REQUIRE(WalletBatch(wallet.GetDatabase()).ReadBIP39DerivedSeed(record));
        BOOST_CHECK_EQUAL(record.protection, BIP39_DERIVED_SEED_ENCRYPTED);
        encrypted_records = GetMockableDatabase(wallet).m_records;
    }

    {
        CWallet wallet(m_node.chain.get(), "bip39-encryption-restart", CreateMockableWalletDatabase(encrypted_records));
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        {
            LOCK(wallet.cs_wallet);
            BIP39Seed unavailable{};
            bilingual_str error;
            BOOST_CHECK(!wallet.GetBIP39DerivedSeed(unavailable, error));
        }
        BOOST_CHECK(!wallet.Unlock("wrong wallet password"));
        BOOST_REQUIRE(wallet.Unlock(wallet_passphrase));
        {
            LOCK(wallet.cs_wallet);
            BIP39Seed actual_seed{};
            bilingual_str error;
            BOOST_REQUIRE(wallet.GetBIP39DerivedSeed(actual_seed, error));
            BOOST_CHECK(actual_seed == *expected_seed);
            ClearBIP39Seed(actual_seed);
        }
        BOOST_REQUIRE(wallet.Lock());
        {
            LOCK(wallet.cs_wallet);
            BIP39Seed unavailable{};
            bilingual_str error;
            BOOST_CHECK(!wallet.GetBIP39DerivedSeed(unavailable, error));
        }
        BOOST_REQUIRE(wallet.ChangeWalletPassphrase(wallet_passphrase, changed_wallet_passphrase));
        BOOST_REQUIRE(wallet.Lock());
        BOOST_CHECK(!wallet.Unlock(wallet_passphrase));
        BOOST_REQUIRE(wallet.Unlock(changed_wallet_passphrase));
        {
            LOCK(wallet.cs_wallet);
            BIP39Seed actual_seed{};
            bilingual_str error;
            BOOST_REQUIRE(wallet.GetBIP39DerivedSeed(actual_seed, error));
            BOOST_CHECK(actual_seed == *expected_seed);
            ClearBIP39Seed(actual_seed);
        }
    }

    MockableData corrupted_records{encrypted_records};
    {
        CWallet wallet(m_node.chain.get(), "bip39-encryption-corrupt-source", CreateMockableWalletDatabase(corrupted_records));
        WalletBatch batch(wallet.GetDatabase());
        CBIP39DerivedSeedRecord record;
        BOOST_REQUIRE(batch.ReadBIP39DerivedSeed(record));
        BOOST_REQUIRE(!record.payload.empty());
        record.payload[0] ^= 0x01;
        BOOST_REQUIRE(batch.WriteBIP39DerivedSeed(record));
        corrupted_records = GetMockableDatabase(wallet).m_records;
    }
    {
        CWallet wallet(m_node.chain.get(), "bip39-encryption-corrupt-restart", CreateMockableWalletDatabase(corrupted_records));
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        bilingual_str unlock_error;
        BOOST_CHECK(!wallet.Unlock(wallet_passphrase, &unlock_error));
        BOOST_CHECK(unlock_error.original.find("authentication failed") != std::string::npos);
        BOOST_CHECK(wallet.IsLocked());
    }

    ClearBIP39Seed(*expected_seed);
}

BOOST_AUTO_TEST_CASE(bip39_derived_seed_wallet_compatibility_and_corruption)
{
    const CKey mnemonic_entropy{GenerateRandomKey()};
    const SecureString empty_bip39_passphrase;
    auto expected_seed{DeriveBIP39SeedFromEntropyKey(mnemonic_entropy, empty_bip39_passphrase)};
    BOOST_REQUIRE(expected_seed);

    MockableData valid_records;
    {
        CWallet wallet(m_node.chain.get(), "bip39-state-source", CreateMockableWalletDatabase());
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans(mnemonic_entropy, empty_bip39_passphrase);
        BOOST_REQUIRE(wallet.IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED));
        valid_records = GetMockableDatabase(wallet).m_records;
    }

    // A pre-passphrase V4 wallet has the entropy key and Orchard chain but no
    // record or flag. It must retain the exact empty-passphrase derivation and
    // must not be rewritten merely by loading or reading the seed.
    MockableData legacy_records;
    {
        CWallet wallet(m_node.chain.get(), "bip39-state-old-v4-prep", CreateMockableWalletDatabase(valid_records));
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        LOCK(wallet.cs_wallet);
        wallet.UnsetWalletFlag(WALLET_FLAG_BIP39_DERIVED_SEED);
        BOOST_REQUIRE(WalletBatch(wallet.GetDatabase()).EraseBIP39DerivedSeed());
        legacy_records = GetMockableDatabase(wallet).m_records;
    }
    {
        CWallet wallet(m_node.chain.get(), "bip39-state-old-v4", CreateMockableWalletDatabase(legacy_records));
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED));
        BOOST_CHECK(!HasMockRecordType(GetMockableDatabase(wallet).m_records, DBKeys::BIP39_DERIVED_SEED));
        BIP39Seed actual_seed{};
        bilingual_str error;
        BOOST_REQUIRE(wallet.GetBIP39DerivedSeed(actual_seed, error));
        BOOST_CHECK(actual_seed == *expected_seed);
        BOOST_CHECK(GetMockableDatabase(wallet).m_records == legacy_records);
        ClearBIP39Seed(actual_seed);
    }

    MockableData flag_without_record;
    {
        CWallet wallet(m_node.chain.get(), "bip39-state-missing-record-prep", CreateMockableWalletDatabase(valid_records));
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        BOOST_REQUIRE(WalletBatch(wallet.GetDatabase()).EraseBIP39DerivedSeed());
        flag_without_record = GetMockableDatabase(wallet).m_records;
    }
    {
        CWallet wallet(m_node.chain.get(), "bip39-state-missing-record", CreateMockableWalletDatabase(flag_without_record));
        BOOST_CHECK_EQUAL(wallet.LoadWallet(), DBErrors::CORRUPT);
    }

    MockableData record_without_flag;
    {
        CWallet wallet(m_node.chain.get(), "bip39-state-missing-flag-prep", CreateMockableWalletDatabase(valid_records));
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        wallet.UnsetWalletFlag(WALLET_FLAG_BIP39_DERIVED_SEED);
        record_without_flag = GetMockableDatabase(wallet).m_records;
    }
    {
        CWallet wallet(m_node.chain.get(), "bip39-state-missing-flag", CreateMockableWalletDatabase(record_without_flag));
        BOOST_CHECK_EQUAL(wallet.LoadWallet(), DBErrors::CORRUPT);
    }

    MockableData corrupt_clear_record;
    {
        CWallet wallet(m_node.chain.get(), "bip39-state-corrupt-clear-prep", CreateMockableWalletDatabase(valid_records));
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        WalletBatch batch(wallet.GetDatabase());
        CBIP39DerivedSeedRecord record;
        BOOST_REQUIRE(batch.ReadBIP39DerivedSeed(record));
        BOOST_REQUIRE_EQUAL(record.protection, BIP39_DERIVED_SEED_CLEAR);
        BOOST_REQUIRE(!record.payload.empty());
        record.payload[0] ^= 0x01;
        BOOST_REQUIRE(batch.WriteBIP39DerivedSeed(record));
        corrupt_clear_record = GetMockableDatabase(wallet).m_records;
    }
    {
        CWallet wallet(m_node.chain.get(), "bip39-state-corrupt-clear", CreateMockableWalletDatabase(corrupt_clear_record));
        BOOST_CHECK_EQUAL(wallet.LoadWallet(), DBErrors::CORRUPT);
    }

    ClearBIP39Seed(*expected_seed);
}

BOOST_AUTO_TEST_CASE(private_accounting_indexed_lookup)
{
    LOCK(m_wallet.cs_wallet);
    CMutableTransaction tx;
    tx.m_private_bundle.emplace();
    tx.m_private_bundle->effects.actions.resize(3);
    for (uint8_t i = 0; i < 3; ++i) {
        auto& action = tx.m_private_bundle->effects.actions[i];
        action.cmx = uint256{static_cast<uint8_t>(11 + i)};
        action.nullifier = uint256{static_cast<uint8_t>(101 + i)};
    }
    const CWalletTx wtx{MakeTransactionRef(tx), TxStateInactive{}};
    CPrivateWalletNote cached_note;
    cached_note.m_is_change = true;
    DataStream serialized_note;
    serialized_note << cached_note;
    serialized_note >> cached_note;
    BOOST_CHECK(!cached_note.m_is_change.has_value());
    auto load = [&](uint256 cmx, uint256 nf, uint256 txid, CAmount value, bool internal, uint8_t receiver, bool change = false) {
        CPrivateWalletNote note;
        note.cmx = cmx;
        note.nullifier = nf;
        note.txid = txid;
        note.value = value;
        note.internal = internal;
        note.recipient_raw.assign(43, receiver);
        // This lookup test uses synthetic actions; cryptographic classification
        // is covered by Orchard FFI and functional history tests.
        note.m_is_change = change;
        BOOST_REQUIRE(m_wallet.LoadPrivateNote(note));
    };
    load(uint256{1}, uint256{101}, uint256{201}, 30, false, 1);
    load(uint256{11}, uint256{111}, wtx.GetHash(), 10, false, 1);
    load(uint256{12}, uint256{112}, wtx.GetHash(), 5, true, 3, true);
    load(uint256{13}, uint256{113}, wtx.GetHash(), 7, false, 1, true);
    for (int i = 0; i < 5000; ++i) {
        load(InsecureRand256(), InsecureRand256(), uint256{202}, 1, false, 4);
    }
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 200; ++i) {
        BOOST_CHECK_EQUAL(CachedTxGetPrivateCredit(m_wallet, wtx), 22);
        BOOST_CHECK_EQUAL(CachedTxGetPrivateExternalCredit(m_wallet, wtx), 10);
        BOOST_CHECK_EQUAL(CachedTxGetPrivateInternalCredit(m_wallet, wtx), 12);
        BOOST_CHECK_EQUAL(CachedTxGetPrivateDebit(m_wallet, wtx), 30);
    }
    BOOST_TEST_MESSAGE("Private accounting, 5004 notes/200 iterations: " <<
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count() << " us");
    m_wallet.ClearDecryptedPrivateNotes();
    BOOST_CHECK_EQUAL(CachedTxGetPrivateCredit(m_wallet, wtx), 0);
    BOOST_CHECK_EQUAL(CachedTxGetPrivateDebit(m_wallet, wtx), 0);
    // Reloading reconstructs the lookup without a stale balance/result cache.
    load(uint256{1}, uint256{101}, uint256{201}, 30, false, 1);
    BOOST_CHECK_EQUAL(CachedTxGetPrivateDebit(m_wallet, wtx), 30);
}

BOOST_AUTO_TEST_CASE(seed_recovery_progress_roundtrip)
{
    const uint256 target{InsecureRand256()};
    SeedHistoryState state{SeedHistoryState::AvailableBalance(42, target, /*orchard_applicable=*/true)};
    state.MarkFunds(/*orchard=*/false, SeedRecoveryStatus::COMPLETE, 42, target);
    state.MarkFunds(/*orchard=*/true, SeedRecoveryStatus::FAILED, 42, target);
    BOOST_REQUIRE(state.IsValid());

    DataStream encoded;
    encoded << state;
    SeedHistoryState decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK_EQUAL(decoded.m_version, SeedHistoryState::CURRENT_VERSION);
    BOOST_CHECK(decoded.m_transparent.m_restore_funds.m_status == SeedRecoveryStatus::COMPLETE);
    BOOST_CHECK(decoded.m_orchard.m_restore_funds.m_status == SeedRecoveryStatus::FAILED);
    BOOST_CHECK_EQUAL(decoded.m_orchard.m_restore_funds.m_height, 42);
    BOOST_CHECK(decoded.m_orchard.m_restore_funds.m_block == target);
    BOOST_CHECK(decoded.m_transparent.m_explicit_history.m_status == SeedRecoveryStatus::NOT_REQUESTED);
}

BOOST_AUTO_TEST_CASE(seed_recovery_unsupported_state_is_rejected)
{
    for (const uint8_t version : {1, 3}) {
        for (const auto mode : {SeedHistoryMode::AVAILABLE_BALANCE, SeedHistoryMode::FULL_HISTORY}) {
            DataStream encoded;
            encoded << version << static_cast<uint8_t>(mode) << int{42} << InsecureRand256();
            SeedHistoryState state;
            BOOST_CHECK_THROW(encoded >> state, std::ios_base::failure);
        }
    }
}

BOOST_AUTO_TEST_CASE(private_chain_unsupported_versions_are_rejected)
{
    for (const int version : {-1, 0, 1, 2, 3, 4, 5, 6, 8}) {
        DataStream current;
        current << CPrivateWalletChain{};
        current.ignore(sizeof(int32_t));
        DataStream encoded;
        encoded << version;
        encoded.write(Span<const std::byte>{current.data(), current.size()});
        CPrivateWalletChain chain;
        BOOST_CHECK_THROW(encoded >> chain, std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(private_note_unsupported_versions_are_rejected)
{
    for (const int version : {-1, 0, 1, 3}) {
        DataStream current;
        current << CPrivateWalletNote{};
        current.ignore(sizeof(int32_t));
        DataStream encoded;
        encoded << version;
        encoded.write(Span<const std::byte>{current.data(), current.size()});
        CPrivateWalletNote note;
        BOOST_CHECK_THROW(encoded >> note, std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(private_scan_obligations_are_generation_aware)
{
    CPrivateWalletChain chain;
    const uint256 start_a{InsecureRand256()};
    const uint256 target_a{InsecureRand256()};
    const uint256 target_b{InsecureRand256()};
    chain.private_locked_live_scan.Mark(10, start_a, 10, target_a);
    const uint64_t first_generation{chain.private_locked_live_scan.generation};
    chain.private_locked_live_scan.Mark(12, InsecureRand256(), 12, target_b);
    chain.Normalize();

    BOOST_CHECK(chain.private_locked_live_scan.IsPending());
    BOOST_CHECK_EQUAL(chain.private_locked_live_scan.start_height, 10);
    BOOST_CHECK(chain.private_locked_live_scan.start_block == start_a);
    BOOST_CHECK_EQUAL(chain.private_locked_live_scan.target_height, 12);
    BOOST_CHECK(chain.private_locked_live_scan.target_block == target_b);
    BOOST_CHECK(chain.private_locked_live_scan.generation > first_generation);
    BOOST_CHECK_EQUAL(chain.private_scan_pending_height, 10);

    DataStream encoded;
    encoded << chain;
    CPrivateWalletChain decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded.private_locked_live_scan.HasExactTarget());
    BOOST_CHECK_EQUAL(decoded.private_locked_live_scan.generation, chain.private_locked_live_scan.generation);
    BOOST_CHECK_EQUAL(decoded.private_scan_pending_height, 10);
}

static bool HasMockRecordType(const MockableData& records, const std::string& expected_type)
{
    for (const auto& [serialized_key, _] : records) {
        DataStream key{Span<const std::byte>{serialized_key.data(), serialized_key.size()}};
        std::string type;
        key >> type;
        if (type == expected_type) return true;
    }
    return false;
}

BOOST_AUTO_TEST_CASE(passphrase_rescan_unlock_lease)
{
    {
        LOCK(m_wallet.cs_wallet);
        auto* legacy_spkm = m_wallet.GetOrCreateLegacyScriptPubKeyMan();
        BOOST_REQUIRE(legacy_spkm);
        BOOST_REQUIRE(legacy_spkm->SetupGeneration(true));
    }
    BOOST_REQUIRE(m_wallet.EncryptWallet("rescan lease passphrase"));
    BOOST_REQUIRE(m_wallet.Unlock("rescan lease passphrase"));
    BOOST_REQUIRE(!m_wallet.IsLocked());

    const int64_t expired_relock_time{GetTime() - 1};
    WITH_LOCK(m_wallet.cs_wallet, m_wallet.nRelockTime = expired_relock_time);
    {
        WalletRescanReserver reserver(m_wallet);
        BOOST_REQUIRE(reserver.reserve(/*with_passphrase=*/true));
        BOOST_CHECK(!m_wallet.TryRelock(expired_relock_time));
        BOOST_CHECK(!m_wallet.IsLocked());
    }

    BOOST_CHECK(m_wallet.IsLocked());
    BOOST_CHECK_EQUAL(WITH_LOCK(m_wallet.cs_wallet, return m_wallet.nRelockTime), 0);
}

BOOST_AUTO_TEST_CASE(private_note_encrypted_at_rest)
{
    CWallet wallet(m_node.chain.get(), "encrypted-private-note", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        auto* legacy_spkm = wallet.GetOrCreateLegacyScriptPubKeyMan();
        BOOST_REQUIRE(legacy_spkm);
        BOOST_REQUIRE(legacy_spkm->SetupGeneration(true));

        CPrivateWalletNote note;
        note.cmx = InsecureRand256();
        note.nullifier = InsecureRand256();
        note.txid = InsecureRand256();
        note.value = 123456789;
        note.decrypted = true;
        note.recipient_raw = {1, 2, 3, 4};
        note.rho = {5, 6, 7, 8};
        note.rseed = {9, 10, 11, 12};
        note.memo = {'s', 'e', 'c', 'r', 'e', 't'};
        WalletBatch batch(wallet.GetDatabase());
        BOOST_REQUIRE(wallet.LoadPrivateNote(note));
        BOOST_REQUIRE(batch.WritePrivateNote(note));

        CPrivateWalletChain private_chain;
        private_chain.hd_seed_id = GenerateRandomKey().GetPubKey().GetID();
        private_chain.seed_scope = PrivateSeedScope::ORCHARD_ONLY;
        private_chain.has_external_full_viewing_key = true;
        private_chain.has_internal_full_viewing_key = true;
        private_chain.external_full_viewing_key.fill(0x41);
        private_chain.internal_full_viewing_key.fill(0x42);
        wallet.LoadPrivateChain(private_chain);
        BOOST_REQUIRE(batch.WritePrivateChain(private_chain));
    }

    BOOST_REQUIRE(wallet.EncryptWallet("private note encryption passphrase"));
    BOOST_CHECK(wallet.IsLocked());
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(wallet.mapPrivateNotes.empty());
    }

    bool found_plaintext_note{false};
    bool found_crypted_note{false};
    bool found_sanitized_chain{false};
    for (const auto& [serialized_key, serialized_value] : GetMockableDatabase(wallet).m_records) {
        DataStream key{Span<const std::byte>{serialized_key.data(), serialized_key.size()}};
        std::string type;
        key >> type;
        if (type == DBKeys::PRIVATE_NOTE) found_plaintext_note = true;
        if (type == DBKeys::CRYPTED_PRIVATE_NOTE) found_crypted_note = true;
        if (type == DBKeys::PRIVATE_CHAIN) {
            DataStream value{Span<const std::byte>{serialized_value.data(), serialized_value.size()}};
            CPrivateWalletChain stored_chain;
            value >> stored_chain;
            found_sanitized_chain = !stored_chain.has_external_full_viewing_key &&
                                    !stored_chain.has_internal_full_viewing_key;
        }
    }
    BOOST_CHECK(!found_plaintext_note);
    BOOST_CHECK(found_crypted_note);
    BOOST_CHECK(found_sanitized_chain);

    BOOST_REQUIRE(wallet.Unlock("private note encryption passphrase"));
    {
        LOCK(wallet.cs_wallet);
        BOOST_REQUIRE_EQUAL(wallet.mapPrivateNotes.size(), 1);
        const CPrivateWalletNote& recovered = wallet.mapPrivateNotes.begin()->second;
        BOOST_CHECK_EQUAL(recovered.value, 123456789);
        BOOST_CHECK_EQUAL(std::string(recovered.memo.begin(), recovered.memo.end()), "secret");
    }
    BOOST_REQUIRE(wallet.LockForDisplay());
    BOOST_CHECK(wallet.IsLocked());
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(wallet.CanViewPrivateData());
        BOOST_REQUIRE_EQUAL(wallet.mapPrivateNotes.size(), 1);
    }

    BOOST_REQUIRE(wallet.Unlock("private note encryption passphrase"));
    BOOST_REQUIRE(wallet.Lock());
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(!wallet.CanViewPrivateData());
        BOOST_CHECK(wallet.mapPrivateNotes.empty());
    }
}

BOOST_AUTO_TEST_CASE(private_bump_recipe_authenticated_envelope)
{
    CWallet wallet(m_node.chain.get(), "private-bump-envelope", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        auto* legacy_spkm{wallet.GetOrCreateLegacyScriptPubKeyMan()};
        BOOST_REQUIRE(legacy_spkm);
        BOOST_REQUIRE(legacy_spkm->SetupGeneration(true));
    }
    BOOST_REQUIRE(wallet.EncryptWallet("private bump envelope passphrase"));
    BOOST_REQUIRE(wallet.Unlock("private bump envelope passphrase"));

    CMutableTransaction original;
    original.m_private_bundle.emplace();
    original.m_private_bundle->effects.actions.resize(1);
    original.m_private_bundle->effects.actions[0].nullifier = uint256{1};
    const CTransactionRef original_tx{MakeTransactionRef(original)};
    CPrivateWalletNote original_note;
    original_note.cmx = uint256{2};
    original_note.nullifier = original_tx->m_private_bundle->effects.actions[0].nullifier;
    {
        LOCK(wallet.cs_wallet);
        wallet.mapPrivateNotes.emplace(original_note.cmx, original_note);
    }
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> private_raw{};
    private_raw.fill(0xa7);
    const std::vector<CRecipient> recipients{{CNoDestination{}, 2 * COIN, false, private_raw}};
    CCoinControl coin_control;
    coin_control.m_private_tx_source = CCoinControl::PrivateTxSource::PRIVATE_NOTES;
    mapValue_t map_value;
    BOOST_REQUIRE(feebumper::AddPrivateBumpMetadata(wallet, original_tx->GetHash(), map_value, coin_control, recipients, {original_note.cmx}));
    BOOST_REQUIRE_EQUAL(map_value.size(), 1U);

    CWalletTx original_wtx{original_tx, TxStateInactive{}};
    original_wtx.mapValue = map_value;
    CMutableTransaction replacement{original};
    replacement.nLockTime = 1;
    const uint256 replacement_txid{replacement.GetHash()};
    mapValue_t rebound{map_value};
    BOOST_REQUIRE(feebumper::RebindPrivateBumpMetadata(wallet, original_wtx, replacement_txid, rebound));
    BOOST_CHECK(rebound != map_value);

    {
        LOCK(wallet.cs_wallet);
        wallet.mapPrivateNotes.at(original_note.cmx).nullifier = uint256{3};
    }
    mapValue_t mismatched{map_value};
    BOOST_CHECK(!feebumper::RebindPrivateBumpMetadata(wallet, original_wtx, replacement_txid, mismatched));
    {
        LOCK(wallet.cs_wallet);
        wallet.mapPrivateNotes.at(original_note.cmx).nullifier = original_note.nullifier;
    }

    CMutableTransaction wrong_binding{original};
    wrong_binding.nLockTime = 2;
    CWalletTx wrong_wtx{MakeTransactionRef(wrong_binding), TxStateInactive{}};
    wrong_wtx.mapValue = map_value;
    mapValue_t ignored{map_value};
    BOOST_CHECK(!feebumper::RebindPrivateBumpMetadata(wallet, wrong_wtx, replacement_txid, ignored));

    mapValue_t tampered{map_value};
    BOOST_REQUIRE(!tampered.begin()->second.empty());
    auto decoded_envelope{DecodeBase64(tampered.begin()->second)};
    BOOST_REQUIRE(decoded_envelope);
    BOOST_REQUIRE(!decoded_envelope->empty());
    decoded_envelope->back() ^= 1;
    tampered.begin()->second = EncodeBase64(*decoded_envelope);
    CWalletTx tampered_wtx{original_tx, TxStateInactive{}};
    tampered_wtx.mapValue = tampered;
    BOOST_CHECK(!feebumper::RebindPrivateBumpMetadata(wallet, tampered_wtx, replacement_txid, ignored));

    wallet.Lock();
    BOOST_CHECK(!feebumper::RebindPrivateBumpMetadata(wallet, original_wtx, replacement_txid, ignored));
}

BOOST_AUTO_TEST_CASE(private_bump_recipe_encrypted_during_wallet_encryption)
{
    const SecureString old_passphrase{"private bump old passphrase"};
    const SecureString new_passphrase{"private bump new passphrase"};
    CWallet wallet(m_node.chain.get(), "private-bump-migration", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        auto* legacy_spkm{wallet.GetOrCreateLegacyScriptPubKeyMan()};
        BOOST_REQUIRE(legacy_spkm);
        BOOST_REQUIRE(legacy_spkm->SetupGeneration(true));
    }

    CMutableTransaction transaction;
    transaction.m_private_bundle.emplace();
    transaction.m_private_bundle->effects.actions.resize(1);
    const CTransactionRef tx{MakeTransactionRef(transaction)};
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> private_raw{};
    private_raw.fill(0x5a);
    const std::vector<CRecipient> recipients{{CNoDestination{}, COIN, true, private_raw}};
    CCoinControl coin_control;
    coin_control.m_private_tx_source = CCoinControl::PrivateTxSource::TRANSPARENT_COINS;
    mapValue_t map_value;
    BOOST_REQUIRE(feebumper::AddPrivateBumpMetadata(wallet, tx->GetHash(), map_value, coin_control, recipients, {}));
    map_value["nito_private_bump_source"] = "unsupported plaintext source";
    map_value["nito_private_bump_recipients"] = "unsupported plaintext recipient";
    map_value["nito_private_bump_notes"] = "unsupported plaintext note ids";
    map_value["comment"] = "preserved public metadata";
    mapValue_t failed_protection{map_value};
    const mapValue_t before_failed_protection{failed_protection};
    BOOST_CHECK(!feebumper::EncryptPrivateBumpMetadata({}, tx->GetHash(), failed_protection));
    BOOST_CHECK(failed_protection == before_failed_protection);
    {
        LOCK(wallet.cs_wallet);
        CWalletTx wtx{tx, TxStateInactive{}};
        wtx.mapValue = map_value;
        BOOST_REQUIRE(WalletBatch(wallet.GetDatabase()).WriteTx(wtx));
        wallet.mapWallet.try_emplace(tx->GetHash(), tx, TxStateInactive{}).first->second.CopyFrom(wtx);
    }

    BOOST_REQUIRE(wallet.EncryptWallet(old_passphrase));
    BOOST_CHECK(wallet.IsLocked());
    CWalletTx encrypted_wtx{tx, TxStateInactive{}};
    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* stored_wtx{wallet.GetWalletTx(tx->GetHash())};
        BOOST_REQUIRE(stored_wtx);
        encrypted_wtx.CopyFrom(*stored_wtx);
    }
    BOOST_CHECK(!encrypted_wtx.mapValue.count("nito_private_bump_source"));
    BOOST_CHECK(!encrypted_wtx.mapValue.count("nito_private_bump_recipients"));
    BOOST_CHECK(!encrypted_wtx.mapValue.count("nito_private_bump_notes"));
    BOOST_REQUIRE(encrypted_wtx.mapValue.count("comment"));
    BOOST_CHECK_EQUAL(encrypted_wtx.mapValue.at("comment"), "preserved public metadata");
    BOOST_REQUIRE_EQUAL(encrypted_wtx.mapValue.size(), 2U);

    const std::vector<std::byte> private_pattern(private_raw.size(), std::byte{0x5a});
    bool found_tx_record{false};
    for (const auto& [serialized_key, serialized_value] : GetMockableDatabase(wallet).m_records) {
        DataStream key{Span<const std::byte>{serialized_key.data(), serialized_key.size()}};
        std::string type;
        key >> type;
        if (type != DBKeys::TX) continue;
        uint256 stored_txid;
        key >> stored_txid;
        if (stored_txid != tx->GetHash()) continue;
        found_tx_record = true;
        BOOST_CHECK(std::search(serialized_value.begin(), serialized_value.end(), private_pattern.begin(), private_pattern.end()) == serialized_value.end());
    }
    BOOST_REQUIRE(found_tx_record);

    CMutableTransaction replacement{transaction};
    replacement.nLockTime = 1;
    mapValue_t rebound{encrypted_wtx.mapValue};
    BOOST_CHECK(!feebumper::RebindPrivateBumpMetadata(wallet, encrypted_wtx, replacement.GetHash(), rebound));
    BOOST_REQUIRE(wallet.Unlock(old_passphrase));
    BOOST_REQUIRE(feebumper::RebindPrivateBumpMetadata(wallet, encrypted_wtx, replacement.GetHash(), rebound));
    BOOST_REQUIRE(wallet.ChangeWalletPassphrase(old_passphrase, new_passphrase));
    wallet.Lock();
    BOOST_CHECK(!wallet.Unlock(old_passphrase));
    BOOST_REQUIRE(wallet.Unlock(new_passphrase));
    BOOST_REQUIRE(feebumper::RebindPrivateBumpMetadata(wallet, encrypted_wtx, replacement.GetHash(), rebound));
}

BOOST_AUTO_TEST_CASE(corrupt_private_note_does_not_reject_valid_passphrase)
{
    const SecureString old_passphrase{"private note old passphrase"};
    const SecureString new_passphrase{"private note new passphrase"};
    const uint256 corrupt_cmx{InsecureRand256()};
    const uint256 intact_cmx{InsecureRand256()};
    MockableData records;

    {
        CWallet wallet(m_node.chain.get(), "private-note-corruption-source", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            auto* legacy_spkm{wallet.GetOrCreateLegacyScriptPubKeyMan()};
            BOOST_REQUIRE(legacy_spkm);
            BOOST_REQUIRE(legacy_spkm->SetupGeneration(true));

            WalletBatch batch(wallet.GetDatabase());
            for (const auto& [cmx, value] : {std::pair{corrupt_cmx, CAmount{1}}, std::pair{intact_cmx, CAmount{2}}}) {
                CPrivateWalletNote note;
                note.cmx = cmx;
                note.nullifier = InsecureRand256();
                note.txid = InsecureRand256();
                note.value = value;
                note.decrypted = true;
                note.recipient_raw = {1, 2, 3, 4};
                note.rho = {5, 6, 7, 8};
                note.rseed = {9, 10, 11, 12};
                BOOST_REQUIRE(wallet.LoadPrivateNote(note));
                BOOST_REQUIRE(batch.WritePrivateNote(note));
            }
        }
        BOOST_REQUIRE(wallet.EncryptWallet(old_passphrase));
        records = GetMockableDatabase(wallet).m_records;
    }

    bool corrupted{false};
    for (auto& [serialized_key, serialized_value] : records) {
        DataStream key{Span<const std::byte>{serialized_key.data(), serialized_key.size()}};
        std::string type;
        key >> type;
        if (type != DBKeys::CRYPTED_PRIVATE_NOTE) continue;
        uint256 cmx;
        key >> cmx;
        if (cmx != corrupt_cmx) continue;
        BOOST_REQUIRE(!serialized_value.empty());
        serialized_value.back() ^= std::byte{1};
        corrupted = true;
        break;
    }
    BOOST_REQUIRE(corrupted);

    CWallet wallet(m_node.chain.get(), "private-note-corruption", CreateMockableWalletDatabase(records));
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
    GetMockableDatabase(wallet).m_fail_key_type = DBKeys::PRIVATE_CHAIN;
    BOOST_CHECK(!wallet.Unlock("wrong passphrase"));
    BOOST_CHECK(wallet.IsLocked());

    {
        ASSERT_DEBUG_LOG("Wallet key accepted, but private note encryption migration failed");
        ASSERT_DEBUG_LOG("Wallet key accepted, but one or more encrypted private notes are unreadable");
        BOOST_REQUIRE(wallet.Unlock(old_passphrase));
    }
    BOOST_CHECK(!wallet.IsLocked());
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK_EQUAL(wallet.mapPrivateNotes.size(), 1);
        BOOST_CHECK(wallet.mapPrivateNotes.count(corrupt_cmx) == 0);
        BOOST_CHECK(wallet.mapPrivateNotes.count(intact_cmx) == 1);
    }

    {
        ASSERT_DEBUG_LOG("Wallet key accepted, but private note encryption migration failed");
        ASSERT_DEBUG_LOG("Wallet key accepted, but one or more encrypted private notes are unreadable");
        BOOST_REQUIRE(wallet.ChangeWalletPassphrase(old_passphrase, new_passphrase));
    }
    wallet.Lock();
    BOOST_CHECK(!wallet.Unlock(old_passphrase));
    BOOST_REQUIRE(wallet.Unlock(new_passphrase));
    BOOST_CHECK(!wallet.IsLocked());
}

BOOST_AUTO_TEST_CASE(private_seed_activation_failure_is_restart_safe)
{
    const SecureString empty_bip39_passphrase;
    for (const std::string& failed_type : {DBKeys::BIP39_DERIVED_SEED, DBKeys::PRIVATE_CHAIN, DBKeys::FLAGS}) {
        BOOST_TEST_CONTEXT("failed activation record=" << failed_type) {
            const CKey orchard_seed{GenerateRandomKey()};
            MockableData failed_records;
            {
                CWallet wallet(m_node.chain.get(), "private-seed-failure", CreateMockableWalletDatabase());
                LOCK(wallet.cs_wallet);
                auto* legacy_spkm{wallet.GetOrCreateLegacyScriptPubKeyMan()};
                BOOST_REQUIRE(legacy_spkm);
                BOOST_REQUIRE(legacy_spkm->SetupGeneration(true));

                MockableDatabase& database{GetMockableDatabase(wallet)};
                database.m_fail_key_type = failed_type;
                bilingual_str error;
                BOOST_CHECK(!wallet.InitializePrivateHDSeed(orchard_seed, empty_bip39_passphrase, PrivateSeedScope::ORCHARD_ONLY, error));
                BOOST_CHECK(!wallet.HasCanonicalPrivateHDSeed());
                BOOST_CHECK(wallet.GetPrivateChain().hd_seed_id.IsNull());
                BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED));
                BOOST_CHECK(!HasMockRecordType(database.m_records, DBKeys::BIP39_DERIVED_SEED));
                BOOST_CHECK(!HasMockRecordType(database.m_records, DBKeys::PRIVATE_CHAIN));
                BOOST_CHECK(HasMockRecordType(database.m_records, DBKeys::KEY));
                failed_records = database.m_records;
            }

            MockableData activated_records;
            {
                CWallet wallet(m_node.chain.get(), "private-seed-retry", CreateMockableWalletDatabase(failed_records));
                BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
                LOCK(wallet.cs_wallet);
                BOOST_CHECK(!wallet.HasCanonicalPrivateHDSeed());
                BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED));
                BOOST_CHECK(!HasMockRecordType(GetMockableDatabase(wallet).m_records, DBKeys::BIP39_DERIVED_SEED));
                BOOST_CHECK(!HasMockRecordType(GetMockableDatabase(wallet).m_records, DBKeys::PRIVATE_CHAIN));

                GetMockableDatabase(wallet).m_fail_key_type.reset();
                bilingual_str error;
                BOOST_REQUIRE(wallet.InitializePrivateHDSeed(orchard_seed, empty_bip39_passphrase, PrivateSeedScope::ORCHARD_ONLY, error));
                BOOST_CHECK(wallet.HasCanonicalPrivateHDSeed());
                BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED));
                BOOST_CHECK_EQUAL(wallet.GetPrivateSeedScope(), PrivateSeedScope::ORCHARD_ONLY);
                BOOST_CHECK(HasMockRecordType(GetMockableDatabase(wallet).m_records, DBKeys::BIP39_DERIVED_SEED));
                BOOST_CHECK(HasMockRecordType(GetMockableDatabase(wallet).m_records, DBKeys::PRIVATE_CHAIN));
                activated_records = GetMockableDatabase(wallet).m_records;
            }

            {
                CWallet wallet(m_node.chain.get(), "private-seed-restarted", CreateMockableWalletDatabase(activated_records));
                BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
                LOCK(wallet.cs_wallet);
                BOOST_CHECK(wallet.HasCanonicalPrivateHDSeed());
                BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_BIP39_DERIVED_SEED));
                CKey recovered_seed;
                bilingual_str error;
                BOOST_REQUIRE(wallet.GetPrivateHDSeed(recovered_seed, error));
                BOOST_CHECK(recovered_seed == orchard_seed);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(private_seed_key_write_retry_is_restart_safe)
{
    for (const bool descriptors : {false, true}) {
        for (const bool encrypted : {false, true}) {
            const std::vector<std::string> failed_types = descriptors
                ? std::vector<std::string>{encrypted ? DBKeys::WALLETDESCRIPTORCKEY : DBKeys::WALLETDESCRIPTORKEY}
                : std::vector<std::string>{DBKeys::KEYMETA, encrypted ? DBKeys::CRYPTED_KEY : DBKeys::KEY};
            for (const auto& failed_type : failed_types) {
                BOOST_TEST_CONTEXT("descriptors=" << descriptors << ", encrypted=" << encrypted << ", failed record=" << failed_type) {
                    const CKey orchard_seed{GenerateRandomKey()};
                    const SecureString passphrase{"Orchard key persistence test"};
                    const SecureString empty_bip39_passphrase;
                    MockableData activated_records;
                    {
                        CWallet wallet(m_node.chain.get(), "private-seed-key-write", CreateMockableWalletDatabase());
                        LOCK(wallet.cs_wallet);
                        if (descriptors) {
                            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
                            const CKey transparent_seed{GenerateRandomKey()};
                            CExtKey master_key;
                            master_key.SetSeed(transparent_seed);
                            wallet.SetupDescriptorScriptPubKeyMans(master_key);
                        } else {
                            auto* legacy_spkm{wallet.GetOrCreateLegacyScriptPubKeyMan()};
                            BOOST_REQUIRE(legacy_spkm);
                            BOOST_REQUIRE(legacy_spkm->SetupGeneration(true));
                        }
                        if (encrypted) {
                            BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
                            BOOST_REQUIRE(wallet.Unlock(passphrase));
                        }
                        BOOST_REQUIRE(!wallet.HasCanonicalPrivateHDSeed());

                        MockableDatabase& database{GetMockableDatabase(wallet)};
                        const bool had_chain_record{HasMockRecordType(database.m_records, DBKeys::PRIVATE_CHAIN)};
                        database.m_fail_key_type = failed_type;
                        bilingual_str error;
                        for (int attempt = 0; attempt < 2; ++attempt) {
                            BOOST_CHECK(!wallet.InitializePrivateHDSeed(orchard_seed, empty_bip39_passphrase, PrivateSeedScope::ORCHARD_ONLY, error));
                            BOOST_CHECK(!wallet.HasCanonicalPrivateHDSeed());
                            BOOST_CHECK_EQUAL(HasMockRecordType(database.m_records, DBKeys::PRIVATE_CHAIN), had_chain_record);
                            if (had_chain_record) {
                                CPrivateWalletChain stored_chain;
                                BOOST_REQUIRE(database.MakeBatch()->Read(DBKeys::PRIVATE_CHAIN, stored_chain));
                                BOOST_CHECK(stored_chain.hd_seed_id.IsNull());
                            }
                        }
                        database.m_fail_key_type.reset();
                        BOOST_REQUIRE(wallet.InitializePrivateHDSeed(orchard_seed, empty_bip39_passphrase, PrivateSeedScope::ORCHARD_ONLY, error));
                        activated_records = database.m_records;
                    }

                    CWallet restarted(m_node.chain.get(), "private-seed-key-restart", CreateMockableWalletDatabase(activated_records));
                    BOOST_REQUIRE_EQUAL(restarted.LoadWallet(), DBErrors::LOAD_OK);
                    if (encrypted) BOOST_REQUIRE(restarted.Unlock(passphrase));
                    LOCK(restarted.cs_wallet);
                    CKey recovered_seed;
                    bilingual_str error;
                    BOOST_REQUIRE(restarted.GetPrivateHDSeed(recovered_seed, error));
                    BOOST_CHECK(recovered_seed == orchard_seed);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(private_compact_update_db_failure_is_atomic_after_restart)
{
    MockableData baseline_records;
    CPrivateWalletNote original_note;
    original_note.cmx = InsecureRand256();
    original_note.nullifier = InsecureRand256();
    original_note.txid = InsecureRand256();
    original_note.value = 5 * COIN;
    original_note.decrypted = true;

    {
        CWallet wallet(m_node.chain.get(), "private-atomic-failure", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            auto* legacy_spkm{wallet.GetOrCreateLegacyScriptPubKeyMan()};
            BOOST_REQUIRE(legacy_spkm);
            BOOST_REQUIRE(legacy_spkm->SetupGeneration(true));
            WalletBatch batch(wallet.GetDatabase());
            BOOST_REQUIRE(wallet.LoadPrivateNote(original_note));
            BOOST_REQUIRE(batch.WritePrivateNote(original_note));
        }

        MockableDatabase& database{GetMockableDatabase(wallet)};
        baseline_records = database.m_records;
        database.m_fail_key_type = DBKeys::PRIVATE_NOTE;

        CPrivateCompactEffects effects;
        CPrivateCompactAction action;
        action.nullifier = original_note.nullifier;
        action.cmx = InsecureRand256();
        effects.actions.push_back(action);
        int active_height;
        uint256 active_hash;
        {
            LOCK(cs_main);
            active_height = m_node.chainman->ActiveChain().Height();
            active_hash = m_node.chainman->ActiveChain().Tip()->GetBlockHash();
        }
        BOOST_CHECK_EXCEPTION(
            wallet.SyncPrivateCompactEffects(
                InsecureRand256(), effects, TxStateConfirmed{active_hash, active_height, 0}),
            std::runtime_error,
            HasReason("DB error refreshing private note spent state"));
        BOOST_CHECK(database.m_records == baseline_records);
    }

    CWallet restarted(m_node.chain.get(), "private-atomic-restart", CreateMockableWalletDatabase(baseline_records));
    BOOST_REQUIRE_EQUAL(restarted.LoadWallet(), DBErrors::LOAD_OK);
    LOCK(restarted.cs_wallet);
    BOOST_REQUIRE_EQUAL(restarted.mapPrivateNotes.size(), 1);
    BOOST_CHECK(!restarted.mapPrivateNotes.at(original_note.cmx).spent);
    BOOST_CHECK(restarted.mapPrivateSpentNullifiers.empty());
}

static CMutableTransaction TestSimpleSpend(const CTransaction& from, uint32_t index, const CKey& key, const CScript& pubkey)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(from.vout[index].nValue - DEFAULT_TRANSACTION_MAXFEE, pubkey);
    mtx.vin.push_back({CTxIn{from.GetHash(), index}});
    FillableSigningProvider keystore;
    keystore.AddKey(key);
    std::map<COutPoint, Coin> coins;
    coins[mtx.vin[0].prevout].out = from.vout[index];
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(mtx, &keystore, coins, SIGHASH_ALL, input_errors));
    return mtx;
}

static void AddKey(CWallet& wallet, const CKey& key)
{
    LOCK(wallet.cs_wallet);
    FlatSigningProvider provider;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse("combo(" + EncodeSecret(key) + ")", provider, error, /* require_checksum=*/ false);
    assert(desc);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
    if (!wallet.AddWalletDescriptor(w_desc, provider, "", false)) assert(false);
}

BOOST_FIXTURE_TEST_CASE(transparent_input_addresses_mempool_block_and_restore, TestChain100Setup)
{
    const CKey source_a{GenerateRandomKey()}, source_b{GenerateRandomKey()}, recipient{GenerateRandomKey()};
    const CTxDestination address_a{WitnessV0KeyHash(source_a.GetPubKey())};
    const CTxDestination address_b{WitnessV0KeyHash(source_b.GetPubKey())};
    const CTxDestination receive_address{WitnessV0KeyHash(recipient.GetPubKey())};
    auto wallet = std::make_shared<CWallet>(m_node.chain.get(), "input-addresses", CreateMockableWalletDatabase());
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    }
    AddKey(*wallet, recipient);

    const CAmount amount = m_coinbase_txns[0]->vout[0].nValue;
    const CAmount part = amount / 4;
    const auto parent = CreateValidMempoolTransaction(
        {m_coinbase_txns[0]}, {COutPoint(m_coinbase_txns[0]->GetHash(), 0)}, 1, {coinbaseKey},
        {{part, GetScriptForDestination(address_a)}, {part, GetScriptForDestination(address_a)},
         {amount - 2 * part - 1000, GetScriptForDestination(address_b)}});
    const auto parent_ref = MakeTransactionRef(parent);
    const auto child = CreateValidMempoolTransaction(
        {parent_ref}, {COutPoint(parent_ref->GetHash(), 0), COutPoint(parent_ref->GetHash(), 1), COutPoint(parent_ref->GetHash(), 2)},
        0, {source_a, source_b}, {{amount - 2000, GetScriptForDestination(receive_address)}});
    const auto child_ref = MakeTransactionRef(child);
    wallet->transactionAddedToMempool(child_ref);

    WalletContext context;
    context.chain = m_node.chain.get();
    context.args = m_node.args;
    auto interface = interfaces::MakeWallet(context, wallet);
    auto details = interface->getWalletTx(child_ref->GetHash());
    BOOST_REQUIRE(details.tx);
    BOOST_CHECK(details.txin_addresses_complete);
    BOOST_REQUIRE_EQUAL(details.txin_addresses.size(), 2);
    BOOST_CHECK(details.txin_addresses[0] == address_a);
    BOOST_CHECK(details.txin_addresses[1] == address_b);
    BOOST_CHECK_EQUAL(details.value_map.count("nito_input_addresses"), 0);

    // Same-block parent/child transactions exercise undo lookup, including
    // previous outputs which never existed in the final block UTXO view.
    const CBlock block = CreateAndProcessBlock({parent, child}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    const int height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    const auto block_info = WITH_LOCK(cs_main, return kernel::MakeBlockInfo(m_node.chainman->ActiveChain().Tip(), &block));
    wallet->blockConnected(ChainstateRole::NORMAL, block_info);
    BOOST_CHECK(interface->getWalletTx(child_ref->GetHash()).txin_addresses_complete);
    std::vector<CTxOut> previous_outputs;
    BOOST_CHECK(m_node.chain->findConfirmedTransactionInputs(*child_ref, block.GetHash(), 2, previous_outputs));
    BOOST_CHECK_EQUAL(previous_outputs.size(), 3);
    BOOST_CHECK(!m_node.chain->findConfirmedTransactionInputs(*child_ref, block.GetHash(), 1, previous_outputs));
    BOOST_CHECK(previous_outputs.empty());
    BOOST_CHECK(!m_node.chain->findConfirmedTransactionInputs(*child_ref, uint256::ONE, 2, previous_outputs));
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->AddToWallet(child_ref, TxStateInactive{}));
        BOOST_CHECK_EQUAL(wallet->mapWallet.at(child_ref->GetHash()).m_input_addresses.size(), 3);
        BOOST_REQUIRE(wallet->AddToWallet(child_ref, TxStateConfirmed{block.GetHash(), height, 2}));
    }

    // Persistence must not depend on the node retaining the spent outputs.
    CWallet offline(nullptr, "input-addresses-offline", DuplicateMockDatabase(wallet->GetDatabase()));
    BOOST_REQUIRE_EQUAL(offline.LoadWallet(), DBErrors::LOAD_OK);
    {
        LOCK(offline.cs_wallet);
        const auto& restored = offline.mapWallet.at(child_ref->GetHash());
        BOOST_CHECK_EQUAL(restored.m_input_addresses.size(), 3);
        BOOST_CHECK_EQUAL(restored.m_input_addresses.at(0), EncodeDestination(address_a));
        BOOST_CHECK_EQUAL(restored.m_input_addresses.at(2), EncodeDestination(address_b));
        BOOST_CHECK_EQUAL(restored.mapValue.count("nito_input_addresses"), 0);
    }

    // A wallet discovered by a historical scan, without seeing either mempool
    // transaction, obtains the same public input metadata from block undo data.
    auto rescanned = CreateSyncedWallet(*m_node.chain, m_node.chainman->ActiveChain(), recipient);
    {
        LOCK(rescanned->cs_wallet);
        auto& received = rescanned->mapWallet.at(child_ref->GetHash());
        BOOST_CHECK_EQUAL(received.m_input_addresses.size(), 3);
        received.m_input_addresses.clear(); // simulate an older V3/V4 record
        BOOST_REQUIRE(WalletBatch(rescanned->GetDatabase()).WriteTx(received));
    }
    rescanned->RefreshInputAddresses();
    {
        LOCK(rescanned->cs_wallet);
        BOOST_CHECK_EQUAL(rescanned->mapWallet.at(child_ref->GetHash()).m_input_addresses.size(), 3);
    }
}

BOOST_AUTO_TEST_CASE(transparent_input_addresses_partial_and_cache_validation)
{
    const CKey source{GenerateRandomKey()};
    const CTxDestination address{WitnessV0KeyHash(source.GetPubKey())};
    CMutableTransaction previous;
    previous.vout.emplace_back(COIN, GetScriptForDestination(address));
    auto previous_ref = MakeTransactionRef(previous);
    BOOST_REQUIRE(m_wallet.AddToWallet(previous_ref, TxStateInactive{}));
    CMutableTransaction received;
    received.vin.emplace_back(previous_ref->GetHash(), 0);
    received.vin.emplace_back(Txid::FromUint256(uint256::ONE), 0);
    received.vout.emplace_back(COIN, GetScriptForDestination(address));
    CWalletTx* stored = m_wallet.AddToWallet(MakeTransactionRef(received), TxStateInactive{});
    BOOST_REQUIRE(stored);
    BOOST_REQUIRE_EQUAL(stored->m_input_addresses.size(), 1);
    BOOST_CHECK_EQUAL(stored->m_input_addresses.at(0), EncodeDestination(address));

    const auto encoded = stored->SerializeInputAddresses();
    stored->DeserializeInputAddresses(encoded);
    BOOST_CHECK_EQUAL(stored->m_input_addresses.size(), 1);

    // A valid address substitution must not survive the checksum; a cache
    // copied from another transaction must not be attributed to that payment.
    DataStream cache{ParseHex(encoded)};
    std::map<uint32_t, std::string> addresses;
    uint256 checksum;
    cache >> addresses >> checksum;
    addresses[0] = EncodeDestination(WitnessV0KeyHash(GenerateRandomKey().GetPubKey()));
    DataStream altered;
    altered << addresses << checksum;
    stored->DeserializeInputAddresses(HexStr(altered));
    BOOST_CHECK(stored->m_input_addresses.empty());
    CMutableTransaction another{received};
    another.nLockTime = 1;
    CWalletTx another_wallet_tx{MakeTransactionRef(another), TxStateInactive{}};
    another_wallet_tx.DeserializeInputAddresses(encoded);
    BOOST_CHECK(another_wallet_tx.m_input_addresses.empty());
    stored->DeserializeInputAddresses(encoded.substr(0, encoded.size() - 2));
    BOOST_CHECK(stored->m_input_addresses.empty());
    stored->DeserializeInputAddresses("invalid cache");
    BOOST_CHECK(stored->m_input_addresses.empty());
    stored->m_input_addresses[5] = EncodeDestination(address);
    const auto invalid_index = stored->SerializeInputAddresses();
    stored->DeserializeInputAddresses(invalid_index);
    BOOST_CHECK(stored->m_input_addresses.empty());
    stored->m_input_addresses = m_wallet.ResolveInputAddresses(*stored);
    BOOST_CHECK_EQUAL(stored->m_input_addresses.size(), 1);

    CMutableTransaction mixed{received};
    mixed.m_private_bundle.emplace();
    CWalletTx mixed_wallet_tx{MakeTransactionRef(mixed), TxStateInactive{}};
    mixed_wallet_tx.m_input_addresses = stored->m_input_addresses;
    BOOST_CHECK(m_wallet.ResolveInputAddresses(mixed_wallet_tx).empty());
    mixed_wallet_tx.DeserializeInputAddresses(encoded);
    BOOST_CHECK(mixed_wallet_tx.m_input_addresses.empty());
}

BOOST_FIXTURE_TEST_CASE(scan_for_wallet_transactions, TestChain100Setup)
{
    const CAmount coinbase_amount{GetBlockSubsidy(/*nHeight=*/1, Params().GetConsensus())};

    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    WITH_LOCK(::cs_main, m_node.chainman->m_blockman.GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());

    // Verify ScanForWalletTransactions fails to read an unknown start block.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/{}, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        std::chrono::steady_clock::time_point fake_time;
        reserver.setNow([&] { fake_time += 60s; return fake_time; });
        reserver.reserve();

        {
            CBlockLocator locator;
            BOOST_CHECK(!WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_CHECK(locator.IsNull());
        }

        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/true);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 2 * coinbase_amount);

        {
            CBlockLocator locator;
            BOOST_CHECK(WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_CHECK(!locator.IsNull());
        }
    }

    // Prune the older block file.
    int file_number;
    {
        LOCK(cs_main);
        file_number = oldTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    m_node.chainman->m_blockman.UnlinkPrunedFiles({file_number});

    // Verify ScanForWalletTransactions only picks transactions in the new block
    // file.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, oldTip->GetBlockHash());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, coinbase_amount);
    }

    // Prune the remaining block file.
    {
        LOCK(cs_main);
        file_number = newTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    m_node.chainman->m_blockman.UnlinkPrunedFiles({file_number});

    // Verify ScanForWalletTransactions scans no blocks.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, newTip->GetBlockHash());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }
}

BOOST_FIXTURE_TEST_CASE(importmulti_rescan, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    WITH_LOCK(::cs_main, m_node.chainman->m_blockman.GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());

    // Prune the older block file.
    int file_number;
    {
        LOCK(cs_main);
        file_number = oldTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    m_node.chainman->m_blockman.UnlinkPrunedFiles({file_number});

    // Verify importmulti RPC returns failure for a key whose creation time is
    // before the missing block, and success for a key whose creation time is
    // after.
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        wallet->SetupLegacyScriptPubKeyMan();
        WITH_LOCK(wallet->cs_wallet, wallet->SetLastBlockProcessed(newTip->nHeight, newTip->GetBlockHash()));
        WalletContext context;
        context.args = &m_args;
        AddWallet(context, wallet);
        UniValue keys;
        keys.setArray();
        UniValue key;
        key.setObject();
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(coinbaseKey.GetPubKey())));
        key.pushKV("timestamp", 0);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        key.clear();
        key.setObject();
        CKey futureKey = GenerateRandomKey();
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(futureKey.GetPubKey())));
        key.pushKV("timestamp", newTip->GetBlockTimeMax() + TIMESTAMP_WINDOW + 1);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        JSONRPCRequest request;
        request.context = &context;
        request.params.setArray();
        request.params.push_back(keys);

        UniValue response = importmulti().HandleRequest(request);
        BOOST_CHECK_EQUAL(response.write(),
            strprintf("[{\"success\":false,\"error\":{\"code\":-1,\"message\":\"Rescan failed for key with creation "
                      "timestamp %d. There was an error reading a block from time %d, which is after or within %d "
                      "seconds of key creation, and could contain transactions pertaining to the key. As a result, "
                      "transactions and coins using this key may not appear in the wallet. This error could be caused "
                      "by pruning or data corruption (see nitod log for details) and could be dealt with by "
                      "downloading and rescanning the relevant blocks (see -reindex option and rescanblockchain "
                      "RPC).\"}},{\"success\":true}]",
                              0, oldTip->GetBlockTimeMax(), TIMESTAMP_WINDOW));
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
    }
}

// Verify importwallet RPC starts rescan at earliest block with timestamp
// greater or equal than key birthday. Previously there was a bug where
// importwallet RPC would start the scan at the latest block with timestamp less
// than or equal to key birthday.
BOOST_FIXTURE_TEST_CASE(importwallet_rescan, TestChain100Setup)
{
    // Create two blocks with same timestamp to verify that importwallet rescan
    // will pick up both blocks, not just the first.
    const int64_t BLOCK_TIME = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockTimeMax() + 5);
    SetMockTime(BLOCK_TIME);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    // Set key birthday to block time increased by the timestamp window, so
    // rescan will start at the block time.
    const int64_t KEY_TIME = BLOCK_TIME + TIMESTAMP_WINDOW;
    SetMockTime(KEY_TIME);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    std::string backup_file = fs::PathToString(m_args.GetDataDirNet() / "wallet.backup");

    // Import key into wallet and call dumpwallet to create backup file.
    {
        WalletContext context;
        context.args = &m_args;
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            auto spk_man = wallet->GetOrCreateLegacyScriptPubKeyMan();
            LOCK2(wallet->cs_wallet, spk_man->cs_KeyStore);
            spk_man->mapKeyMetadata[coinbaseKey.GetPubKey().GetID()].nCreateTime = KEY_TIME;
            spk_man->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());

            AddWallet(context, wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        JSONRPCRequest request;
        request.context = &context;
        request.params.setArray();
        request.params.push_back(backup_file);

        wallet::dumpwallet().HandleRequest(request);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
    }

    // Call importwallet RPC and verify all blocks with timestamps >= BLOCK_TIME
    // were scanned, and no prior blocks were scanned.
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        LOCK(wallet->cs_wallet);
        wallet->SetupLegacyScriptPubKeyMan();

        WalletContext context;
        context.args = &m_args;
        JSONRPCRequest request;
        request.context = &context;
        request.params.setArray();
        request.params.push_back(backup_file);
        AddWallet(context, wallet);
        LOCK(Assert(m_node.chainman)->GetMutex());
        wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        wallet::importwallet().HandleRequest(request);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);

        BOOST_CHECK_EQUAL(wallet->mapWallet.size(), 3U);
        BOOST_CHECK_EQUAL(m_coinbase_txns.size(), 103U);
        for (size_t i = 0; i < m_coinbase_txns.size(); ++i) {
            bool found = wallet->GetWalletTx(m_coinbase_txns[i]->GetHash());
            bool expected = i >= 100;
            BOOST_CHECK_EQUAL(found, expected);
        }
    }
}

// Check that GetImmatureCredit() returns a newly calculated value instead of
// the cached value after a MarkDirty() call.
//
// This is a regression test written to verify a bugfix for the immature credit
// function. Similar tests probably should be written for the other credit and
// debit functions.
BOOST_FIXTURE_TEST_CASE(coin_mark_dirty_immature_credit, TestChain100Setup)
{
    const CAmount coinbase_amount{GetBlockSubsidy(/*nHeight=*/1, Params().GetConsensus())};
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());

    LOCK(wallet.cs_wallet);
    LOCK(Assert(m_node.chainman)->GetMutex());
    CWalletTx wtx{m_coinbase_txns.back(), TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/0}};
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());

    // Call GetImmatureCredit() once before adding the key to the wallet to
    // cache the current immature credit amount, which is 0.
    BOOST_CHECK_EQUAL(CachedTxGetImmatureCredit(wallet, wtx, ISMINE_SPENDABLE), 0);

    // Invalidate the cached value, add the key, and make sure a new immature
    // credit amount is calculated.
    wtx.MarkDirty();
    AddKey(wallet, coinbaseKey);
    BOOST_CHECK_EQUAL(CachedTxGetImmatureCredit(wallet, wtx, ISMINE_SPENDABLE), coinbase_amount);
}

static int64_t AddTx(ChainstateManager& chainman, CWallet& wallet, uint32_t lockTime, int64_t mockTime, int64_t blockTime)
{
    CMutableTransaction tx;
    TxState state = TxStateInactive{};
    tx.nLockTime = lockTime;
    SetMockTime(mockTime);
    CBlockIndex* block = nullptr;
    if (blockTime > 0) {
        LOCK(cs_main);
        auto inserted = chainman.BlockIndex().emplace(std::piecewise_construct, std::make_tuple(GetRandHash()), std::make_tuple());
        assert(inserted.second);
        const uint256& hash = inserted.first->first;
        block = &inserted.first->second;
        block->nTime = blockTime;
        block->phashBlock = &hash;
        state = TxStateConfirmed{hash, block->nHeight, /*index=*/0};
    }
    return wallet.AddToWallet(MakeTransactionRef(tx), state, [&](CWalletTx& wtx, bool /* new_tx */) {
        // Assign wtx.m_state to simplify test and avoid the need to simulate
        // reorg events. Without this, AddToWallet asserts false when the same
        // transaction is confirmed in different blocks.
        wtx.m_state = state;
        return true;
    })->nTimeSmart;
}

// Simple test to verify assignment of CWalletTx::nSmartTime value. Could be
// expanded to cover more corner cases of smart time logic.
BOOST_AUTO_TEST_CASE(ComputeTimeSmart)
{
    // New transaction should use clock time if lower than block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 100, 120), 100);

    // Test that updating existing transaction does not change smart time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 200, 220), 100);

    // New transaction should use clock time if there's no block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 2, 300, 0), 300);

    // New transaction should use block time if lower than clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 3, 420, 400), 400);

    // New transaction should use latest entry time if higher than
    // min(block time, clock time).
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 4, 500, 390), 400);

    // If there are future entries, new transaction should use time of the
    // newest entry that is no more than 300 seconds ahead of the clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 5, 50, 600), 300);
}

void TestLoadWallet(const std::string& name, DatabaseFormat format, std::function<void(std::shared_ptr<CWallet>)> f)
{
    node::NodeContext node;
    auto chain{interfaces::MakeChain(node)};
    DatabaseOptions options;
    options.require_format = format;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database{MakeWalletDatabase(name, options, status, error)};
    auto wallet{std::make_shared<CWallet>(chain.get(), "", std::move(database))};
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::LOAD_OK);
    WITH_LOCK(wallet->cs_wallet, f(wallet));
}

BOOST_FIXTURE_TEST_CASE(LoadReceiveRequests, TestingSetup)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string name{strprintf("receive-requests-%i", format)};
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(PKHash()));
            WalletBatch batch{wallet->GetDatabase()};
            BOOST_CHECK(batch.WriteAddressPreviouslySpent(PKHash(), true));
            BOOST_CHECK(batch.WriteAddressPreviouslySpent(ScriptHash(), true));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "0", "val_rr00"));
            BOOST_CHECK(wallet->EraseAddressReceiveRequest(batch, PKHash(), "0"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "1", "val_rr10"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "1", "val_rr11"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, ScriptHash(), "2", "val_rr20"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, CNoDestination(), "3", "val_rr30"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, CNoDestination(), "4", "val_rr40"));
            BOOST_CHECK(wallet->EraseAddressReceiveRequest(batch, CNoDestination(), "4"));
        });
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(wallet->IsAddressPreviouslySpent(PKHash()));
            BOOST_CHECK(wallet->IsAddressPreviouslySpent(ScriptHash()));
            BOOST_CHECK(!wallet->m_address_book.count(CNoDestination()));
            auto requests = wallet->GetAddressReceiveRequests();
            auto erequests = {"val_rr30", "val_rr11", "val_rr20"};
            BOOST_CHECK_EQUAL_COLLECTIONS(requests.begin(), requests.end(), std::begin(erequests), std::end(erequests));
            RunWithinTxn(wallet->GetDatabase(), /*process_desc*/"test", [](WalletBatch& batch){
                BOOST_CHECK(batch.WriteAddressPreviouslySpent(PKHash(), false));
                BOOST_CHECK(batch.EraseAddressData(ScriptHash()));
                return true;
            });
        });
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(PKHash()));
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(ScriptHash()));
            auto requests = wallet->GetAddressReceiveRequests();
            auto erequests = {"val_rr30", "val_rr11"};
            BOOST_CHECK_EQUAL_COLLECTIONS(requests.begin(), requests.end(), std::begin(erequests), std::end(erequests));
        });
    }
}

// Test some watch-only LegacyScriptPubKeyMan methods by the procedure of loading (LoadWatchOnly),
// checking (HaveWatchOnly), getting (GetWatchPubKey) and removing (RemoveWatchOnly) a
// given PubKey, resp. its corresponding P2PK Script. Results of the impact on
// the address -> PubKey map is dependent on whether the PubKey is a point on the curve
static void TestWatchOnlyPubKey(LegacyScriptPubKeyMan* spk_man, const CPubKey& add_pubkey)
{
    CScript p2pk = GetScriptForRawPubKey(add_pubkey);
    CKeyID add_address = add_pubkey.GetID();
    CPubKey found_pubkey;
    LOCK(spk_man->cs_KeyStore);

    // all Scripts (i.e. also all PubKeys) are added to the general watch-only set
    BOOST_CHECK(!spk_man->HaveWatchOnly(p2pk));
    spk_man->LoadWatchOnly(p2pk);
    BOOST_CHECK(spk_man->HaveWatchOnly(p2pk));

    // only PubKeys on the curve shall be added to the watch-only address -> PubKey map
    bool is_pubkey_fully_valid = add_pubkey.IsFullyValid();
    if (is_pubkey_fully_valid) {
        BOOST_CHECK(spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == add_pubkey);
    } else {
        BOOST_CHECK(!spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == CPubKey()); // passed key is unchanged
    }

    spk_man->RemoveWatchOnly(p2pk);
    BOOST_CHECK(!spk_man->HaveWatchOnly(p2pk));

    if (is_pubkey_fully_valid) {
        BOOST_CHECK(!spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == add_pubkey); // passed key is unchanged
    }
}

// Cryptographically invalidate a PubKey whilst keeping length and first byte
static void PollutePubKey(CPubKey& pubkey)
{
    std::vector<unsigned char> pubkey_raw(pubkey.begin(), pubkey.end());
    std::fill(pubkey_raw.begin()+1, pubkey_raw.end(), 0);
    pubkey = CPubKey(pubkey_raw);
    assert(!pubkey.IsFullyValid());
    assert(pubkey.IsValid());
}

// Test watch-only logic for PubKeys
BOOST_AUTO_TEST_CASE(WatchOnlyPubKeys)
{
    CKey key;
    CPubKey pubkey;
    LegacyScriptPubKeyMan* spk_man = m_wallet.GetOrCreateLegacyScriptPubKeyMan();

    BOOST_CHECK(!spk_man->HaveWatchOnly());

    // uncompressed valid PubKey
    key.MakeNewKey(false);
    pubkey = key.GetPubKey();
    assert(!pubkey.IsCompressed());
    TestWatchOnlyPubKey(spk_man, pubkey);

    // uncompressed cryptographically invalid PubKey
    PollutePubKey(pubkey);
    TestWatchOnlyPubKey(spk_man, pubkey);

    // compressed valid PubKey
    key.MakeNewKey(true);
    pubkey = key.GetPubKey();
    assert(pubkey.IsCompressed());
    TestWatchOnlyPubKey(spk_man, pubkey);

    // compressed cryptographically invalid PubKey
    PollutePubKey(pubkey);
    TestWatchOnlyPubKey(spk_man, pubkey);

    // invalid empty PubKey
    pubkey = CPubKey();
    TestWatchOnlyPubKey(spk_man, pubkey);
}

class ListCoinsTestingSetup : public TestChain100Setup
{
public:
    ListCoinsTestingSetup()
    {
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    }

    ~ListCoinsTestingSetup()
    {
        wallet.reset();
    }

    CWalletTx& AddTx(CRecipient recipient)
    {
        CTransactionRef tx;
        CCoinControl dummy;
        {
            auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, dummy);
            BOOST_CHECK(res);
            tx = res->tx;
        }
        BOOST_CHECK(wallet->CommitTransaction(tx, {}, {}));
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            blocktx = CMutableTransaction(*wallet->mapWallet.at(tx->GetHash()).tx);
        }
        CreateAndProcessBlock({CMutableTransaction(blocktx)}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

        LOCK(wallet->cs_wallet);
        LOCK(Assert(m_node.chainman)->GetMutex());
        wallet->SetLastBlockProcessed(wallet->GetLastBlockHeight() + 1, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        auto it = wallet->mapWallet.find(tx->GetHash());
        BOOST_CHECK(it != wallet->mapWallet.end());
        it->second.m_state = TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/1};
        return it->second;
    }

    std::unique_ptr<CWallet> wallet;
};

BOOST_FIXTURE_TEST_CASE(ListCoinsTest, ListCoinsTestingSetup)
{
    std::string coinbaseAddress = coinbaseKey.GetPubKey().GetID().ToString();

    // Confirm ListCoins initially returns 1 coin grouped under coinbaseKey
    // address.
    std::map<CTxDestination, std::vector<COutput>> list;
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 1U);

    // Check initial balance from one mature coinbase transaction.
    BOOST_CHECK_EQUAL(GetBlockSubsidy(/*nHeight=*/1, Params().GetConsensus()), WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet).GetTotalAmount()));

    // Add a transaction creating a change address, and confirm ListCoins still
    // returns the coin associated with the change address underneath the
    // coinbaseKey pubkey, even though the change address has a different
    // pubkey.
    AddTx(CRecipient{PubKeyDestination{{}}, 1 * COIN, /*subtract_fee=*/false});
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);

    // Lock both coins. Confirm number of available coins drops to 0.
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoinsListUnspent(*wallet).Size(), 2U);
    }
    for (const auto& group : list) {
        for (const auto& coin : group.second) {
            LOCK(wallet->cs_wallet);
            wallet->LockCoin(coin.outpoint);
        }
    }
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoinsListUnspent(*wallet).Size(), 0U);
    }
    // Confirm ListCoins still returns same result as before, despite coins
    // being locked.
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);
}

void TestCoinsResult(ListCoinsTest& context, OutputType out_type, CAmount amount,
                     std::map<OutputType, size_t>& expected_coins_sizes)
{
    LOCK(context.wallet->cs_wallet);
    util::Result<CTxDestination> dest = Assert(context.wallet->GetNewDestination(out_type, ""));
    CWalletTx& wtx = context.AddTx(CRecipient{*dest, amount, /*fSubtractFeeFromAmount=*/true});
    CoinFilterParams filter;
    filter.skip_locked = false;
    CoinsResult available_coins = AvailableCoins(*context.wallet, nullptr, std::nullopt, filter);

    size_t new_outputs_found{0};
    std::map<OutputType, size_t> new_outputs_by_type;
    for (const auto& [type, coins] : available_coins.coins) {
        for (const auto& coin : coins) {
            if (coin.outpoint.hash == wtx.GetHash()) {
                ++new_outputs_by_type[type];
                ++new_outputs_found;
            }
        }
    }
    BOOST_CHECK_EQUAL(new_outputs_found, wtx.tx->vout.size());
    for (const auto& [type, size] : new_outputs_by_type) expected_coins_sizes[type] += size;

    // Lock outputs so they are not spent in follow-up transactions
    for (uint32_t i = 0; i < wtx.tx->vout.size(); i++) context.wallet->LockCoin({wtx.GetHash(), i});
    for (const auto& [type, size] : expected_coins_sizes) BOOST_CHECK_EQUAL(size, available_coins.coins[type].size());
}

BOOST_FIXTURE_TEST_CASE(BasicOutputTypesTest, ListCoinsTest)
{
    std::map<OutputType, size_t> expected_coins_sizes;
    for (const auto& out_type : OUTPUT_TYPES) { expected_coins_sizes[out_type] = 0U; }

    // Verify our wallet has one usable coinbase UTXO before starting
    // This UTXO is a P2PK, so it should show up in the Other bucket
    expected_coins_sizes[OutputType::UNKNOWN] = 1U;
    CoinsResult available_coins = WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet));
    BOOST_CHECK_EQUAL(available_coins.Size(), expected_coins_sizes[OutputType::UNKNOWN]);
    BOOST_CHECK_EQUAL(available_coins.coins[OutputType::UNKNOWN].size(), expected_coins_sizes[OutputType::UNKNOWN]);

    // We will create a self transfer for each of the OutputTypes and
    // verify each new wallet output is put in the matching AvailableCoins bucket.

    for (const auto& out_type : OUTPUT_TYPES) {
        if (out_type == OutputType::UNKNOWN) continue;
        TestCoinsResult(*this, out_type, 1 * COIN, expected_coins_sizes);
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_disableprivkeys, TestChain100Setup)
{
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        wallet->SetupLegacyScriptPubKeyMan();
        wallet->SetMinVersion(FEATURE_LATEST);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        BOOST_CHECK(!wallet->TopUpKeyPool(1000));
        BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
    }
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetMinVersion(FEATURE_LATEST);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
    }
}

// Explicit calculation which is used to test the wallet constant
// We get the same virtual size due to rounding(weight/4) for both use_max_sig values
static size_t CalculateNestedKeyhashInputSize(bool use_max_sig)
{
    // Generate ephemeral valid pubkey
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();

    // Generate pubkey hash
    uint160 key_hash(Hash160(pubkey));

    // Create inner-script to enter into keystore. Key hash can't be 0...
    CScript inner_script = CScript() << OP_0 << std::vector<unsigned char>(key_hash.begin(), key_hash.end());

    // Create outer P2SH script for the output
    uint160 script_id(Hash160(inner_script));
    CScript script_pubkey = CScript() << OP_HASH160 << std::vector<unsigned char>(script_id.begin(), script_id.end()) << OP_EQUAL;

    // Add inner-script to key store and key to watchonly
    FillableSigningProvider keystore;
    keystore.AddCScript(inner_script);
    keystore.AddKeyPubKey(key, pubkey);

    // Fill in dummy signatures for fee calculation.
    SignatureData sig_data;

    if (!ProduceSignature(keystore, use_max_sig ? DUMMY_MAXIMUM_SIGNATURE_CREATOR : DUMMY_SIGNATURE_CREATOR, script_pubkey, sig_data)) {
        // We're hand-feeding it correct arguments; shouldn't happen
        assert(false);
    }

    CTxIn tx_in;
    UpdateInput(tx_in, sig_data);
    return (size_t)GetVirtualTransactionInputSize(tx_in);
}

BOOST_FIXTURE_TEST_CASE(dummy_input_size_test, TestChain100Setup)
{
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(false), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(true), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
}

bool malformed_descriptor(std::ios_base::failure e)
{
    std::string s(e.what());
    return s.find("Missing checksum") != std::string::npos;
}

BOOST_FIXTURE_TEST_CASE(wallet_descriptor_test, BasicTestingSetup)
{
    std::vector<unsigned char> malformed_record;
    VectorWriter vw{malformed_record, 0};
    vw << std::string("notadescriptor");
    vw << uint64_t{0};
    vw << int32_t{0};
    vw << int32_t{0};
    vw << int32_t{1};

    SpanReader vr{malformed_record};
    WalletDescriptor w_desc;
    BOOST_CHECK_EXCEPTION(vr >> w_desc, std::ios_base::failure, malformed_descriptor);
}

//! Test CWallet::Create() and its behavior handling potential race
//! conditions if it's called the same time an incoming transaction shows up in
//! the mempool or a new block.
//!
//! It isn't possible to verify there aren't race condition in every case, so
//! this test just checks two specific cases and ensures that timing of
//! notifications in these cases doesn't prevent the wallet from detecting
//! transactions.
//!
//! In the first case, block and mempool transactions are created before the
//! wallet is loaded, but notifications about these transactions are delayed
//! until after it is loaded. The notifications are superfluous in this case, so
//! the test verifies the transactions are detected before they arrive.
//!
//! In the second case, block and mempool transactions are created after the
//! wallet rescan and notifications are immediately synced, to verify the wallet
//! must already have a handler in place for them, and there's no gap after
//! rescanning where new transactions in new blocks could be lost.
BOOST_FIXTURE_TEST_CASE(CreateWallet, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    // Create new wallet with known key and unload it.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestLoadWallet(context);
    CKey key = GenerateRandomKey();
    AddKey(*wallet, key);
    TestUnloadWallet(std::move(wallet));


    // Add log hook to detect AddToWallet events from rescans, blockConnected,
    // and transactionAddedToMempool notifications
    int addtx_count = 0;
    DebugLogHelper addtx_counter("[default wallet] AddToWallet", [&](const std::string* s) {
        if (s) ++addtx_count;
        return false;
    });


    bool rescan_completed = false;
    DebugLogHelper rescan_check("[default wallet] Rescan completed", [&](const std::string* s) {
        if (s) rescan_completed = true;
        return false;
    });


    // Block the queue to prevent the wallet receiving blockConnected and
    // transactionAddedToMempool notifications, and create block and mempool
    // transactions paying to the wallet
    std::promise<void> promise;
    CallFunctionInValidationInterfaceQueue([&promise] {
        promise.get_future().wait();
    });
    std::string error;
    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto mempool_tx = TestSimpleSpend(*m_coinbase_txns[1], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, false, error));


    // Reload wallet and make sure new transactions are detected despite events
    // being blocked
    // Loading will also ask for current mempool transactions
    wallet = TestLoadWallet(context);
    BOOST_CHECK(rescan_completed);
    // AddToWallet events for block_tx and mempool_tx (x2)
    BOOST_CHECK_EQUAL(addtx_count, 3);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_tx.GetHash()), 1U);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(mempool_tx.GetHash()), 1U);
    }


    // Unblock notification queue and make sure stale blockConnected and
    // transactionAddedToMempool events are processed
    promise.set_value();
    SyncWithValidationInterfaceQueue();
    // AddToWallet events for block_tx and mempool_tx events are counted a
    // second time as the notification queue is processed
    BOOST_CHECK_EQUAL(addtx_count, 5);


    TestUnloadWallet(std::move(wallet));


    // Load wallet again, this time creating new block and mempool transactions
    // paying to the wallet as the wallet finishes loading and syncing the
    // queue so the events have to be handled immediately. Releasing the wallet
    // lock during the sync is a little artificial but is needed to avoid a
    // deadlock during the sync and simulates a new block notification happening
    // as soon as possible.
    addtx_count = 0;
    auto handler = HandleLoadWallet(context, [&](std::unique_ptr<interfaces::Wallet> wallet) {
            BOOST_CHECK(rescan_completed);
            m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            block_tx = TestSimpleSpend(*m_coinbase_txns[2], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            mempool_tx = TestSimpleSpend(*m_coinbase_txns[3], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, false, error));
            SyncWithValidationInterfaceQueue();
        });
    wallet = TestLoadWallet(context);
    // Since mempool transactions are requested at the end of loading, there will
    // be 2 additional AddToWallet calls, one from the previous test, and a duplicate for mempool_tx
    BOOST_CHECK_EQUAL(addtx_count, 2 + 2);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_tx.GetHash()), 1U);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(mempool_tx.GetHash()), 1U);
    }


    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(CreateWalletWithoutChain, BasicTestingSetup)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestLoadWallet(context);
    BOOST_CHECK(wallet);
    UnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(RemoveTxs, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestLoadWallet(context);
    CKey key = GenerateRandomKey();
    AddKey(*wallet, key);

    std::string error;
    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    SyncWithValidationInterfaceQueue();

    {
        auto block_hash = block_tx.GetHash();
        auto prev_tx = m_coinbase_txns[0];

        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->HasWalletSpend(prev_tx));
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_hash), 1u);

        std::vector<uint256> vHashIn{ block_hash };
        BOOST_CHECK(wallet->RemoveTxs(vHashIn));

        BOOST_CHECK(!wallet->HasWalletSpend(prev_tx));
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_hash), 0u);
    }

    TestUnloadWallet(std::move(wallet));
}

/**
 * Checks a wallet invalid state where the inputs (prev-txs) of a new arriving transaction are not marked dirty,
 * while the transaction that spends them exist inside the in-memory wallet tx map (not stored on db due a db write failure).
 */
BOOST_FIXTURE_TEST_CASE(wallet_sync_tx_invalid_state_test, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    // Add tx to wallet
    const auto op_dest{*Assert(wallet.GetNewDestination(OutputType::BECH32M, ""))};

    CMutableTransaction mtx;
    mtx.vout.emplace_back(COIN, GetScriptForDestination(op_dest));
    mtx.vin.emplace_back(Txid::FromUint256(g_insecure_rand_ctx.rand256()), 0);
    const auto& tx_id_to_spend = wallet.AddToWallet(MakeTransactionRef(mtx), TxStateInMempool{})->GetHash();

    {
        // Cache and verify available balance for the wtx
        LOCK(wallet.cs_wallet);
        const CWalletTx* wtx_to_spend = wallet.GetWalletTx(tx_id_to_spend);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *wtx_to_spend), 1 * COIN);
    }

    // Now the good case:
    // 1) Add a transaction that spends the previously created transaction
    // 2) Verify that the available balance of this new tx and the old one is updated (prev tx is marked dirty)

    mtx.vin.clear();
    mtx.vin.emplace_back(tx_id_to_spend, 0);
    wallet.transactionAddedToMempool(MakeTransactionRef(mtx));
    const auto good_tx_id{mtx.GetHash()};

    {
        // Verify balance update for the new tx and the old one
        LOCK(wallet.cs_wallet);
        const CWalletTx* new_wtx = wallet.GetWalletTx(good_tx_id.ToUint256());
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *new_wtx), 1 * COIN);

        // Now the old wtx
        const CWalletTx* wtx_to_spend = wallet.GetWalletTx(tx_id_to_spend);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *wtx_to_spend), 0 * COIN);
    }

    // Now the bad case:
    // 1) Make db always fail
    // 2) Try to add a transaction that spends the previously created transaction and
    //    verify that we are not moving forward if the wallet cannot store it
    GetMockableDatabase(wallet).m_pass = false;
    mtx.vin.clear();
    mtx.vin.emplace_back(good_tx_id, 0);
    BOOST_CHECK_EXCEPTION(wallet.transactionAddedToMempool(MakeTransactionRef(mtx)),
                          std::runtime_error,
                          HasReason("DB error adding transaction to wallet, write failed"));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
