// Copyright (c) 2020-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <test/util/setup_common.h>
#include <script/solver.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/test/util.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(scriptpubkeyman_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(watch_only_change_reservation)
{
    // A pre-HD watch-only wallet must not be mistaken for a wallet that can
    // generate random keys. Fresh change reservation must fail gracefully.
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    wallet.SetupLegacyScriptPubKeyMan();
    auto& keyman = *wallet.GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(!keyman.CanGenerateKeys());
    BOOST_CHECK(!keyman.TopUp());
    ReserveDestination change(&wallet, OutputType::BECH32);
    BOOST_CHECK(!change.GetReservedDestination(/*internal=*/true));

    // Public keys explicitly imported into a watch-only keypool remain usable.
    wallet.SetMinVersion(FEATURE_LATEST);
    const CPubKey pubkey = GenerateRandomKey().GetPubKey();
    BOOST_REQUIRE(wallet.ImportPubKeys({pubkey.GetID()}, {{pubkey.GetID(), pubkey}},
                                      /*key_origins=*/{}, /*add_keypool=*/true,
                                      /*internal=*/true, /*timestamp=*/1));
    BOOST_REQUIRE(!keyman.CanGenerateKeys());
    auto destination = change.GetReservedDestination(/*internal=*/true);
    BOOST_REQUIRE(destination);
    BOOST_CHECK(*destination == GetDestinationForKey(pubkey, OutputType::BECH32));
    change.KeepDestination();
    BOOST_CHECK(!keyman.HavePrivateKeys());
    BOOST_CHECK(!change.GetReservedDestination(/*internal=*/true));
}

// Test LegacyScriptPubKeyMan::CanProvide behavior, making sure it returns true
// for recognized scripts even when keys may not be available for signing.
BOOST_AUTO_TEST_CASE(CanProvide)
{
    // Set up wallet and keyman variables.
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LegacyScriptPubKeyMan& keyman = *wallet.GetOrCreateLegacyScriptPubKeyMan();

    // Make a 1 of 2 multisig script
    std::vector<CKey> keys(2);
    std::vector<CPubKey> pubkeys;
    for (CKey& key : keys) {
        key.MakeNewKey(true);
        pubkeys.emplace_back(key.GetPubKey());
    }
    CScript multisig_script = GetScriptForMultisig(1, pubkeys);
    CScript p2sh_script = GetScriptForDestination(ScriptHash(multisig_script));
    SignatureData data;

    // Verify the p2sh(multisig) script is not recognized until the multisig
    // script is added to the keystore to make it solvable
    BOOST_CHECK(!keyman.CanProvide(p2sh_script, data));
    keyman.AddCScript(multisig_script);
    BOOST_CHECK(keyman.CanProvide(p2sh_script, data));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
