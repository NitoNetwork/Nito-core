// Copyright (c) 2021-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/private_tx_verify.h>
#include <policy/fees.h>
#include <script/solver.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <algorithm>
#include <array>
#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(private_note_selection_and_consolidation)
{
    LOCK(m_wallet.cs_wallet);
    const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
    BOOST_REQUIRE(tip);
    m_wallet.SetLastBlockProcessed(tip->nHeight, tip->GetBlockHash());
    auto add_note = [&](unsigned id, CAmount value) -> uint256 {
        CPrivateWalletNote note;
        note.cmx = uint256{static_cast<uint8_t>(id)};
        note.nullifier = note.cmx;
        note.txid = note.cmx;
        note.block_hash = tip->GetBlockHash();
        note.block_height = tip->nHeight;
        note.commitment_index = id;
        note.value = value;
        note.decrypted = true;
        note.recipient_raw.resize(43, 1);
        note.rho.resize(32, 1);
        note.rseed.resize(32, 1);
        m_wallet.mapPrivateNotes.emplace(note.cmx, note);
        return note.cmx;
    };
    CCoinControl automatic, consolidate;
    for (unsigned i = 1; i <= MAX_PRIVATE_ORCHARD_ACTIONS; ++i) {
        consolidate.SelectPrivateNote(add_note(i, COIN / 100));
    }
    const uint256 large = add_note(100, 10 * COIN);
    std::vector<const CPrivateWalletNote*> selected;
    CAmount value{0};
    BOOST_REQUIRE(SelectPrivateNotes(m_wallet, COIN, automatic, selected, value));
    BOOST_REQUIRE_EQUAL(selected.size(), 1U);
    BOOST_CHECK(selected.front()->cmx == large);

    // A wallet with more than 50 notes can still consolidate a chosen batch.
    BOOST_REQUIRE(SelectPrivateNotes(m_wallet, COIN / 4, consolidate, selected, value));
    BOOST_CHECK_EQUAL(selected.size(), MAX_PRIVATE_ORCHARD_ACTIONS);
    BOOST_CHECK_EQUAL(value, COIN / 2);
    consolidate.SelectPrivateNote(large);
    BOOST_CHECK(!SelectPrivateNotes(m_wallet, COIN / 4, consolidate, selected, value));
    consolidate.UnSelectPrivateNote(large);
    m_wallet.mapPrivateNotes[uint256{1}].spent = true;
    BOOST_CHECK(!SelectPrivateNotes(m_wallet, COIN / 4, consolidate, selected, value));
    m_wallet.mapPrivateNotes[uint256{1}].spent = false;
    m_wallet.mapPrivateNotes[large].spent = true;
    BOOST_CHECK(!SelectPrivateNotes(m_wallet, COIN, automatic, selected, value));
    BOOST_REQUIRE(SelectPrivateNotes(m_wallet, COIN / 2, automatic, selected, value));
    BOOST_CHECK_EQUAL(selected.size(), MAX_PRIVATE_ORCHARD_ACTIONS);
    m_wallet.mapPrivateNotes[uint256{1}].block_hash = uint256{255};
    BOOST_CHECK(!SelectPrivateNotes(m_wallet, COIN / 2, automatic, selected, value));
}

BOOST_AUTO_TEST_CASE(transaction_change_type)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.m_keypool_size = 1;
    wallet.SetupDescriptorScriptPubKeyMans();

    // Bitcoin Core prioritizes supported recipient types, not input types.
    const std::array types{OutputType::BECH32M, OutputType::BECH32, OutputType::P2SH_SEGWIT, OutputType::LEGACY};
    std::vector<CRecipient> recipients;
    for (const auto type : types) {
        recipients.push_back({*Assert(wallet.GetNewDestination(type, "")), COIN, false});
    }
    for (const auto default_type : types) {
        wallet.m_default_address_type = default_type;
        for (unsigned mask = 0; mask < (1U << types.size()); ++mask) {
            std::vector<CRecipient> selected;
            OutputType expected{OutputType::BECH32M};
            for (size_t i = 0; i < types.size(); ++i) {
                if (mask & (1U << i)) {
                    if (selected.empty()) expected = types[i];
                    selected.push_back(recipients[i]);
                }
            }
            if (default_type == OutputType::LEGACY) expected = OutputType::LEGACY;
            BOOST_CHECK(wallet.TransactionChangeType(std::nullopt, selected) == expected);
            // Explicit overrides take priority, including over a legacy default.
            for (const auto override_type : types) {
                BOOST_CHECK(wallet.TransactionChangeType(override_type, selected) == override_type);
            }
            std::reverse(selected.begin(), selected.end());
            BOOST_CHECK(wallet.TransactionChangeType(std::nullopt, selected) == expected);
        }
    }

    wallet.m_default_address_type = OutputType::P2SH_SEGWIT;
    // P2WSH is not a native key-hash match; neither is an Orchard recipient's
    // nonstandard transparent placeholder. Both use the supported-type fallback.
    const std::vector<CRecipient> unmatched{{WitnessV0ScriptHash{}, COIN, false}, {CNoDestination{}, COIN, false}};
    BOOST_CHECK(wallet.TransactionChangeType(std::nullopt, unmatched) == OutputType::BECH32M);
    auto* taproot = Assert(wallet.GetScriptPubKeyMan(OutputType::BECH32M, true));
    wallet.DeactivateScriptPubKeyMan(taproot->GetID(), OutputType::BECH32M, true);
    BOOST_CHECK(wallet.TransactionChangeType(std::nullopt, unmatched) == OutputType::BECH32);
    BOOST_CHECK(wallet.TransactionChangeType(std::nullopt, recipients) == OutputType::BECH32);
    BOOST_CHECK(wallet.TransactionChangeType(std::nullopt, {recipients[0], recipients[2]}) == OutputType::P2SH_SEGWIT);
    auto* bech32 = Assert(wallet.GetScriptPubKeyMan(OutputType::BECH32, true));
    wallet.DeactivateScriptPubKeyMan(bech32->GetID(), OutputType::BECH32, true);
    BOOST_CHECK(wallet.TransactionChangeType(std::nullopt, unmatched) == OutputType::P2SH_SEGWIT);
    BOOST_CHECK(wallet.TransactionChangeType(std::nullopt, recipients) == OutputType::P2SH_SEGWIT);
    BOOST_CHECK(wallet.TransactionChangeType(std::nullopt, {recipients[0], recipients[3]}) == OutputType::LEGACY);
}

BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    // Check that a subtract-from-recipient transaction slightly less than the
    // coinbase input amount does not create a change output (because it would
    // be uneconomical to add and spend the output), and make sure it pays the
    // leftover input amount which would have been change to the recipient
    // instead of the miner.
    const CAmount coinbase_input_amount = WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet).GetTotalAmount());
    BOOST_REQUIRE_EQUAL(coinbase_input_amount, GetBlockSubsidy(/*nHeight=*/1, Assert(m_node.chainman)->GetConsensus()));

    auto check_tx = [&wallet, coinbase_input_amount](CAmount leftover_input_amount) {
        CRecipient recipient{PubKeyDestination({}), coinbase_input_amount - leftover_input_amount, /*subtract_fee=*/true};
        CCoinControl coin_control;
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        // We need to use a change type with high cost of change so that the leftover amount will be dropped to fee instead of added as a change output
        coin_control.m_change_type = OutputType::LEGACY;
        auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_CHECK(res);
        const auto& txr = *res;
        BOOST_CHECK_EQUAL(txr.tx->vout.size(), 1);
        BOOST_CHECK_EQUAL(txr.tx->vout[0].nValue, recipient.nAmount + leftover_input_amount - txr.fee);
        BOOST_CHECK_GT(txr.fee, 0);
        return txr.fee;
    };

    // Send full input amount to recipient, check that only nonzero fee is
    // subtracted (to_reduce == fee).
    const CAmount fee{check_tx(0)};

    // Send slightly less than full input amount to recipient, check leftover
    // input amount is paid to recipient not the miner (to_reduce == fee - 123)
    BOOST_CHECK_EQUAL(fee, check_tx(123));

    // Send full input minus fee amount to recipient, check leftover input
    // amount is paid to recipient not the miner (to_reduce == 0)
    BOOST_CHECK_EQUAL(fee, check_tx(fee));

    // Send full input minus more than the fee amount to recipient, check
    // leftover input amount is paid to recipient not the miner (to_reduce ==
    // -123). This overpays the recipient instead of overpaying the miner more
    // than double the necessary fee.
    BOOST_CHECK_EQUAL(fee, check_tx(fee + 123));
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // Add 4 spendable UTXO to the wallet.
    for (int i = 0; i < 4; i++) CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const CAmount coinbase_input_amount{GetBlockSubsidy(/*nHeight=*/1, Assert(m_node.chainman)->GetConsensus())};
    const CAmount wallet_balance{4 * coinbase_input_amount};
    const CAmount target_amount{wallet_balance + 99 * COIN};

    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    // Preselect the first 3 UTXO.
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than what preset inputs + wallet selected inputs are covering for.
    // The wallet can cover up to its balance, and the tx target is intentionally higher.
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::BECH32, "dummy")),
                                           /*nAmount=*/target_amount, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Attempt to send more than the wallet balance. The wallet should exclude
    // the preset inputs from the pool of available coins, realize that there is not enough
    // money to fund the payment, and fail with "Insufficient funds".
    //
    // Even with SFFO, the wallet can only afford to send its balance.
    // If the wallet does not properly exclude preset inputs from the pool of available coins
    // prior to coin selection, it may create a transaction that does not fund the full payment
    // amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
    // between the original target and the wrongly counted inputs
    // so that the recipient's amount is no longer equal to the user's selected target of 299 BTC.

    // First case, use 'subtract_fee_from_outputs=true'
    util::Result<CreatedTransactionResult> res_tx = CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control);
    BOOST_CHECK(!res_tx.has_value());

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    res_tx = CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control);
    BOOST_CHECK(!res_tx.has_value());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
