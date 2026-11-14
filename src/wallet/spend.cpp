// Copyright (c) 2021-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/private_tx_verify.h>
#include <consensus/validation.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <numeric>
#include <policy/policy.h>
#include <private/orchard_verifier.h>
#include <private/private_state.h>
#include <primitives/private_transaction.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <support/cleanse.h>
#include <util/check.h>
#include <util/fees.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/private_wallet.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

#include <array>
#include <cmath>
#include <cstring>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <vector>

using interfaces::FoundBlock;

namespace wallet {
static const bilingual_str& WalletSyncPendingMessage()
{
    static const bilingual_str WALLET_SYNC_PENDING_MESSAGE{
        _("The displayed information may be out of date. Your wallet automatically synchronizes with the Nito network after a connection is established, but this process has not completed yet.")};
    return WALLET_SYNC_PENDING_MESSAGE;
}

static constexpr size_t OUTPUT_GROUP_MAX_ENTRIES{100};

/** Whether the descriptor represents, directly or not, a witness program. */
static bool IsSegwit(const Descriptor& desc) {
    if (const auto typ = desc.GetOutputType()) return *typ != OutputType::LEGACY;
    return false;
}

/** Whether to assume ECDSA signatures' will be high-r. */
static bool UseMaxSig(const std::optional<CTxIn>& txin, const CCoinControl* coin_control) {
    // Use max sig if watch only inputs were used or if this particular input is an external input
    // to ensure a sufficient fee is attained for the requested feerate.
    return coin_control && (coin_control->fAllowWatchOnly || (txin && coin_control->IsExternalSelected(txin->prevout)));
}

/** Get the size of an input (in witness units) once it's signed.
 *
 * @param desc The output script descriptor of the coin spent by this input.
 * @param txin Optionally the txin to estimate the size of. Used to determine the size of ECDSA signatures.
 * @param coin_control Information about the context to determine the size of ECDSA signatures.
 * @param tx_is_segwit Whether the transaction has at least a single input spending a segwit coin.
 * @param can_grind_r Whether the signer will be able to grind the R of the signature.
 */
static std::optional<int64_t> MaxInputWeight(const Descriptor& desc, const std::optional<CTxIn>& txin,
                                             const CCoinControl* coin_control, const bool tx_is_segwit,
                                             const bool can_grind_r) {
    if (const auto sat_weight = desc.MaxSatisfactionWeight(!can_grind_r || UseMaxSig(txin, coin_control))) {
        if (const auto elems_count = desc.MaxSatisfactionElems()) {
            const bool is_segwit = IsSegwit(desc);
            // Account for the size of the scriptsig and the number of elements on the witness stack. Note
            // that if any input in the transaction is spending a witness program, we need to specify the
            // witness stack size for every input regardless of whether it is segwit itself.
            // NOTE: this also works in case of mixed scriptsig-and-witness such as in p2sh-wrapped segwit v0
            // outputs. In this case the size of the scriptsig length will always be one (since the redeemScript
            // is always a push of the witness program in this case, which is smaller than 253 bytes).
            const int64_t scriptsig_len = is_segwit ? 1 : GetSizeOfCompactSize(*sat_weight / WITNESS_SCALE_FACTOR);
            const int64_t witstack_len = is_segwit ? GetSizeOfCompactSize(*elems_count) : (tx_is_segwit ? 1 : 0);
            // previous txid + previous vout + sequence + scriptsig len + witstack size + scriptsig or witness
            // NOTE: sat_weight already accounts for the witness discount accordingly.
            return (32 + 4 + 4 + scriptsig_len) * WITNESS_SCALE_FACTOR + witstack_len + *sat_weight;
        }
    }

    return {};
}

int CalculateMaximumSignedInputSize(const CTxOut& txout, const COutPoint outpoint, const SigningProvider* provider, bool can_grind_r, const CCoinControl* coin_control)
{
    if (!provider) return -1;

    if (const auto desc = InferDescriptor(txout.scriptPubKey, *provider)) {
        if (const auto weight = MaxInputWeight(*desc, {}, coin_control, true, can_grind_r)) {
            return static_cast<int>(GetVirtualTransactionSize(*weight, 0, 0));
        }
    }

    return -1;
}

int CalculateMaximumSignedInputSize(const CTxOut& txout, const CWallet* wallet, const CCoinControl* coin_control)
{
    const std::unique_ptr<SigningProvider> provider = wallet->GetSolvingProvider(txout.scriptPubKey);
    return CalculateMaximumSignedInputSize(txout, COutPoint(), provider.get(), wallet->CanGrindR(), coin_control);
}

/** Infer a descriptor for the given output script. */
static std::unique_ptr<Descriptor> GetDescriptor(const CWallet* wallet, const CCoinControl* coin_control,
                                                 const CScript script_pubkey)
{
    MultiSigningProvider providers;
    for (const auto spkman: wallet->GetScriptPubKeyMans(script_pubkey)) {
        providers.AddProvider(spkman->GetSolvingProvider(script_pubkey));
    }
    if (coin_control) {
        providers.AddProvider(std::make_unique<FlatSigningProvider>(coin_control->m_external_provider));
    }
    return InferDescriptor(script_pubkey, providers);
}

/** Infer the maximum size of this input after it will be signed. */
static std::optional<int64_t> GetSignedTxinWeight(const CWallet* wallet, const CCoinControl* coin_control,
                                                  const CTxIn& txin, const CTxOut& txo, const bool tx_is_segwit,
                                                  const bool can_grind_r)
{
    // If weight was provided, use that.
    std::optional<int64_t> weight;
    if (coin_control && (weight = coin_control->GetInputWeight(txin.prevout))) {
        return weight.value();
    }

    // Otherwise, use the maximum satisfaction size provided by the descriptor.
    std::unique_ptr<Descriptor> desc{GetDescriptor(wallet, coin_control, txo.scriptPubKey)};
    if (desc) return MaxInputWeight(*desc, {txin}, coin_control, tx_is_segwit, can_grind_r);

    return {};
}

// txouts needs to be in the order of tx.vin
TxSize CalculateMaximumSignedTxSize(const CTransaction &tx, const CWallet *wallet, const std::vector<CTxOut>& txouts, const CCoinControl* coin_control)
{
    // nVersion + nLockTime + input count + output count
    int64_t weight = (4 + 4 + GetSizeOfCompactSize(tx.vin.size()) + GetSizeOfCompactSize(tx.vout.size())) * WITNESS_SCALE_FACTOR;
    // Whether any input spends a witness program. Necessary to run before the next loop over the
    // inputs in order to accurately compute the compactSize length for the witness data per input.
    bool is_segwit = std::any_of(txouts.begin(), txouts.end(), [&](const CTxOut& txo) {
        std::unique_ptr<Descriptor> desc{GetDescriptor(wallet, coin_control, txo.scriptPubKey)};
        if (desc) return IsSegwit(*desc);
        return false;
    });
    // Segwit marker and flag
    if (is_segwit) weight += 2;

    // Add the size of the transaction outputs.
    for (const auto& txo : tx.vout) weight += GetSerializeSize(txo) * WITNESS_SCALE_FACTOR;

    // Add the size of the transaction inputs as if they were signed.
    for (uint32_t i = 0; i < txouts.size(); i++) {
        const auto txin_weight = GetSignedTxinWeight(wallet, coin_control, tx.vin[i], txouts[i], is_segwit, wallet->CanGrindR());
        if (!txin_weight) return TxSize{-1, -1};
        assert(*txin_weight > -1);
        weight += *txin_weight;
    }

    // It's ok to use 0 as the number of sigops since we never create any pathological transaction.
    return TxSize{GetVirtualTransactionSize(weight, 0, 0), weight};
}

TxSize CalculateMaximumSignedTxSize(const CTransaction &tx, const CWallet *wallet, const CCoinControl* coin_control)
{
    std::vector<CTxOut> txouts;
    // Look up the inputs. The inputs are either in the wallet, or in coin_control.
    for (const CTxIn& input : tx.vin) {
        const auto mi = wallet->mapWallet.find(input.prevout.hash);
        // Can not estimate size without knowing the input details
        if (mi != wallet->mapWallet.end()) {
            assert(input.prevout.n < mi->second.tx->vout.size());
            txouts.emplace_back(mi->second.tx->vout.at(input.prevout.n));
        } else if (coin_control) {
            const auto& txout{coin_control->GetExternalOutput(input.prevout)};
            if (!txout) return TxSize{-1, -1};
            txouts.emplace_back(*txout);
        } else {
            return TxSize{-1, -1};
        }
    }
    return CalculateMaximumSignedTxSize(tx, wallet, txouts, coin_control);
}

size_t CoinsResult::Size() const
{
    size_t size{0};
    for (const auto& it : coins) {
        size += it.second.size();
    }
    return size;
}

std::vector<COutput> CoinsResult::All() const
{
    std::vector<COutput> all;
    all.reserve(coins.size());
    for (const auto& it : coins) {
        all.insert(all.end(), it.second.begin(), it.second.end());
    }
    return all;
}

void CoinsResult::Clear() {
    coins.clear();
}

void CoinsResult::Erase(const std::unordered_set<COutPoint, SaltedOutpointHasher>& coins_to_remove)
{
    for (auto& [type, vec] : coins) {
        auto remove_it = std::remove_if(vec.begin(), vec.end(), [&](const COutput& coin) {
            // remove it if it's on the set
            if (coins_to_remove.count(coin.outpoint) == 0) return false;

            // update cached amounts
            total_amount -= coin.txout.nValue;
            if (coin.HasEffectiveValue()) total_effective_amount = *total_effective_amount - coin.GetEffectiveValue();
            return true;
        });
        vec.erase(remove_it, vec.end());
    }
}

void CoinsResult::Shuffle(FastRandomContext& rng_fast)
{
    for (auto& it : coins) {
        ::Shuffle(it.second.begin(), it.second.end(), rng_fast);
    }
}

void CoinsResult::Add(OutputType type, const COutput& out)
{
    coins[type].emplace_back(out);
    total_amount += out.txout.nValue;
    if (out.HasEffectiveValue()) {
        total_effective_amount = total_effective_amount.has_value() ?
                *total_effective_amount + out.GetEffectiveValue() : out.GetEffectiveValue();
    }
}

static OutputType GetOutputType(TxoutType type, bool is_from_p2sh)
{
    switch (type) {
        case TxoutType::WITNESS_V1_TAPROOT:
            return OutputType::BECH32M;
        case TxoutType::WITNESS_V0_KEYHASH:
        case TxoutType::WITNESS_V0_SCRIPTHASH:
            if (is_from_p2sh) return OutputType::P2SH_SEGWIT;
            else return OutputType::BECH32;
        case TxoutType::SCRIPTHASH:
        case TxoutType::PUBKEYHASH:
            return OutputType::LEGACY;
        default:
            return OutputType::UNKNOWN;
    }
}

// Fetch and validate the coin control selected inputs.
// Coins could be internal (from the wallet) or external.
util::Result<PreSelectedInputs> FetchSelectedInputs(const CWallet& wallet, const CCoinControl& coin_control,
                                            const CoinSelectionParams& coin_selection_params) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    PreSelectedInputs result;
    const bool can_grind_r = wallet.CanGrindR();
    std::map<COutPoint, CAmount> map_of_bump_fees = wallet.chain().calculateIndividualBumpFees(coin_control.ListSelected(), coin_selection_params.m_effective_feerate);
    for (const COutPoint& outpoint : coin_control.ListSelected()) {
        int64_t input_bytes = coin_control.GetInputWeight(outpoint).value_or(-1);
        if (input_bytes != -1) {
            input_bytes = GetVirtualTransactionSize(input_bytes, 0, 0);
        }
        CTxOut txout;
        if (auto ptr_wtx = wallet.GetWalletTx(outpoint.hash)) {
            // Clearly invalid input, fail
            if (ptr_wtx->tx->vout.size() <= outpoint.n) {
                return util::Error{strprintf(_("Invalid pre-selected input %s"), outpoint.ToString())};
            }
            txout = ptr_wtx->tx->vout.at(outpoint.n);
            if (input_bytes == -1) {
                input_bytes = CalculateMaximumSignedInputSize(txout, &wallet, &coin_control);
            }
        } else {
            // The input is external. We did not find the tx in mapWallet.
            const auto out{coin_control.GetExternalOutput(outpoint)};
            if (!out) {
                return util::Error{strprintf(_("Not found pre-selected input %s"), outpoint.ToString())};
            }

            txout = *out;
        }

        if (input_bytes == -1) {
            input_bytes = CalculateMaximumSignedInputSize(txout, outpoint, &coin_control.m_external_provider, can_grind_r, &coin_control);
        }

        if (input_bytes == -1) {
            return util::Error{strprintf(_("Not solvable pre-selected input %s"), outpoint.ToString())}; // Not solvable, can't estimate size for fee
        }

        /* Set some defaults for depth, spendable, solvable, safe, time, and from_me as these don't matter for preset inputs since no selection is being done. */
        COutput output(outpoint, txout, /*depth=*/ 0, input_bytes, /*spendable=*/ true, /*solvable=*/ true, /*safe=*/ true, /*time=*/ 0, /*from_me=*/ false, coin_selection_params.m_effective_feerate);
        output.ApplyBumpFee(map_of_bump_fees.at(output.outpoint));
        result.Insert(output, coin_selection_params.m_subtract_fee_outputs);
    }
    return result;
}

CoinsResult AvailableCoins(const CWallet& wallet,
                           const CCoinControl* coinControl,
                           std::optional<CFeeRate> feerate,
                           const CoinFilterParams& params)
{
    AssertLockHeld(wallet.cs_wallet);

    CoinsResult result;
    // Either the WALLET_FLAG_AVOID_REUSE flag is not set (in which case we always allow), or we default to avoiding, and only in the case where
    // a coin control object is provided, and has the avoid address reuse flag set to false, do we allow already used addresses
    bool allow_used_addresses = !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE) || (coinControl && !coinControl->m_avoid_address_reuse);
    const int min_depth = {coinControl ? coinControl->m_min_depth : DEFAULT_MIN_DEPTH};
    const int max_depth = {coinControl ? coinControl->m_max_depth : DEFAULT_MAX_DEPTH};
    const bool only_safe = {coinControl ? !coinControl->m_include_unsafe_inputs : true};
    const bool can_grind_r = wallet.CanGrindR();
    std::vector<COutPoint> outpoints;

    std::set<uint256> trusted_parents;
    for (const auto& entry : wallet.mapWallet)
    {
        const uint256& txid = entry.first;
        const CWalletTx& wtx = entry.second;

        if (wallet.IsTxImmatureCoinBase(wtx) && !params.include_immature_coinbase)
            continue;

        int nDepth = wallet.GetTxDepthInMainChain(wtx);
        if (nDepth < 0)
            continue;

        // We should not consider coins which aren't at least in our mempool
        // It's possible for these to be conflicted via ancestors which we may never be able to detect
        if (nDepth == 0 && !wtx.InMempool())
            continue;

        bool safeTx = CachedTxIsTrusted(wallet, wtx, trusted_parents);

        // We should not consider coins from transactions that are replacing
        // other transactions.
        //
        // Example: There is a transaction A which is replaced by bumpfee
        // transaction B. In this case, we want to prevent creation of
        // a transaction B' which spends an output of B.
        //
        // Reason: If transaction A were initially confirmed, transactions B
        // and B' would no longer be valid, so the user would have to create
        // a new transaction C to replace B'. However, in the case of a
        // one-block reorg, transactions B' and C might BOTH be accepted,
        // when the user only wanted one of them. Specifically, there could
        // be a 1-block reorg away from the chain where transactions A and C
        // were accepted to another chain where B, B', and C were all
        // accepted.
        if (nDepth == 0 && wtx.mapValue.count("replaces_txid")) {
            safeTx = false;
        }

        // Similarly, we should not consider coins from transactions that
        // have been replaced. In the example above, we would want to prevent
        // creation of a transaction A' spending an output of A, because if
        // transaction B were initially confirmed, conflicting with A and
        // A', we wouldn't want to the user to create a transaction D
        // intending to replace A', but potentially resulting in a scenario
        // where A, A', and D could all be accepted (instead of just B and
        // D, or just A and A' like the user would want).
        if (nDepth == 0 && wtx.mapValue.count("replaced_by_txid")) {
            safeTx = false;
        }

        if (only_safe && !safeTx) {
            continue;
        }

        if (nDepth < min_depth || nDepth > max_depth) {
            continue;
        }

        bool tx_from_me = CachedTxIsFromMe(wallet, wtx, ISMINE_ALL);

        for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
            const CTxOut& output = wtx.tx->vout[i];
            const COutPoint outpoint(Txid::FromUint256(txid), i);

            if (output.nValue < params.min_amount || output.nValue > params.max_amount)
                continue;

            // Skip manually selected coins (the caller can fetch them directly)
            if (coinControl && coinControl->HasSelected() && coinControl->IsSelected(outpoint))
                continue;

            if (wallet.IsLockedCoin(outpoint) && params.skip_locked)
                continue;

            if (wallet.IsSpent(outpoint))
                continue;

            isminetype mine = wallet.IsMine(output);

            if (mine == ISMINE_NO) {
                continue;
            }

            if (!allow_used_addresses && wallet.IsSpentKey(output.scriptPubKey)) {
                continue;
            }

            std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(output.scriptPubKey);

            int input_bytes = CalculateMaximumSignedInputSize(output, COutPoint(), provider.get(), can_grind_r, coinControl);
            // Because CalculateMaximumSignedInputSize infers a solvable descriptor to get the satisfaction size,
            // it is safe to assume that this input is solvable if input_bytes is greater than -1.
            bool solvable = input_bytes > -1;
            bool spendable = ((mine & ISMINE_SPENDABLE) != ISMINE_NO) || (((mine & ISMINE_WATCH_ONLY) != ISMINE_NO) && (coinControl && coinControl->fAllowWatchOnly && solvable));

            // Filter by spendable outputs only
            if (!spendable && params.only_spendable) continue;

            // Obtain script type
            std::vector<std::vector<uint8_t>> script_solutions;
            TxoutType type = Solver(output.scriptPubKey, script_solutions);

            // If the output is P2SH and solvable, we want to know if it is
            // a P2SH (legacy) or one of P2SH-P2WPKH, P2SH-P2WSH (P2SH-Segwit). We can determine
            // this from the redeemScript. If the output is not solvable, it will be classified
            // as a P2SH (legacy), since we have no way of knowing otherwise without the redeemScript
            bool is_from_p2sh{false};
            if (type == TxoutType::SCRIPTHASH && solvable) {
                CScript script;
                if (!provider->GetCScript(CScriptID(uint160(script_solutions[0])), script)) continue;
                type = Solver(script, script_solutions);
                is_from_p2sh = true;
            }

            result.Add(GetOutputType(type, is_from_p2sh),
                       COutput(outpoint, output, nDepth, input_bytes, spendable, solvable, safeTx, wtx.GetTxTime(), tx_from_me, feerate));

            outpoints.push_back(outpoint);

            // Checks the sum amount of all UTXO's.
            if (params.min_sum_amount != MAX_MONEY) {
                if (result.GetTotalAmount() >= params.min_sum_amount) {
                    return result;
                }
            }

            // Checks the maximum number of UTXO's.
            if (params.max_count > 0 && result.Size() >= params.max_count) {
                return result;
            }
        }
    }

    if (feerate.has_value()) {
        std::map<COutPoint, CAmount> map_of_bump_fees = wallet.chain().calculateIndividualBumpFees(outpoints, feerate.value());

        for (auto& [_, outputs] : result.coins) {
            for (auto& output : outputs) {
                output.ApplyBumpFee(map_of_bump_fees.at(output.outpoint));
            }
        }
    }

    return result;
}

CoinsResult AvailableCoinsListUnspent(const CWallet& wallet, const CCoinControl* coinControl, CoinFilterParams params)
{
    params.only_spendable = false;
    return AvailableCoins(wallet, coinControl, /*feerate=*/ std::nullopt, params);
}

const CTxOut& FindNonChangeParentOutput(const CWallet& wallet, const COutPoint& outpoint)
{
    AssertLockHeld(wallet.cs_wallet);
    const CWalletTx* wtx{Assert(wallet.GetWalletTx(outpoint.hash))};

    const CTransaction* ptx = wtx->tx.get();
    int n = outpoint.n;
    while (OutputIsChange(wallet, ptx->vout[n]) && ptx->vin.size() > 0) {
        const COutPoint& prevout = ptx->vin[0].prevout;
        const CWalletTx* it = wallet.GetWalletTx(prevout.hash);
        if (!it || it->tx->vout.size() <= prevout.n ||
            !wallet.IsMine(it->tx->vout[prevout.n])) {
            break;
        }
        ptx = it->tx.get();
        n = prevout.n;
    }
    return ptx->vout[n];
}

std::map<CTxDestination, std::vector<COutput>> ListCoins(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    std::map<CTxDestination, std::vector<COutput>> result;

    CCoinControl coin_control;
    // Include watch-only for LegacyScriptPubKeyMan wallets without private keys
    coin_control.fAllowWatchOnly = wallet.GetLegacyScriptPubKeyMan() && wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    CoinFilterParams coins_params;
    coins_params.only_spendable = false;
    coins_params.skip_locked = false;
    for (const COutput& coin : AvailableCoins(wallet, &coin_control, /*feerate=*/std::nullopt, coins_params).All()) {
        CTxDestination address;
        if ((coin.spendable || (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && coin.solvable))) {
            if (!ExtractDestination(FindNonChangeParentOutput(wallet, coin.outpoint).scriptPubKey, address)) {
                // For backwards compatibility, we convert P2PK output scripts into PKHash destinations
                if (auto pk_dest = std::get_if<PubKeyDestination>(&address)) {
                    address = PKHash(pk_dest->GetPubKey());
                } else {
                    continue;
                }
            }
            result[address].emplace_back(coin);
        }
    }
    return result;
}

FilteredOutputGroups GroupOutputs(const CWallet& wallet,
                          const CoinsResult& coins,
                          const CoinSelectionParams& coin_sel_params,
                          const std::vector<SelectionFilter>& filters,
                          std::vector<OutputGroup>& ret_discarded_groups)
{
    FilteredOutputGroups filtered_groups;

    if (!coin_sel_params.m_avoid_partial_spends) {
        // Allowing partial spends means no grouping. Each COutput gets its own OutputGroup
        for (const auto& [type, outputs] : coins.coins) {
            for (const COutput& output : outputs) {
                // Get mempool info
                size_t ancestors, descendants;
                wallet.chain().getTransactionAncestry(output.outpoint.hash, ancestors, descendants);

                // Create a new group per output and add it to the all groups vector
                OutputGroup group(coin_sel_params);
                group.Insert(std::make_shared<COutput>(output), ancestors, descendants);

                // Each filter maps to a different set of groups
                bool accepted = false;
                for (const auto& sel_filter : filters) {
                    const auto& filter = sel_filter.filter;
                    if (!group.EligibleForSpending(filter)) continue;
                    filtered_groups[filter].Push(group, type, /*insert_positive=*/true, /*insert_mixed=*/true);
                    accepted = true;
                }
                if (!accepted) ret_discarded_groups.emplace_back(group);
            }
        }
        return filtered_groups;
    }

    // We want to combine COutputs that have the same scriptPubKey into single OutputGroups
    // except when there are more than OUTPUT_GROUP_MAX_ENTRIES COutputs grouped in an OutputGroup.
    // To do this, we maintain a map where the key is the scriptPubKey and the value is a vector of OutputGroups.
    // For each COutput, we check if the scriptPubKey is in the map, and if it is, the COutput is added
    // to the last OutputGroup in the vector for the scriptPubKey. When the last OutputGroup has
    // OUTPUT_GROUP_MAX_ENTRIES COutputs, a new OutputGroup is added to the end of the vector.
    typedef std::map<std::pair<CScript, OutputType>, std::vector<OutputGroup>> ScriptPubKeyToOutgroup;
    const auto& insert_output = [&](
            const std::shared_ptr<COutput>& output, OutputType type, size_t ancestors, size_t descendants,
            ScriptPubKeyToOutgroup& groups_map) {
        std::vector<OutputGroup>& groups = groups_map[std::make_pair(output->txout.scriptPubKey,type)];

        if (groups.size() == 0) {
            // No OutputGroups for this scriptPubKey yet, add one
            groups.emplace_back(coin_sel_params);
        }

        // Get the last OutputGroup in the vector so that we can add the COutput to it
        // A pointer is used here so that group can be reassigned later if it is full.
        OutputGroup* group = &groups.back();

        // Check if this OutputGroup is full. We limit to OUTPUT_GROUP_MAX_ENTRIES when using -avoidpartialspends
        // to avoid surprising users with very high fees.
        if (group->m_outputs.size() >= OUTPUT_GROUP_MAX_ENTRIES) {
            // The last output group is full, add a new group to the vector and use that group for the insertion
            groups.emplace_back(coin_sel_params);
            group = &groups.back();
        }

        group->Insert(output, ancestors, descendants);
    };

    ScriptPubKeyToOutgroup spk_to_groups_map;
    ScriptPubKeyToOutgroup spk_to_positive_groups_map;
    for (const auto& [type, outs] : coins.coins) {
        for (const COutput& output : outs) {
            size_t ancestors, descendants;
            wallet.chain().getTransactionAncestry(output.outpoint.hash, ancestors, descendants);

            const auto& shared_output = std::make_shared<COutput>(output);
            // Filter for positive only before adding the output
            if (output.GetEffectiveValue() > 0) {
                insert_output(shared_output, type, ancestors, descendants, spk_to_positive_groups_map);
            }

            // 'All' groups
            insert_output(shared_output, type, ancestors, descendants, spk_to_groups_map);
        }
    }

    // Now we go through the entire maps and pull out the OutputGroups
    const auto& push_output_groups = [&](const ScriptPubKeyToOutgroup& groups_map, bool positive_only) {
        for (const auto& [script, groups] : groups_map) {
            // Go through the vector backwards. This allows for the first item we deal with being the partial group.
            for (auto group_it = groups.rbegin(); group_it != groups.rend(); group_it++) {
                const OutputGroup& group = *group_it;

                // Each filter maps to a different set of groups
                bool accepted = false;
                for (const auto& sel_filter : filters) {
                    const auto& filter = sel_filter.filter;
                    if (!group.EligibleForSpending(filter)) continue;

                    // Don't include partial groups if there are full groups too and we don't want partial groups
                    if (group_it == groups.rbegin() && groups.size() > 1 && !filter.m_include_partial_groups) {
                        continue;
                    }

                    OutputType type = script.second;
                    // Either insert the group into the positive-only groups or the mixed ones.
                    filtered_groups[filter].Push(group, type, positive_only, /*insert_mixed=*/!positive_only);
                    accepted = true;
                }
                if (!accepted) ret_discarded_groups.emplace_back(group);
            }
        }
    };

    push_output_groups(spk_to_groups_map, /*positive_only=*/ false);
    push_output_groups(spk_to_positive_groups_map, /*positive_only=*/ true);

    return filtered_groups;
}

FilteredOutputGroups GroupOutputs(const CWallet& wallet,
                                  const CoinsResult& coins,
                                  const CoinSelectionParams& params,
                                  const std::vector<SelectionFilter>& filters)
{
    std::vector<OutputGroup> unused;
    return GroupOutputs(wallet, coins, params, filters, unused);
}

// Returns true if the result contains an error and the message is not empty
static bool HasErrorMsg(const util::Result<SelectionResult>& res) { return !util::ErrorString(res).empty(); }

util::Result<SelectionResult> AttemptSelection(interfaces::Chain& chain, const CAmount& nTargetValue, OutputGroupTypeMap& groups,
                               const CoinSelectionParams& coin_selection_params, bool allow_mixed_output_types)
{
    // Run coin selection on each OutputType and compute the Waste Metric
    std::vector<SelectionResult> results;
    for (auto& [type, group] : groups.groups_by_type) {
        auto result{ChooseSelectionResult(chain, nTargetValue, group, coin_selection_params)};
        // If any specific error message appears here, then something particularly wrong happened.
        if (HasErrorMsg(result)) return result; // So let's return the specific error.
        // Append the favorable result.
        if (result) results.push_back(*result);
    }
    // If we have at least one solution for funding the transaction without mixing, choose the minimum one according to waste metric
    // and return the result
    if (results.size() > 0) return *std::min_element(results.begin(), results.end());

    // If we can't fund the transaction from any individual OutputType, run coin selection one last time
    // over all available coins, which would allow mixing.
    // If TypesCount() <= 1, there is nothing to mix.
    if (allow_mixed_output_types && groups.TypesCount() > 1) {
        return ChooseSelectionResult(chain, nTargetValue, groups.all_groups, coin_selection_params);
    }
    // Either mixing is not allowed and we couldn't find a solution from any single OutputType, or mixing was allowed and we still couldn't
    // find a solution using all available coins
    return util::Error();
};

util::Result<SelectionResult> ChooseSelectionResult(interfaces::Chain& chain, const CAmount& nTargetValue, Groups& groups, const CoinSelectionParams& coin_selection_params)
{
    // Vector of results. We will choose the best one based on waste.
    std::vector<SelectionResult> results;
    std::vector<util::Result<SelectionResult>> errors;
    auto append_error = [&] (const util::Result<SelectionResult>& result) {
        // If any specific error message appears here, then something different from a simple "no selection found" happened.
        // Let's save it, so it can be retrieved to the user if no other selection algorithm succeeded.
        if (HasErrorMsg(result)) {
            errors.emplace_back(result);
        }
    };

    // Maximum allowed weight
    int max_inputs_weight = MAX_STANDARD_TX_WEIGHT - (coin_selection_params.tx_noinputs_size * WITNESS_SCALE_FACTOR);

    // SFFO frequently causes issues in the context of changeless input sets: skip BnB when SFFO is active
    if (!coin_selection_params.m_subtract_fee_outputs) {
        if (auto bnb_result{SelectCoinsBnB(groups.positive_group, nTargetValue, coin_selection_params.m_cost_of_change, max_inputs_weight)}) {
            results.push_back(*bnb_result);
        } else append_error(bnb_result);
    }

    // As Knapsack and SRD can create change, also deduce change weight.
    max_inputs_weight -= (coin_selection_params.change_output_size * WITNESS_SCALE_FACTOR);

    // The knapsack solver has some legacy behavior where it will spend dust outputs. We retain this behavior, so don't filter for positive only here.
    if (auto knapsack_result{KnapsackSolver(groups.mixed_group, nTargetValue, coin_selection_params.m_min_change_target, coin_selection_params.rng_fast, max_inputs_weight)}) {
        results.push_back(*knapsack_result);
    } else append_error(knapsack_result);

    if (coin_selection_params.m_effective_feerate > CFeeRate{3 * coin_selection_params.m_long_term_feerate}) { // Minimize input set for feerates of at least 3×LTFRE (default: 30 ṩ/vB+)
        if (auto cg_result{CoinGrinder(groups.positive_group, nTargetValue, coin_selection_params.m_min_change_target, max_inputs_weight)}) {
            cg_result->ComputeAndSetWaste(coin_selection_params.min_viable_change, coin_selection_params.m_cost_of_change, coin_selection_params.m_change_fee);
            results.push_back(*cg_result);
        } else {
            append_error(cg_result);
        }
    }

    if (auto srd_result{SelectCoinsSRD(groups.positive_group, nTargetValue, coin_selection_params.m_change_fee, coin_selection_params.rng_fast, max_inputs_weight)}) {
        results.push_back(*srd_result);
    } else append_error(srd_result);

    if (results.empty()) {
        // No solution found, retrieve the first explicit error (if any).
        // future: add 'severity level' to errors so the worst one can be retrieved instead of the first one.
        return errors.empty() ? util::Error() : errors.front();
    }

    // If the chosen input set has unconfirmed inputs, check for synergies from overlapping ancestry
    for (auto& result : results) {
        std::vector<COutPoint> outpoints;
        std::set<std::shared_ptr<COutput>> coins = result.GetInputSet();
        CAmount summed_bump_fees = 0;
        for (auto& coin : coins) {
            if (coin->depth > 0) continue; // Bump fees only exist for unconfirmed inputs
            outpoints.push_back(coin->outpoint);
            summed_bump_fees += coin->ancestor_bump_fees;
        }
        std::optional<CAmount> combined_bump_fee = chain.calculateCombinedBumpFee(outpoints, coin_selection_params.m_effective_feerate);
        if (!combined_bump_fee.has_value()) {
            return util::Error{_("Failed to calculate bump fees, because unconfirmed UTXOs depend on enormous cluster of unconfirmed transactions.")};
        }
        CAmount bump_fee_overestimate = summed_bump_fees - combined_bump_fee.value();
        if (bump_fee_overestimate) {
            result.SetBumpFeeDiscount(bump_fee_overestimate);
        }
        result.ComputeAndSetWaste(coin_selection_params.min_viable_change, coin_selection_params.m_cost_of_change, coin_selection_params.m_change_fee);
    }

    // Choose the result with the least waste
    // If the waste is the same, choose the one which spends more inputs.
    return *std::min_element(results.begin(), results.end());
}

util::Result<SelectionResult> SelectCoins(const CWallet& wallet, CoinsResult& available_coins, const PreSelectedInputs& pre_set_inputs,
                                          const CAmount& nTargetValue, const CCoinControl& coin_control,
                                          const CoinSelectionParams& coin_selection_params)
{
    // Deduct preset inputs amount from the search target
    CAmount selection_target = nTargetValue - pre_set_inputs.total_amount;

    // Return if automatic coin selection is disabled, and we don't cover the selection target
    if (!coin_control.m_allow_other_inputs && selection_target > 0) {
        return util::Error{_("The preselected coins total amount does not cover the transaction target. "
                             "Please allow other inputs to be automatically selected or include more coins manually")};
    }

    // Return if we can cover the target only with the preset inputs
    if (selection_target <= 0) {
        SelectionResult result(nTargetValue, SelectionAlgorithm::MANUAL);
        result.AddInputs(pre_set_inputs.coins, coin_selection_params.m_subtract_fee_outputs);
        result.ComputeAndSetWaste(coin_selection_params.min_viable_change, coin_selection_params.m_cost_of_change, coin_selection_params.m_change_fee);
        return result;
    }

    // Return early if we cannot cover the target with the wallet's UTXO.
    // We use the total effective value if we are not subtracting fee from outputs and 'available_coins' contains the data.
    CAmount available_coins_total_amount = coin_selection_params.m_subtract_fee_outputs ? available_coins.GetTotalAmount() :
            (available_coins.GetEffectiveTotalAmount().has_value() ? *available_coins.GetEffectiveTotalAmount() : 0);
    if (selection_target > available_coins_total_amount) {
        return util::Error(); // Insufficient funds
    }

    // Start wallet Coin Selection procedure
    auto op_selection_result = AutomaticCoinSelection(wallet, available_coins, selection_target, coin_selection_params);
    if (!op_selection_result) return op_selection_result;

    // If needed, add preset inputs to the automatic coin selection result
    if (!pre_set_inputs.coins.empty()) {
        SelectionResult preselected(pre_set_inputs.total_amount, SelectionAlgorithm::MANUAL);
        preselected.AddInputs(pre_set_inputs.coins, coin_selection_params.m_subtract_fee_outputs);
        op_selection_result->Merge(preselected);
        op_selection_result->ComputeAndSetWaste(coin_selection_params.min_viable_change,
                                                coin_selection_params.m_cost_of_change,
                                                coin_selection_params.m_change_fee);
    }
    return op_selection_result;
}

util::Result<SelectionResult> AutomaticCoinSelection(const CWallet& wallet, CoinsResult& available_coins, const CAmount& value_to_select, const CoinSelectionParams& coin_selection_params)
{
    unsigned int limit_ancestor_count = 0;
    unsigned int limit_descendant_count = 0;
    wallet.chain().getPackageLimits(limit_ancestor_count, limit_descendant_count);
    const size_t max_ancestors = (size_t)std::max<int64_t>(1, limit_ancestor_count);
    const size_t max_descendants = (size_t)std::max<int64_t>(1, limit_descendant_count);
    const bool fRejectLongChains = gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);

    // Cases where we have 101+ outputs all pointing to the same destination may result in
    // privacy leaks as they will potentially be deterministically sorted. We solve that by
    // explicitly shuffling the outputs before processing
    if (coin_selection_params.m_avoid_partial_spends && available_coins.Size() > OUTPUT_GROUP_MAX_ENTRIES) {
        available_coins.Shuffle(coin_selection_params.rng_fast);
    }

    // Coin Selection attempts to select inputs from a pool of eligible UTXOs to fund the
    // transaction at a target feerate. If an attempt fails, more attempts may be made using a more
    // permissive CoinEligibilityFilter.
    util::Result<SelectionResult> res = [&] {
        // Place coins eligibility filters on a scope increasing order.
        std::vector<SelectionFilter> ordered_filters{
                // If possible, fund the transaction with confirmed UTXOs only. Prefer at least six
                // confirmations on outputs received from other wallets and only spend confirmed change.
                {CoinEligibilityFilter(1, 6, 0), /*allow_mixed_output_types=*/false},
                {CoinEligibilityFilter(1, 1, 0)},
        };
        // Fall back to using zero confirmation change (but with as few ancestors in the mempool as
        // possible) if we cannot fund the transaction otherwise.
        if (wallet.m_spend_zero_conf_change) {
            ordered_filters.push_back({CoinEligibilityFilter(0, 1, 2)});
            ordered_filters.push_back({CoinEligibilityFilter(0, 1, std::min(size_t{4}, max_ancestors/3), std::min(size_t{4}, max_descendants/3))});
            ordered_filters.push_back({CoinEligibilityFilter(0, 1, max_ancestors/2, max_descendants/2)});
            // If partial groups are allowed, relax the requirement of spending OutputGroups (groups
            // of UTXOs sent to the same address, which are obviously controlled by a single wallet)
            // in their entirety.
            ordered_filters.push_back({CoinEligibilityFilter(0, 1, max_ancestors-1, max_descendants-1, /*include_partial=*/true)});
            // Try with unsafe inputs if they are allowed. This may spend unconfirmed outputs
            // received from other wallets.
            if (coin_selection_params.m_include_unsafe_inputs) {
                ordered_filters.push_back({CoinEligibilityFilter(/*conf_mine=*/0, /*conf_theirs*/0, max_ancestors-1, max_descendants-1, /*include_partial=*/true)});
            }
            // Try with unlimited ancestors/descendants. The transaction will still need to meet
            // mempool ancestor/descendant policy to be accepted to mempool and broadcasted, but
            // OutputGroups use heuristics that may overestimate ancestor/descendant counts.
            if (!fRejectLongChains) {
                ordered_filters.push_back({CoinEligibilityFilter(0, 1, std::numeric_limits<uint64_t>::max(),
                                                                   std::numeric_limits<uint64_t>::max(),
                                                                   /*include_partial=*/true)});
            }
        }

        // Group outputs and map them by coin eligibility filter
        std::vector<OutputGroup> discarded_groups;
        FilteredOutputGroups filtered_groups = GroupOutputs(wallet, available_coins, coin_selection_params, ordered_filters, discarded_groups);

        // Check if we still have enough balance after applying filters (some coins might be discarded)
        CAmount total_discarded = 0;
        CAmount total_unconf_long_chain = 0;
        for (const auto& group : discarded_groups) {
            total_discarded += group.GetSelectionAmount();
            if (group.m_ancestors >= max_ancestors || group.m_descendants >= max_descendants) total_unconf_long_chain += group.GetSelectionAmount();
        }

        if (CAmount total_amount = available_coins.GetTotalAmount() - total_discarded < value_to_select) {
            // Special case, too-long-mempool cluster.
            if (total_amount + total_unconf_long_chain > value_to_select) {
                return util::Result<SelectionResult>({_("Unconfirmed UTXOs are available, but spending them creates a chain of transactions that will be rejected by the mempool")});
            }
            return util::Result<SelectionResult>(util::Error()); // General "Insufficient Funds"
        }

        // Walk-through the filters until the solution gets found.
        // If no solution is found, return the first detailed error (if any).
        // future: add "error level" so the worst one can be picked instead.
        std::vector<util::Result<SelectionResult>> res_detailed_errors;
        for (const auto& select_filter : ordered_filters) {
            auto it = filtered_groups.find(select_filter.filter);
            if (it == filtered_groups.end()) continue;
            if (auto res{AttemptSelection(wallet.chain(), value_to_select, it->second,
                                          coin_selection_params, select_filter.allow_mixed_output_types)}) {
                return res; // result found
            } else {
                // If any specific error message appears here, then something particularly wrong might have happened.
                // Save the error and continue the selection process. So if no solutions gets found, we can return
                // the detailed error to the upper layers.
                if (HasErrorMsg(res)) res_detailed_errors.emplace_back(res);
            }
        }

        // Return right away if we have a detailed error
        if (!res_detailed_errors.empty()) return res_detailed_errors.front();


        // General "Insufficient Funds"
        return util::Result<SelectionResult>(util::Error());
    }();

    return res;
}

static bool IsCurrentForAntiFeeSniping(interfaces::Chain& chain, const uint256& block_hash)
{
    if (chain.isInitialBlockDownload()) {
        return false;
    }
    constexpr int64_t MAX_ANTI_FEE_SNIPING_TIP_AGE = 8 * 60 * 60; // in seconds
    int64_t block_time;
    CHECK_NONFATAL(chain.findBlock(block_hash, FoundBlock().time(block_time)));
    if (block_time < (GetTime() - MAX_ANTI_FEE_SNIPING_TIP_AGE)) {
        return false;
    }
    return true;
}

/**
 * Set a height-based locktime for new transactions (uses the height of the
 * current chain tip unless we are not synced with the current chain
 */
static void DiscourageFeeSniping(CMutableTransaction& tx, FastRandomContext& rng_fast,
                                 interfaces::Chain& chain, const uint256& block_hash, int block_height)
{
    // Transparent inputs, if any, must be added by now. Nito.network private-only
    // transactions can validly spend Orchard notes without any transparent vin.
    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    if (IsCurrentForAntiFeeSniping(chain, block_hash)) {
        tx.nLockTime = block_height;

        // Secondly occasionally randomly pick a nLockTime even further back, so
        // that transactions that are delayed after signing for whatever reason,
        // e.g. high-latency mix networks and some CoinJoin implementations, have
        // better privacy.
        if (rng_fast.randrange(10) == 0) {
            tx.nLockTime = std::max(0, int(tx.nLockTime) - int(rng_fast.randrange(100)));
        }
    } else {
        // If our chain is lagging behind, we can't discourage fee sniping nor help
        // the privacy of high-latency transactions. To avoid leaking a potentially
        // unique "nLockTime fingerprint", set nLockTime to a constant.
        tx.nLockTime = 0;
    }
    // Sanity check all values
    assert(tx.nLockTime < LOCKTIME_THRESHOLD); // Type must be block height
    assert(tx.nLockTime <= uint64_t(block_height));
    for (const auto& in : tx.vin) {
        // Can not be FINAL for locktime to work
        assert(in.nSequence != CTxIn::SEQUENCE_FINAL);
        // May be MAX NONFINAL to disable both BIP68 and BIP125
        if (in.nSequence == CTxIn::MAX_SEQUENCE_NONFINAL) continue;
        // May be MAX BIP125 to disable BIP68 and enable BIP125
        if (in.nSequence == MAX_BIP125_RBF_SEQUENCE) continue;
        // The wallet does not support any other sequence-use right now.
        assert(false);
    }
}

namespace {
static constexpr size_t PRIVATE_WALLET_MAX_ACTIONS{MAX_PRIVATE_ORCHARD_ACTIONS};

size_t EstimatePrivateBundleActions(size_t spend_count, size_t output_count)
{
    if (spend_count == 0 && output_count == 0) return 0;
    return std::max<size_t>(2, std::max(spend_count, output_count));
}

CPrivateBundle MakePrivateBundleWeightProbe(size_t action_count, const uint256& anchor = uint256{}, CAmount value_balance = 0)
{
    CPrivateBundle bundle;
    bundle.effects.flags = PRIVATE_ORCHARD_FLAGS_MASK;
    bundle.effects.anchor = anchor;
    bundle.effects.value_balance = value_balance;
    bundle.effects.actions.resize(action_count);
    bundle.auth.emplace();
    bundle.auth->actions_auth.resize(action_count);
    bundle.auth->proof.resize(PrivateOrchardExpectedProofSize(action_count));
    bundle.auth->binding_sig.resize(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE);

    for (size_t i = 0; i < action_count; ++i) {
        CPrivateActionEffects& action = bundle.effects.actions[i];
        action.ephemeral_key.resize(PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE);
        action.enc_ciphertext.resize(PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE);
        action.out_ciphertext.resize(PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE);
        bundle.auth->actions_auth[i].spend_auth_sig.resize(PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE);
    }

    return bundle;
}

int64_t EstimatePrivateBundleWeightDelta(const CMutableTransaction& tx_without_private, size_t action_count, const uint256& anchor, CAmount value_balance)
{
    CMutableTransaction tx_with_private{tx_without_private};
    tx_with_private.m_private_bundle = MakePrivateBundleWeightProbe(action_count, anchor, value_balance);
    return static_cast<int64_t>(GetTransactionWeight(CTransaction(tx_with_private))) -
           static_cast<int64_t>(GetTransactionWeight(CTransaction(tx_without_private)));
}

TxSize EstimatePrivateTransactionSize(const CMutableTransaction& tx_without_private, size_t action_count, const uint256& anchor, CAmount value_balance)
{
    CMutableTransaction tx_with_private{tx_without_private};
    tx_with_private.m_private_bundle = MakePrivateBundleWeightProbe(action_count, anchor, value_balance);
    const int64_t weight{static_cast<int64_t>(GetTransactionWeight(CTransaction(tx_with_private)))};
    return TxSize{GetVirtualTransactionSize(
        weight,
        /*nSigOpCost=*/0,
        /*bytes_per_sigop=*/0,
        GetPrivateOrchardVerificationCost(action_count)), weight};
}

util::Result<TxSize> EstimateSignedTransparentPrivateTransactionSize(
    const CMutableTransaction& tx_without_private,
    CWallet& wallet,
    const CCoinControl& coin_control,
    size_t action_count,
    const uint256& anchor,
    CAmount value_balance,
    int64_t& private_weight_delta_out) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const TxSize transparent_size{CalculateMaximumSignedTxSize(CTransaction(tx_without_private), &wallet, &coin_control)};
    if (transparent_size.vsize == -1 || transparent_size.weight == -1) {
        return util::Error{_("Missing solving data for estimating transaction size")};
    }

    private_weight_delta_out = EstimatePrivateBundleWeightDelta(tx_without_private, action_count, anchor, value_balance);
    const int64_t weight{transparent_size.weight + private_weight_delta_out};
    return TxSize{GetVirtualTransactionSize(
        weight,
        /*nSigOpCost=*/0,
        /*bytes_per_sigop=*/0,
        GetPrivateOrchardVerificationCost(action_count)), weight};
}

bool CheckPrivateWeightEstimate(const CMutableTransaction& tx_without_private, const CPrivateBundle& bundle, size_t estimated_actions, int64_t estimated_private_delta, std::string& error)
{
    const size_t actual_actions{bundle.effects.actions.size()};
    if (actual_actions != estimated_actions) {
        error = strprintf("private Orchard action estimate mismatch: estimated=%u actual=%u",
            static_cast<unsigned>(estimated_actions),
            static_cast<unsigned>(actual_actions));
        return false;
    }

    CMutableTransaction tx_with_private{tx_without_private};
    CPrivateBundle weight_bundle{bundle};
    if (!weight_bundle.auth) {
        CPrivateBundle auth_probe = MakePrivateBundleWeightProbe(actual_actions);
        weight_bundle.auth = std::move(auth_probe.auth);
    }
    tx_with_private.m_private_bundle = std::move(weight_bundle);
    const int64_t actual_private_delta =
        static_cast<int64_t>(GetTransactionWeight(CTransaction(tx_with_private))) -
        static_cast<int64_t>(GetTransactionWeight(CTransaction(tx_without_private)));
    if (actual_private_delta != estimated_private_delta) {
        error = strprintf("private Orchard weight estimate mismatch: estimated_delta=%d actual_delta=%d",
            estimated_private_delta,
            actual_private_delta);
        return false;
    }
    return true;
}

struct TransparentChangeSource {
    CTxDestination destination;
    CAmount total{0};
    CAmount largest_input{0};
    COutPoint smallest_largest_outpoint;
    bool has_input{false};
};

struct PrivateChangeSource {
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> recipient_raw{};
    CAmount total{0};
    CAmount largest_input{0};
    uint64_t smallest_largest_commitment_index{std::numeric_limits<uint64_t>::max()};
    uint256 smallest_largest_cmx;
    bool has_input{false};
};

bool CanUseSourceChange(CWallet& wallet, const CCoinControl& coin_control, OutputType change_type)
{
    if (coin_control.m_change_type || wallet.m_default_change_type) return false;
    const auto* manager = wallet.GetScriptPubKeyMan(change_type, /*internal=*/true);
    return !manager || !manager->IsHDEnabled() || wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
}

CScript BuildTransparentChangeSizingScript()
{
    return CScript() << OP_1 << std::vector<unsigned char>(32, 0);
}

void SetTransparentChangeSizing(
    CWallet& wallet,
    CoinSelectionParams& coin_selection_params,
    const CScript& script_change)
{
    CTxOut change_prototype_txout(0, script_change);
    coin_selection_params.change_output_size = GetSerializeSize(change_prototype_txout);

    int change_spend_size = CalculateMaximumSignedInputSize(change_prototype_txout, &wallet, /*coin_control=*/nullptr);
    if (change_spend_size == -1) {
        coin_selection_params.change_spend_size = DUMMY_NESTED_P2WPKH_INPUT_SIZE;
    } else {
        coin_selection_params.change_spend_size = static_cast<size_t>(change_spend_size);
    }

    coin_selection_params.m_change_fee = coin_selection_params.m_effective_feerate.GetFee(coin_selection_params.change_output_size);
    coin_selection_params.m_cost_of_change = coin_selection_params.m_discard_feerate.GetFee(coin_selection_params.change_spend_size) + coin_selection_params.m_change_fee;

    const auto dust = GetDustThreshold(change_prototype_txout, coin_selection_params.m_discard_feerate);
    const auto change_spend_fee = coin_selection_params.m_discard_feerate.GetFee(coin_selection_params.change_spend_size);
    coin_selection_params.min_viable_change = std::max(change_spend_fee + 1, dust);
}

util::Result<CTxDestination> GetDominantTransparentChangeDestination(
    const CWallet& wallet,
    const SelectionResult& result) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    std::map<CTxDestination, TransparentChangeSource> sources;
    for (const auto& coin : result.GetInputSet()) {
        CTxDestination destination;
        const CTxOut& source_txout = wallet.GetWalletTx(coin->outpoint.hash) ?
            FindNonChangeParentOutput(wallet, coin->outpoint) :
            coin->txout;
        if (!ExtractDestination(source_txout.scriptPubKey, destination)) {
            if (auto pk_dest = std::get_if<PubKeyDestination>(&destination)) {
                destination = PKHash(pk_dest->GetPubKey());
            } else {
                return util::Error{_("Unable to determine a source address for transparent change.")};
            }
        }
        if (!IsValidDestination(destination)) {
            return util::Error{_("Unable to determine a valid source address for transparent change.")};
        }

        auto& source = sources[destination];
        source.destination = destination;
        if (!MoneyAddSigned(source.total, coin->txout.nValue, source.total)) {
            return util::Error{_("Transparent change source amount is out of range.")};
        }
        if (!source.has_input ||
            coin->txout.nValue > source.largest_input ||
            (coin->txout.nValue == source.largest_input && coin->outpoint < source.smallest_largest_outpoint)) {
            source.largest_input = coin->txout.nValue;
            source.smallest_largest_outpoint = coin->outpoint;
            source.has_input = true;
        }
    }

    if (sources.empty()) {
        return util::Error{_("Unable to determine a source address for transparent change.")};
    }

    auto best = sources.begin();
    for (auto it = std::next(sources.begin()); it != sources.end(); ++it) {
        const auto& current = it->second;
        const auto& selected = best->second;
        if (current.total > selected.total ||
            (current.total == selected.total && current.largest_input > selected.largest_input) ||
            (current.total == selected.total && current.largest_input == selected.largest_input && current.smallest_largest_outpoint < selected.smallest_largest_outpoint)) {
            best = it;
        }
    }
    return best->second.destination;
}

util::Result<std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>> GetDominantPrivateChangeRecipient(
    const std::vector<const CPrivateWalletNote*>& selected)
{
    std::map<std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>, PrivateChangeSource> sources;
    for (const CPrivateWalletNote* note : selected) {
        if (note == nullptr || note->recipient_raw.size() != NITO_ORCHARD_RAW_ADDRESS_SIZE) {
            return util::Error{_("Unable to determine a source address for private change.")};
        }

        std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> recipient_raw{};
        std::copy(note->recipient_raw.begin(), note->recipient_raw.end(), recipient_raw.begin());

        auto& source = sources[recipient_raw];
        source.recipient_raw = recipient_raw;
        if (!MoneyAddSigned(source.total, note->value, source.total)) {
            return util::Error{_("Private change source amount is out of range.")};
        }
        if (!source.has_input ||
            note->value > source.largest_input ||
            (note->value == source.largest_input &&
                (note->commitment_index < source.smallest_largest_commitment_index ||
                 (note->commitment_index == source.smallest_largest_commitment_index && note->cmx < source.smallest_largest_cmx)))) {
            source.largest_input = note->value;
            source.smallest_largest_commitment_index = note->commitment_index;
            source.smallest_largest_cmx = note->cmx;
            source.has_input = true;
        }
    }

    if (sources.empty()) {
        return util::Error{_("Unable to determine a source address for private change.")};
    }

    auto best = sources.begin();
    for (auto it = std::next(sources.begin()); it != sources.end(); ++it) {
        const auto& current = it->second;
        const auto& selected_source = best->second;
        if (current.total > selected_source.total ||
            (current.total == selected_source.total && current.largest_input > selected_source.largest_input) ||
            (current.total == selected_source.total && current.largest_input == selected_source.largest_input &&
                (current.smallest_largest_commitment_index < selected_source.smallest_largest_commitment_index ||
                 (current.smallest_largest_commitment_index == selected_source.smallest_largest_commitment_index &&
                     current.smallest_largest_cmx < selected_source.smallest_largest_cmx)))) {
            best = it;
        }
    }
    return best->second.recipient_raw;
}

struct PreparedPrivateSpend {
    const CPrivateWalletNote* note{nullptr};
    std::array<unsigned char, NITO_PRIVATE_ORCHARD_SPENDING_KEY_SIZE> spending_key{};
    std::array<unsigned char, NITO_ORCHARD_MERKLE_PATH_SIZE> merkle_path{};
};

bool GetPrivateWalletSeed(CWallet& wallet, BIP39Seed& seed, bilingual_str& error) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    return wallet.GetBIP39DerivedSeed(seed, error);
}

static int GetPrivateNoteDepthForSpend(const CWallet& wallet, const CPrivateWalletNote& note) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const auto it = wallet.mapWallet.find(note.txid);
    if (it != wallet.mapWallet.end()) {
        const CWalletTx& wtx = it->second;
        const auto* confirmed = wtx.state<TxStateConfirmed>();
        if (confirmed == nullptr) return 0;
        if (confirmed->confirmed_block_hash != note.block_hash || confirmed->confirmed_block_height != note.block_height) return 0;
    }

    if (!note.IsConfirmed()) return 0;
    if (!wallet.HaveChain()) return 0;

    bool active{false};
    int height{-1};
    if (!wallet.chain().findBlock(note.block_hash, FoundBlock().inActiveChain(active).height(height)) ||
            !active || height != note.block_height) {
        return 0;
    }

    const int depth = wallet.GetLastBlockHeight() - note.block_height + 1;
    return std::max(depth, 0);
}

} // namespace

bool SelectPrivateNotes(
    const CWallet& wallet,
    CAmount target,
    const CCoinControl& coin_control,
    std::vector<const CPrivateWalletNote*>& selected,
    CAmount& selected_value) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    selected.clear();
    selected_value = 0;

    const std::vector<uint256> selected_private_notes = coin_control.ListSelectedPrivateNotes();
    const bool has_preselected_private_notes = !selected_private_notes.empty();
    if (has_preselected_private_notes && selected_private_notes.size() > PRIVATE_WALLET_MAX_ACTIONS) {
        return false;
    }

    std::vector<const CPrivateWalletNote*> candidates;
    candidates.reserve(has_preselected_private_notes ? selected_private_notes.size() : wallet.mapPrivateNotes.size());
    auto consider = [&](const CPrivateWalletNote& note, bool is_preselected) {
        const bool spendable = note.IsSpendable() ||
            (coin_control.m_allow_spent_private_note_replacement && is_preselected &&
                note.HasNullifier() && note.HasWitnessPosition() && note.HasSpendSecrets() && note.value > 0);
        if (spendable && GetPrivateNoteDepthForSpend(wallet, note) > 0) {
            candidates.push_back(&note);
        }
    };
    if (has_preselected_private_notes) {
        for (const auto& cmx : selected_private_notes) {
            const auto found = wallet.mapPrivateNotes.find(cmx);
            if (found == wallet.mapPrivateNotes.end()) return false;
            consider(found->second, true);
        }
    } else {
        for (const auto& [_, note] : wallet.mapPrivateNotes) consider(note, false);
    }
    if (has_preselected_private_notes && candidates.size() != selected_private_notes.size()) {
        return false;
    }
    std::sort(candidates.begin(), candidates.end(), [](const CPrivateWalletNote* a, const CPrivateWalletNote* b) {
        // Minimize the number of actions. In particular, never exhaust the
        // action budget on small notes while a larger usable note is available.
        if (a->value != b->value) return a->value > b->value;
        if (a->commitment_index != b->commitment_index) return a->commitment_index < b->commitment_index;
        return a->cmx < b->cmx;
    });

    for (const CPrivateWalletNote* note : candidates) {
        if (selected.size() >= PRIVATE_WALLET_MAX_ACTIONS) break;
        if (!MoneyAddSigned(selected_value, note->value, selected_value)) return false;
        selected.push_back(note);
        if (!has_preselected_private_notes && selected_value >= target) return true;
    }
    return selected_value >= target;
}

namespace {
struct PrivateSpendAvailability
{
    size_t spendable_notes{0};
    size_t unconfirmed_notes{0};
    CAmount spendable_value{0};
    CAmount unconfirmed_value{0};
};

PrivateSpendAvailability GetPrivateSpendAvailability(const CWallet& wallet, const CCoinControl& coin_control)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    PrivateSpendAvailability availability;
    const std::vector<uint256> selected_private_notes = coin_control.ListSelectedPrivateNotes();
    const bool has_preselected_private_notes = !selected_private_notes.empty();
    std::set<uint256> pending_spent_nullifiers;
    for (const auto& [txid, wtx] : wallet.mapWallet) {
        if (!wtx.tx || !wtx.tx->HasPrivateBundle() || !wtx.state<TxStateInMempool>()) continue;
        for (const auto& action : wtx.tx->m_private_bundle->effects.actions) {
            if (!action.nullifier.IsNull()) {
                pending_spent_nullifiers.insert(action.nullifier);
            }
        }
    }

    for (const auto& [cmx, note] : wallet.mapPrivateNotes) {
        const bool is_preselected = has_preselected_private_notes &&
            std::find(selected_private_notes.begin(), selected_private_notes.end(), cmx) != selected_private_notes.end();
        if (has_preselected_private_notes && !is_preselected) continue;
        const bool pending_spent = note.spent && note.HasNullifier() && pending_spent_nullifiers.count(note.nullifier) != 0;
        const bool has_private_spend_material = (!note.spent || pending_spent) && note.HasNullifier() && note.HasSpendSecrets() && note.value > 0;
        if (!has_private_spend_material) continue;

        const int depth = GetPrivateNoteDepthForSpend(wallet, note);
        if (!pending_spent && depth > 0 && note.HasWitnessPosition()) {
            ++availability.spendable_notes;
            if (!MoneyAddSigned(availability.spendable_value, note.value, availability.spendable_value)) {
                availability.spendable_value = MAX_MONEY;
            }
        } else {
            ++availability.unconfirmed_notes;
            if (!MoneyAddSigned(availability.unconfirmed_value, note.value, availability.unconfirmed_value)) {
                availability.unconfirmed_value = MAX_MONEY;
            }
        }
    }
    return availability;
}

bool PreparePrivateSpends(
    const std::vector<const CPrivateWalletNote*>& selected,
    const BIP39Seed& seed,
    interfaces::Chain& chain,
    const uint256& expected_anchor,
    std::vector<PreparedPrivateSpend>& prepared,
    std::string& error)
{
    error.clear();
    for (auto& spend : prepared) {
        memory_cleanse(spend.spending_key.data(), spend.spending_key.size());
        memory_cleanse(spend.merkle_path.data(), spend.merkle_path.size());
    }
    prepared.clear();
    prepared.resize(selected.size());
    if (selected.empty()) return true;

    std::vector<uint64_t> commitment_indices;
    commitment_indices.reserve(selected.size());
    for (size_t i = 0; i < selected.size(); ++i) {
        const CPrivateWalletNote& note = *selected[i];
        if (note.commitment_index > std::numeric_limits<uint32_t>::max()) {
            error = "private note position exceeds private wallet builder limit";
            return false;
        }
        commitment_indices.push_back(note.commitment_index);
    }

    std::vector<std::vector<uint256>> auth_paths;
    uint256 auth_root;
    if (!chain.getPrivateAuthPaths(commitment_indices, auth_paths, auth_root)) {
        error = "unable to read synced private wallet index authorization paths; start with -orchardindex=1 and wait for getindexinfo orchardindex to report synced=true";
        return false;
    }
    if (auth_root != expected_anchor) {
        error = "private note auth path root does not match current private anchor";
        return false;
    }
    if (auth_paths.size() != selected.size()) {
        error = "private note auth path count mismatch";
        return false;
    }

    for (size_t i = 0; i < selected.size(); ++i) {
        const CPrivateWalletNote& note = *selected[i];
        const std::vector<uint256>& auth_path = auth_paths[i];
        if (auth_path.size() != NITO_ORCHARD_MERKLE_PATH_SIZE / 32) {
            error = "private note auth path has unexpected depth";
            return false;
        }

        PreparedPrivateSpend& spend = prepared[i];
        spend.note = &note;
        for (size_t path_idx = 0; path_idx < auth_path.size(); ++path_idx) {
            std::memcpy(spend.merkle_path.data() + path_idx * 32, auth_path[path_idx].begin(), 32);
        }

        PrivateOrchardKeyPath path{note.account, note.internal, note.diversifier_index, note.derivation_version};
        auto key_result = DeriveNitoPrivateOrchardSpendingKey(seed, path, spend.spending_key, error);
        if (key_result != PrivateOrchardBuildResult::OK) {
            if (error.empty()) error = "failed to derive private note spending key";
            return false;
        }
    }
    return true;
}

void CleansePreparedPrivateSpends(std::vector<PreparedPrivateSpend>& prepared)
{
    for (auto& spend : prepared) {
        memory_cleanse(spend.spending_key.data(), spend.spending_key.size());
        memory_cleanse(spend.merkle_path.data(), spend.merkle_path.size());
    }
}

util::Result<CreatedTransactionResult> CreatePrivateTransactionInternal(
        CWallet& wallet,
        const std::vector<CRecipient>& vecSend,
        std::optional<unsigned int> change_pos,
        const CCoinControl& coin_control,
        bool sign) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    auto count_private_recipients = [&vecSend]() {
        return std::count_if(vecSend.begin(), vecSend.end(), [](const CRecipient& recipient) {
            return recipient.IsPrivate();
        });
    };
    auto calculate_recipient_values = [&vecSend](CAmount fee) -> util::Result<std::vector<CAmount>> {
        std::vector<CAmount> recipient_values;
        recipient_values.reserve(vecSend.size());
        const size_t subtract_count = std::count_if(vecSend.begin(), vecSend.end(), [](const CRecipient& recipient) {
            return recipient.fSubtractFeeFromAmount;
        });
        if (subtract_count == 0) {
            for (const CRecipient& recipient : vecSend) {
                recipient_values.push_back(recipient.nAmount);
            }
            return recipient_values;
        }

        size_t subtract_seen{0};
        for (const CRecipient& recipient : vecSend) {
            CAmount value = recipient.nAmount;
            if (recipient.fSubtractFeeFromAmount) {
                value -= fee / static_cast<CAmount>(subtract_count);
                if (subtract_seen == 0) {
                    value -= fee % static_cast<CAmount>(subtract_count);
                }
                ++subtract_seen;
            }
            if (value <= 0 || !MoneyRange(value)) {
                return util::Error{_("The private transaction amount is too small to pay the fee.")};
            }
            recipient_values.push_back(value);
        }
        return recipient_values;
    };
    auto sum_recipient_values = [&vecSend](Span<const CAmount> recipient_values, bool private_outputs) -> util::Result<CAmount> {
        CAmount total{0};
        for (size_t i = 0; i < vecSend.size(); ++i) {
            if (vecSend[i].IsPrivate() != private_outputs) continue;
            if (!MoneyAddSigned(total, recipient_values[i], total)) {
                return util::Error{private_outputs ? _("Private output total amount out of range.") : _("Transparent output total amount out of range.")};
            }
        }
        return total;
    };
    auto load_private_root = [&wallet](uint256& private_root, uint64_t& private_commitment_count) -> util::Result<void> {
        if (wallet.chain().getPrivateChainState(private_root, private_commitment_count)) {
            return {};
        }
        std::string empty_error;
        if (!GetPrivateEmptyRoot(private_root, empty_error)) {
            return util::Error{Untranslated(empty_error.empty() ? "unable to initialize the Nito.network private empty root" : empty_error)};
        }
        private_commitment_count = 0;
        return {};
    };
    auto add_transparent_outputs = [&wallet, &vecSend](CMutableTransaction& txNew, Span<const CAmount> recipient_values) -> util::Result<CAmount> {
        CAmount transparent_output_sum{0};
        for (size_t i = 0; i < vecSend.size(); ++i) {
            const CRecipient& recipient = vecSend[i];
            if (recipient.IsPrivate()) continue;
            if (!IsValidDestination(recipient.dest)) {
                return util::Error{_("Private-note spending to data outputs or invalid transparent destinations is not supported.")};
            }
            CTxOut txout(recipient_values[i], GetScriptForDestination(recipient.dest));
            if (IsDust(txout, wallet.chain().relayDustFee())) {
                return util::Error{_("Transaction amount too small")};
            }
            if (!MoneyAddSigned(transparent_output_sum, txout.nValue, transparent_output_sum)) {
                return util::Error{_("Transparent output total amount out of range.")};
            }
            txNew.vout.push_back(std::move(txout));
        }
        return transparent_output_sum;
    };

    const size_t private_recipient_count = count_private_recipients();
    const bool has_private_recipient = private_recipient_count > 0;
    const bool subtract_fee_from_outputs = std::any_of(vecSend.begin(), vecSend.end(), [](const CRecipient& recipient) {
        return recipient.fSubtractFeeFromAmount;
    });

    if (change_pos) {
        return util::Error{_("Nito.network private-bundle transaction creation does not support a custom change position.")};
    }
    if (vecSend.empty()) {
        return util::Error{_("Nito.network private transaction requires at least one recipient.")};
    }
    const int current_block_height = wallet.GetLastBlockHeight();
    const int private_activation_height = Params().GetConsensus().privateTxActivationHeight;
    if (!Consensus::PrivateTxActive(Params().GetConsensus(), current_block_height)) {
        return private_activation_height < 0
            ? util::Error{_("Nito.network private transactions are not active on this network.")}
            : util::Error{Untranslated("Nito.network private transactions activate at block " +
                  std::to_string(private_activation_height) + ". Current block: " +
                  std::to_string(current_block_height) + ".")};
    }

    CAmount recipients_sum{0};
    for (const CRecipient& recipient : vecSend) {
        if (recipient.nAmount <= 0 || !MoneyRange(recipient.nAmount)) {
            return util::Error{_("Invalid private transaction recipient amount.")};
        }
        if (!MoneyAddSigned(recipients_sum, recipient.nAmount, recipients_sum)) {
            return util::Error{_("Private transaction recipient total amount out of range.")};
        }
    }

    FeeCalculation feeCalc;
    CFeeRate fee_rate = GetMinimumFeeRate(wallet, coin_control, &feeCalc);
    if (coin_control.m_feerate && fee_rate > *coin_control.m_feerate) {
        return util::Error{strprintf(_("Fee rate (%s) is lower than the minimum fee rate setting (%s)"), coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), fee_rate.ToString(FeeEstimateMode::SAT_VB))};
    }
    if (feeCalc.reason == FeeReason::FALLBACK && !wallet.m_allow_fallback_fee) {
        return util::Error{strprintf(_("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable %s."), "-fallbackfee")};
    }

    BIP39Seed derived_seed{};
    BIP39SeedGuard seed_cleanup{derived_seed};
    bilingual_str seed_error;
    if (!GetPrivateWalletSeed(wallet, derived_seed, seed_error)) {
        return util::Error{seed_error};
    }

    auto build_from_private_notes = [&]() EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) -> util::Result<CreatedTransactionResult> {
        const auto private_build_start{SteadyClock::now()};
        if (coin_control.HasSelected()) {
            return util::Error{_("Nito.network private-note spending cannot mix manually selected transparent UTXOs with private notes; use shieldtoaddress for transparent UTXO shielding.")};
        }

        uint256 private_root;
        uint64_t private_commitment_count{0};
        if (auto root_res = load_private_root(private_root, private_commitment_count); !root_res) {
            return util::Error{util::ErrorString(root_res)};
        }
        auto private_no_spendable_notes_error = [&](const PrivateSpendAvailability& private_availability) {
            if (coin_control.HasSelectedPrivateNotes()) {
                if (private_availability.spendable_notes == 0 && private_availability.unconfirmed_notes > 0) {
                    return _("The selected private notes are waiting for confirmation. Wait for the next block before spending them.");
                }
                return _("The selected private notes do not cover the transaction target.");
            }
            if (private_availability.unconfirmed_notes > 0) {
                return _("Private funds are waiting for confirmation. Wait for the next block before spending private notes.");
            }
            return _("No spendable private notes are available.");
        };
        if (private_commitment_count == 0) {
            return util::Error{private_no_spendable_notes_error(GetPrivateSpendAvailability(wallet, coin_control))};
        }
        auto private_selection_error = [&](CAmount target) {
            const auto private_availability = GetPrivateSpendAvailability(wallet, coin_control);
            if (coin_control.ListSelectedPrivateNotes().size() > PRIVATE_WALLET_MAX_ACTIONS ||
                (!coin_control.HasSelectedPrivateNotes() && private_availability.spendable_value >= target)) {
                return _("Private transaction would exceed the maximum Orchard action count.");
            }
            if (coin_control.HasSelectedPrivateNotes()) {
                if (private_availability.spendable_notes == 0 && private_availability.unconfirmed_notes > 0) {
                    return _("The selected private notes are waiting for confirmation. Wait for the next block before spending them.");
                }
                return _("The selected private notes do not cover the transaction target.");
            }
            if (private_availability.spendable_notes == 0) {
                return private_no_spendable_notes_error(private_availability);
            }
            CAmount total_private_value{private_availability.spendable_value};
            const bool have_total_private_value = MoneyAddSigned(total_private_value, private_availability.unconfirmed_value, total_private_value);
            if (private_availability.spendable_value < target && have_total_private_value && total_private_value >= target) {
                return _("Some private funds are still waiting for confirmation. Wait for the next block or spend a smaller confirmed amount.");
            }
            return strprintf(_("Insufficient confirmed private funds. Available private balance: %s; required: %s."),
                FormatMoney(private_availability.spendable_value), FormatMoney(target));
        };

        CAmount fee{fee_rate.GetFee(1000)};
        CTransactionRef final_tx;
        CAmount final_fee{0};
        std::vector<PSBTProprietary> final_private_psbt_records;
        std::vector<uint256> final_private_spend_note_ids;
        std::vector<PreparedPrivateSpend> prepared;
        std::string private_error;
        int64_t select_ms{0};
        int64_t estimate_ms{0};
        int64_t proof_ms{0};
        int64_t verify_ms{0};
        int64_t final_estimated_vsize{0};
        int64_t final_actual_vsize{0};
        int final_attempt{0};

        for (int attempt = 0; attempt < 8; ++attempt) {
            if (fee < 0 || !MoneyRange(fee)) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{_("Private transaction fee is out of range.")};
            }

            CAmount selection_target{recipients_sum};
            if (!subtract_fee_from_outputs && !MoneyAddSigned(selection_target, fee, selection_target)) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{_("Private transaction target amount out of range.")};
            }

            std::vector<const CPrivateWalletNote*> selected;
            CAmount selected_value{0};
            const auto select_start{SteadyClock::now()};
            if (!SelectPrivateNotes(wallet, selection_target, coin_control, selected, selected_value)) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{private_selection_error(selection_target)};
            }

            CleansePreparedPrivateSpends(prepared);
            prepared.clear();
            if (!PreparePrivateSpends(selected, derived_seed, wallet.chain(), private_root, prepared, private_error)) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{Untranslated(private_error.empty() ? "failed to prepare private spends" : private_error)};
            }
            select_ms += Ticks<std::chrono::milliseconds>(SteadyClock::now() - select_start);

            auto recipient_values_res = calculate_recipient_values(fee);
            if (!recipient_values_res) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{util::ErrorString(recipient_values_res)};
            }
            const std::vector<CAmount>& recipient_values = *recipient_values_res;

            auto private_output_sum_res = sum_recipient_values(Span<const CAmount>{recipient_values}, /*private_outputs=*/true);
            if (!private_output_sum_res) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{util::ErrorString(private_output_sum_res)};
            }

            CMutableTransaction txNew;
            if (coin_control.m_version) {
                txNew.nVersion = coin_control.m_version.value();
            } else if (coin_control.m_signal_bip125_rbf.value_or(wallet.m_signal_rbf)) {
                // A private-note-only transaction has no transparent input
                // sequence with which to signal BIP125 replacement.
                txNew.nVersion = NITO_PRIVATE_RBF_TX_VERSION;
            }

            auto transparent_output_sum_res = add_transparent_outputs(txNew, Span<const CAmount>{recipient_values});
            if (!transparent_output_sum_res) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{util::ErrorString(transparent_output_sum_res)};
            }

            CAmount spend_target_sum{*private_output_sum_res};
            if (!MoneyAddSigned(spend_target_sum, *transparent_output_sum_res, spend_target_sum)) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{_("Private transaction spend target out of range.")};
            }

            CAmount change_value = selected_value - spend_target_sum - fee;
            if (change_value < 0 || !MoneyRange(change_value)) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{_("Private transaction change amount out of range.")};
            }

            std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> change_raw{};
            bool uses_change{change_value > 0};
            if (uses_change) {
                auto change_recipient_res = GetDominantPrivateChangeRecipient(selected);
                if (!change_recipient_res) {
                    CleansePreparedPrivateSpends(prepared);
                    return util::Error{util::ErrorString(change_recipient_res)};
                }
                change_raw = *change_recipient_res;
            }

            std::vector<PrivateOrchardSpendInfo> spend_infos;
            spend_infos.reserve(prepared.size());
            for (const PreparedPrivateSpend& spend : prepared) {
                const CPrivateWalletNote& note = *spend.note;
                spend_infos.push_back(PrivateOrchardSpendInfo{
                    Span<const unsigned char>{spend.spending_key.data(), spend.spending_key.size()},
                    Span<const unsigned char>{note.recipient_raw.data(), note.recipient_raw.size()},
                    note.value,
                    Span<const unsigned char>{note.rho.data(), note.rho.size()},
                    Span<const unsigned char>{note.rseed.data(), note.rseed.size()},
                    static_cast<uint32_t>(note.commitment_index),
                    Span<const unsigned char>{spend.merkle_path.data(), spend.merkle_path.size()},
                });
            }

            std::vector<PrivateOrchardOutputInfo> output_infos;
            output_infos.reserve(private_recipient_count + (uses_change ? 1 : 0));
            for (size_t i = 0; i < vecSend.size(); ++i) {
                if (!vecSend[i].IsPrivate()) continue;
                output_infos.push_back(PrivateOrchardOutputInfo{
                    Span<const unsigned char>{vecSend[i].private_raw_address->data(), vecSend[i].private_raw_address->size()},
                    recipient_values[i],
                    false,
                });
            }
            if (uses_change) {
                output_infos.push_back(PrivateOrchardOutputInfo{
                    Span<const unsigned char>{change_raw.data(), change_raw.size()},
                    change_value,
                    true,
                });
            }

            const size_t action_count = EstimatePrivateBundleActions(spend_infos.size(), output_infos.size());
            if (action_count == 0 || action_count > PRIVATE_WALLET_MAX_ACTIONS) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{_("Private transaction would exceed the maximum Orchard action count.")};
            }

            if (coin_control.m_locktime) {
                txNew.nLockTime = coin_control.m_locktime.value();
            } else {
                FastRandomContext rng_fast;
                DiscourageFeeSniping(txNew, rng_fast, wallet.chain(), wallet.GetLastBlockHash(), wallet.GetLastBlockHeight());
            }

            const auto estimate_start{SteadyClock::now()};
            const TxSize estimated_size{EstimatePrivateTransactionSize(txNew, action_count, private_root, /*value_balance=*/0)};
            const int64_t estimated_private_delta{EstimatePrivateBundleWeightDelta(txNew, action_count, private_root, /*value_balance=*/0)};
            const CAmount fee_needed = fee_rate.GetFee(estimated_size.vsize);
            estimate_ms += Ticks<std::chrono::milliseconds>(SteadyClock::now() - estimate_start);
            if (fee_needed != fee) {
                fee = fee_needed;
                CleansePreparedPrivateSpends(prepared);
                prepared.clear();
                continue;
            }

            auto sighash_callback = [&txNew](const CPrivateBundle& effects_bundle, uint256& sighash_out, std::string& error) {
                CMutableTransaction sighash_tx{txNew};
                sighash_tx.m_private_bundle = effects_bundle;
                sighash_out = PrivateBundleSighash(sighash_tx);
                error.clear();
                return true;
            };

            CPrivateBundle bundle;
            const auto proof_start{SteadyClock::now()};
            auto build_result = sign
                ? BuildPrivateOrchardBundleWithSighashCallback(
                    Span<const PrivateOrchardSpendInfo>{spend_infos},
                    Span<const PrivateOrchardOutputInfo>{output_infos},
                    private_root,
                    sighash_callback,
                    bundle,
                    private_error)
                : BuildPrivateOrchardBundleEffectsOnly(
                    Span<const PrivateOrchardSpendInfo>{spend_infos},
                    Span<const PrivateOrchardOutputInfo>{output_infos},
                    private_root,
                    bundle,
                    private_error);
            proof_ms += Ticks<std::chrono::milliseconds>(SteadyClock::now() - proof_start);
            if (build_result != PrivateOrchardBuildResult::OK) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{Untranslated(private_error.empty() ? "failed to build private Orchard bundle" : private_error)};
            }

            std::string weight_error;
            if (!CheckPrivateWeightEstimate(txNew, bundle, action_count, estimated_private_delta, weight_error)) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{Untranslated(weight_error)};
            }

            txNew.m_private_bundle = std::move(bundle);
            CTransactionRef tx = MakeTransactionRef(txNew);

            if (sign) {
                const auto verify_start{SteadyClock::now()};
                std::string verify_error;
                if (VerifyPrivateOrchardBundle(*tx, verify_error) != PrivateOrchardVerifyResult::OK) {
                    CleansePreparedPrivateSpends(prepared);
                    return util::Error{Untranslated(verify_error.empty() ? "private Orchard bundle verification failed" : verify_error)};
                }
                verify_ms += Ticks<std::chrono::milliseconds>(SteadyClock::now() - verify_start);
            }

            const int64_t actual_weight = sign ? static_cast<int64_t>(GetTransactionWeight(*tx)) : estimated_size.weight;
            const int64_t actual_vsize = sign ? static_cast<int64_t>(GetVirtualTransactionSize(*tx)) : estimated_size.vsize;
            if (actual_vsize > estimated_size.vsize) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{Untranslated(strprintf("private Orchard vsize estimate mismatch: estimated=%d actual=%d", estimated_size.vsize, actual_vsize))};
            }

            if (actual_weight > MAX_STANDARD_TX_WEIGHT) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{_("Transaction too large")};
            }
            if (fee > wallet.m_default_max_tx_fee) {
                CleansePreparedPrivateSpends(prepared);
                return util::Error{TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED)};
            }
            if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
                auto result = wallet.chain().checkChainLimits(tx);
                if (!result) {
                    CleansePreparedPrivateSpends(prepared);
                    return util::Error{util::ErrorString(result)};
                }
            }

            final_tx = tx;
            final_fee = fee;
            final_estimated_vsize = estimated_size.vsize;
            final_actual_vsize = actual_vsize;
            final_attempt = attempt + 1;
            final_private_spend_note_ids.clear();
            final_private_spend_note_ids.reserve(selected.size());
            for (const CPrivateWalletNote* note : selected) {
                final_private_spend_note_ids.push_back(note->cmx);
            }
            if (!sign) {
                final_private_psbt_records.clear();

                CPrivatePSBTOrchardBundlePlan plan;
                plan.anchor = private_root;
                plan.value_balance = tx->m_private_bundle->GetValueBalance();
                plan.spend_count = static_cast<uint32_t>(prepared.size());
                plan.output_count = static_cast<uint32_t>(output_infos.size());
                final_private_psbt_records.push_back(MakeNitoPSBTOrchardBundlePlanProprietary(plan));

                for (uint64_t spend_index = 0; spend_index < prepared.size(); ++spend_index) {
                    const PreparedPrivateSpend& spend = prepared[spend_index];
                    const CPrivateWalletNote& note = *spend.note;
                    CPrivatePSBTOrchardSpendMaterial material;
                    material.cmx = note.cmx;
                    material.nullifier = note.nullifier;
                    material.value = note.value;
                    material.derivation_version = note.derivation_version;
                    material.account = note.account;
                    material.internal = note.internal;
                    material.diversifier_index = note.diversifier_index;
                    material.commitment_index = note.commitment_index;
                    material.action_index = note.action_index;
                    material.recipient_raw = note.recipient_raw;
                    material.rho = note.rho;
                    material.rseed = note.rseed;
                    material.merkle_path.assign(spend.merkle_path.begin(), spend.merkle_path.end());
                    final_private_psbt_records.push_back(MakeNitoPSBTOrchardSpendMaterialProprietary(spend_index, material));
                }

                for (uint64_t output_index = 0; output_index < output_infos.size(); ++output_index) {
                    const PrivateOrchardOutputInfo& output = output_infos[output_index];
                    CPrivatePSBTOrchardOutputMaterial material;
                    material.recipient_raw.assign(output.recipient_raw.begin(), output.recipient_raw.end());
                    material.value = output.value;
                    material.ovk_internal = output.ovk_internal;
                    final_private_psbt_records.push_back(MakeNitoPSBTOrchardOutputMaterialProprietary(output_index, material));
                }
            }
            break;
        }

        CleansePreparedPrivateSpends(prepared);

        if (!final_tx) {
            return util::Error{_("Unable to converge Nito.network private transaction fee calculation.")};
        }

        wallet.WalletLogPrintf("Private Coin Selection: Source:private Notes:%u Fee:%d VSize:%u EstimateVSize:%u Attempts:%d SelectMs:%d EstimateMs:%d ProofMs:%d VerifyMs:%d BuildMs:%d\n",
            static_cast<unsigned>(final_tx->m_private_bundle ? final_tx->m_private_bundle->effects.actions.size() : 0),
            final_fee,
            static_cast<unsigned>(final_actual_vsize),
            static_cast<unsigned>(final_estimated_vsize),
            final_attempt,
            select_ms,
            estimate_ms,
            proof_ms,
            verify_ms,
            Ticks<std::chrono::milliseconds>(SteadyClock::now() - private_build_start));

        CreatedTransactionResult result(final_tx, final_fee, std::nullopt, feeCalc);
        result.private_psbt_records = std::move(final_private_psbt_records);
        result.private_spend_note_ids = std::move(final_private_spend_note_ids);
        return result;
    };

    auto build_from_transparent_coins = [&]() EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) -> util::Result<CreatedTransactionResult> {
        const auto private_build_start{SteadyClock::now()};
        if (!has_private_recipient) {
            return util::Error{_("shieldtoaddress requires nito1x private recipients only.")};
        }

        uint256 private_root;
        uint64_t private_commitment_count{0};
        if (auto root_res = load_private_root(private_root, private_commitment_count); !root_res) {
            return util::Error{util::ErrorString(root_res)};
        }

        CAmount fee{fee_rate.GetFee(1000)};
        CTransactionRef final_tx;
        CAmount final_fee{0};
        int64_t select_ms{0};
        int64_t estimate_ms{0};
        int64_t proof_ms{0};
        int64_t sign_ms{0};
        int64_t verify_ms{0};
        int64_t final_estimated_vsize{0};
        int64_t final_actual_vsize{0};
        int final_attempt{0};

        const OutputType change_type = wallet.TransactionChangeType(coin_control.m_change_type ? *coin_control.m_change_type : wallet.m_default_change_type, vecSend);
        ReserveDestination reservedest(&wallet, change_type);
        CScript scriptChange;
        bool use_source_change{false};
        bool change_key_unavailable{false};
        if (!std::get_if<CNoDestination>(&coin_control.destChange)) {
            scriptChange = GetScriptForDestination(coin_control.destChange);
        } else {
            CTxDestination dest;
            auto op_dest = reservedest.GetReservedDestination(/*internal=*/true);
            if (!op_dest) {
                change_key_unavailable = !CanUseSourceChange(wallet, coin_control, change_type);
                use_source_change = !change_key_unavailable;
            } else {
                dest = *op_dest;
                scriptChange = GetScriptForDestination(dest);
            }
            CHECK_NONFATAL(IsValidDestination(dest) != scriptChange.empty());
            if (change_key_unavailable) scriptChange = BuildTransparentChangeSizingScript();
        }
        bool final_uses_transparent_change{false};

        for (int attempt = 0; attempt < 8; ++attempt) {
            if (fee < 0 || !MoneyRange(fee)) {
                return util::Error{_("Private transaction fee is out of range.")};
            }

            auto recipient_values_res = calculate_recipient_values(fee);
            if (!recipient_values_res) return util::Error{util::ErrorString(recipient_values_res)};
            const std::vector<CAmount>& recipient_values = *recipient_values_res;

            auto private_output_sum_res = sum_recipient_values(Span<const CAmount>{recipient_values}, /*private_outputs=*/true);
            if (!private_output_sum_res) return util::Error{util::ErrorString(private_output_sum_res)};
            const CAmount private_output_sum = *private_output_sum_res;

            auto transparent_output_sum_res = sum_recipient_values(Span<const CAmount>{recipient_values}, /*private_outputs=*/false);
            if (!transparent_output_sum_res) return util::Error{util::ErrorString(transparent_output_sum_res)};
            const CAmount transparent_output_sum = *transparent_output_sum_res;

            CAmount spend_target_sum{private_output_sum};
            if (!MoneyAddSigned(spend_target_sum, transparent_output_sum, spend_target_sum)) {
                return util::Error{_("Private shielding spend target out of range.")};
            }

            CAmount selection_target{subtract_fee_from_outputs ? recipients_sum : spend_target_sum};
            if (!subtract_fee_from_outputs && !MoneyAddSigned(selection_target, fee, selection_target)) {
                return util::Error{_("Private shielding target amount out of range.")};
            }

            const auto select_start{SteadyClock::now()};
            FastRandomContext rng_fast;
            CoinSelectionParams coin_selection_params{rng_fast};
            coin_selection_params.m_avoid_partial_spends = coin_control.m_avoid_partial_spends;
            coin_selection_params.m_include_unsafe_inputs = coin_control.m_include_unsafe_inputs;
            coin_selection_params.m_long_term_feerate = wallet.m_consolidate_feerate;
            coin_selection_params.m_discard_feerate = GetDiscardRate(wallet);
            coin_selection_params.m_effective_feerate = fee_rate;
            coin_selection_params.m_subtract_fee_outputs = subtract_fee_from_outputs;
            coin_selection_params.min_viable_change = 1;
            coin_selection_params.tx_noinputs_size = 10;

            PreSelectedInputs preset_inputs;
            if (coin_control.HasSelected()) {
                auto res_fetch_inputs = FetchSelectedInputs(wallet, coin_control, coin_selection_params);
                if (!res_fetch_inputs) return util::Error{util::ErrorString(res_fetch_inputs)};
                preset_inputs = *res_fetch_inputs;
            }

            CoinsResult available_coins;
            if (coin_control.m_allow_other_inputs) {
                available_coins = AvailableCoins(wallet, &coin_control, coin_selection_params.m_effective_feerate);
            }

            auto select_coins_res = SelectCoins(wallet, available_coins, preset_inputs, selection_target, coin_control, coin_selection_params);
            if (!select_coins_res) {
                const bilingual_str& err = util::ErrorString(select_coins_res);
                return util::Error{err.empty() ? _("Insufficient funds") : err};
            }
            const SelectionResult& result = *select_coins_res;
            std::vector<std::shared_ptr<COutput>> selected_coins = result.GetShuffledInputVector();
            select_ms += Ticks<std::chrono::milliseconds>(SteadyClock::now() - select_start);

            if (coin_control.HasSelected() && coin_control.HasSelectedOrder()) {
                std::stable_sort(selected_coins.begin(), selected_coins.end(),
                    [&coin_control](const std::shared_ptr<COutput>& a, const std::shared_ptr<COutput>& b) {
                        auto a_pos = coin_control.GetSelectionPos(a->outpoint);
                        auto b_pos = coin_control.GetSelectionPos(b->outpoint);
                        if (a_pos.has_value() && b_pos.has_value()) {
                            return a_pos.value() < b_pos.value();
                        }
                        return a_pos.has_value() && !b_pos.has_value();
                    });
            }

            const CAmount selected_value = result.GetSelectedValue();
            CScript selected_change_script{scriptChange};
            if (use_source_change) {
                auto change_dest_res = GetDominantTransparentChangeDestination(wallet, result);
                if (!change_dest_res) return util::Error{util::ErrorString(change_dest_res)};
                selected_change_script = GetScriptForDestination(*change_dest_res);
            }
            CTxOut change_prototype_txout(0, selected_change_script);
            const CAmount transparent_change_dust = GetDustThreshold(change_prototype_txout, wallet.chain().relayDustFee());
            CAmount transparent_change_value = selected_value - spend_target_sum - fee;
            if (transparent_change_value < 0 || !MoneyRange(transparent_change_value)) {
                return util::Error{_("Private shielding transparent change amount out of range.")};
            }
            const bool uses_transparent_change = transparent_change_value > transparent_change_dust;
            if (uses_transparent_change && change_key_unavailable) {
                return util::Error{_("Transaction needs a change address, but we can't generate it.")};
            }

            std::vector<PrivateOrchardOutputInfo> output_infos;
            output_infos.reserve(private_recipient_count);
            for (size_t i = 0; i < vecSend.size(); ++i) {
                if (!vecSend[i].IsPrivate()) continue;
                output_infos.push_back(PrivateOrchardOutputInfo{
                    Span<const unsigned char>{vecSend[i].private_raw_address->data(), vecSend[i].private_raw_address->size()},
                    recipient_values[i],
                    false,
                });
            }
            const size_t action_count = EstimatePrivateBundleActions(/*spend_count=*/0, output_infos.size());
            if (action_count == 0 || action_count > PRIVATE_WALLET_MAX_ACTIONS) {
                return util::Error{_("Private shielding transaction would exceed the maximum Orchard action count.")};
            }

            CMutableTransaction txNew;
            if (coin_control.m_version) {
                txNew.nVersion = coin_control.m_version.value();
            }

            bool use_anti_fee_sniping = true;
            const uint32_t default_sequence{coin_control.m_signal_bip125_rbf.value_or(wallet.m_signal_rbf) ? MAX_BIP125_RBF_SEQUENCE : CTxIn::MAX_SEQUENCE_NONFINAL};
            for (const std::shared_ptr<COutput>& coin : selected_coins) {
                std::optional<uint32_t> sequence = coin_control.GetSequence(coin->outpoint);
                if (sequence) {
                    use_anti_fee_sniping = false;
                }
                txNew.vin.emplace_back(coin->outpoint, CScript{}, sequence.value_or(default_sequence));

                auto scripts = coin_control.GetScripts(coin->outpoint);
                if (scripts.first) {
                    txNew.vin.back().scriptSig = *scripts.first;
                }
                if (scripts.second) {
                    txNew.vin.back().scriptWitness = *scripts.second;
                }
            }
            if (coin_control.m_locktime) {
                txNew.nLockTime = coin_control.m_locktime.value();
                use_anti_fee_sniping = false;
            }
            if (use_anti_fee_sniping) {
                DiscourageFeeSniping(txNew, rng_fast, wallet.chain(), wallet.GetLastBlockHash(), wallet.GetLastBlockHeight());
            }
            auto add_transparent_outputs_res = add_transparent_outputs(txNew, Span<const CAmount>{recipient_values});
            if (!add_transparent_outputs_res) {
                return util::Error{util::ErrorString(add_transparent_outputs_res)};
            }
            if (*add_transparent_outputs_res != transparent_output_sum) {
                return util::Error{_("Transparent output total amount out of range.")};
            }
            if (uses_transparent_change) {
                CTxOut change_output(transparent_change_value, selected_change_script);
                if (IsDust(change_output, wallet.chain().relayDustFee())) {
                    return util::Error{_("Private shielding transparent change amount is dust.")};
                }
                const unsigned int change_pos_out = rng_fast.randrange(txNew.vout.size() + 1);
                txNew.vout.insert(txNew.vout.begin() + change_pos_out, std::move(change_output));
            }

            CMutableTransaction tx_without_private{txNew};
            const auto estimate_start{SteadyClock::now()};
            int64_t estimated_private_delta{0};
            auto estimated_size_res = EstimateSignedTransparentPrivateTransactionSize(
                tx_without_private,
                wallet,
                coin_control,
                action_count,
                private_root,
                /*value_balance=*/0,
                estimated_private_delta);
            if (!estimated_size_res) {
                return util::Error{util::ErrorString(estimated_size_res)};
            }
            const TxSize estimated_size{*estimated_size_res};
            estimate_ms += Ticks<std::chrono::milliseconds>(SteadyClock::now() - estimate_start);

            const CAmount fee_needed = fee_rate.GetFee(estimated_size.vsize) + result.GetTotalBumpFees();
            const CAmount actual_fee = selected_value - spend_target_sum - (uses_transparent_change ? transparent_change_value : 0);
            if (actual_fee < fee_needed) {
                fee = fee_needed;
                continue;
            }

            auto sighash_callback = [&txNew](const CPrivateBundle& effects_bundle, uint256& sighash_out, std::string& error) {
                CMutableTransaction sighash_tx{txNew};
                sighash_tx.m_private_bundle = effects_bundle;
                sighash_out = PrivateBundleSighash(sighash_tx);
                error.clear();
                return true;
            };

            CPrivateBundle bundle;
            std::string private_error;
            const auto proof_start{SteadyClock::now()};
            auto build_result = BuildPrivateOrchardBundleWithSighashCallback(
                Span<const PrivateOrchardSpendInfo>{},
                Span<const PrivateOrchardOutputInfo>{output_infos},
                private_root,
                sighash_callback,
                bundle,
                private_error);
            proof_ms += Ticks<std::chrono::milliseconds>(SteadyClock::now() - proof_start);
            if (build_result != PrivateOrchardBuildResult::OK) {
                return util::Error{Untranslated(private_error.empty() ? "failed to build private shielding Orchard bundle" : private_error)};
            }

            std::string weight_error;
            if (!CheckPrivateWeightEstimate(tx_without_private, bundle, action_count, estimated_private_delta, weight_error)) {
                return util::Error{Untranslated(weight_error)};
            }

            txNew.m_private_bundle = std::move(bundle);
            if (!sign) {
                for (CTxIn& txin : txNew.vin) {
                    txin.scriptSig.clear();
                    txin.scriptWitness.SetNull();
                }
            }

            if (sign) {
                const auto sign_start{SteadyClock::now()};
                if (!wallet.SignTransaction(txNew)) {
                    return util::Error{_("Signing transaction failed")};
                }
                sign_ms += Ticks<std::chrono::milliseconds>(SteadyClock::now() - sign_start);
            }

            CTransactionRef tx = MakeTransactionRef(txNew);

            const auto verify_start{SteadyClock::now()};
            std::string verify_error;
            if (VerifyPrivateOrchardBundle(*tx, verify_error) != PrivateOrchardVerifyResult::OK) {
                return util::Error{Untranslated(verify_error.empty() ? "private Orchard bundle verification failed" : verify_error)};
            }
            verify_ms += Ticks<std::chrono::milliseconds>(SteadyClock::now() - verify_start);

            const int64_t tx_weight = sign ? static_cast<int64_t>(GetTransactionWeight(*tx)) : estimated_size.weight;
            const int64_t tx_vsize = sign ? static_cast<int64_t>(GetVirtualTransactionSize(*tx)) : estimated_size.vsize;
            if (tx_vsize > estimated_size.vsize) {
                return util::Error{Untranslated(strprintf("private shielding vsize estimate mismatch: estimated=%d actual=%d", estimated_size.vsize, tx_vsize))};
            }

            if (tx_weight > MAX_STANDARD_TX_WEIGHT) {
                return util::Error{_("Transaction too large")};
            }
            if (actual_fee > wallet.m_default_max_tx_fee) {
                return util::Error{TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED)};
            }
            if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
                auto chain_limit = wallet.chain().checkChainLimits(tx);
                if (!chain_limit) {
                    return util::Error{util::ErrorString(chain_limit)};
                }
            }

            final_tx = tx;
            final_fee = actual_fee;
            final_estimated_vsize = estimated_size.vsize;
            final_actual_vsize = tx_vsize;
            final_attempt = attempt + 1;
            final_uses_transparent_change = uses_transparent_change;

            wallet.WalletLogPrintf("Private Coin Selection: Source:transparent Algorithm:%s Waste:%d Fee:%d VSize:%u EstimateVSize:%u Attempts:%d SelectMs:%d EstimateMs:%d ProofMs:%d SignMs:%d VerifyMs:%d BuildMs:%d\n",
                GetAlgorithmName(result.GetAlgo()),
                result.GetWaste(),
                actual_fee,
                static_cast<unsigned>(final_actual_vsize),
                static_cast<unsigned>(final_estimated_vsize),
                final_attempt,
                select_ms,
                estimate_ms,
                proof_ms,
                sign_ms,
                verify_ms,
                Ticks<std::chrono::milliseconds>(SteadyClock::now() - private_build_start));

            break;
        }

        if (!final_tx) {
            return util::Error{_("Unable to converge Nito.network transparent-to-private transaction fee calculation.")};
        }
        if (final_uses_transparent_change) {
            reservedest.KeepDestination();
        }
        return CreatedTransactionResult(final_tx, final_fee, std::nullopt, feeCalc);
    };

    switch (coin_control.m_private_tx_source) {
    case CCoinControl::PrivateTxSource::TRANSPARENT_COINS:
        return build_from_transparent_coins();
    case CCoinControl::PrivateTxSource::PRIVATE_NOTES:
        return build_from_private_notes();
    case CCoinControl::PrivateTxSource::AUTO:
        if (has_private_recipient) {
            return build_from_transparent_coins();
        }
        return build_from_private_notes();
    }

    return util::Error{_("Invalid Nito.network private transaction source.")};
}
} // namespace

static util::Result<CreatedTransactionResult> CreateTransactionInternal(
        CWallet& wallet,
        const std::vector<CRecipient>& vecSend,
        std::optional<unsigned int> change_pos,
        const CCoinControl& coin_control,
        bool sign) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    const bool has_private_recipient = std::any_of(vecSend.begin(), vecSend.end(), [](const CRecipient& recipient) {
        return recipient.IsPrivate();
    });
    if (has_private_recipient || coin_control.m_private_tx_source != CCoinControl::PrivateTxSource::AUTO) {
        if (!wallet.HaveChain() || !wallet.chain().hasOrchardIndex()) {
            return util::Error{_("The private wallet index is not available. Restart Nito Core with private wallet indexing enabled (-orchardindex=1) before using Bech32x wallet features.")};
        }
        wallet.RefreshPrivateCommitmentIndexes();
        return CreatePrivateTransactionInternal(wallet, vecSend, change_pos, coin_control, sign);
    }

    FastRandomContext rng_fast;
    CMutableTransaction txNew; // The resulting transaction that we make

    if (coin_control.m_version) {
        txNew.nVersion = coin_control.m_version.value();
    }

    CoinSelectionParams coin_selection_params{rng_fast}; // Parameters for coin selection, init with dummy
    coin_selection_params.m_avoid_partial_spends = coin_control.m_avoid_partial_spends;
    coin_selection_params.m_include_unsafe_inputs = coin_control.m_include_unsafe_inputs;

    // Set the long term feerate estimate to the wallet's consolidate feerate
    coin_selection_params.m_long_term_feerate = wallet.m_consolidate_feerate;

    CAmount recipients_sum = 0;
    const OutputType change_type = wallet.TransactionChangeType(coin_control.m_change_type ? *coin_control.m_change_type : wallet.m_default_change_type, vecSend);
    ReserveDestination reservedest(&wallet, change_type);
    unsigned int outputs_to_subtract_fee_from = 0; // The number of outputs which we are subtracting the fee from
    for (const auto& recipient : vecSend) {
        recipients_sum += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount) {
            outputs_to_subtract_fee_from++;
            coin_selection_params.m_subtract_fee_outputs = true;
        }
    }

    // Create change script that will be used if we need change
    CScript scriptChange;
    bool use_source_change{false};
    bool change_key_unavailable{false};

    // Internal coin control may still force a change destination for replacement
    // transactions. Normal wallet sends reserve a fresh internal destination.
    if (!std::get_if<CNoDestination>(&coin_control.destChange)) {
        scriptChange = GetScriptForDestination(coin_control.destChange);
    } else { // no coin control: send change to newly generated address
        CTxDestination dest;
        auto op_dest = reservedest.GetReservedDestination(/*internal=*/true);
        if (!op_dest) {
            // Keep the source-return fallback for imported/watch-only wallets,
            // without overriding an explicit type or exhausting an HD keypool.
            change_key_unavailable = !CanUseSourceChange(wallet, coin_control, change_type);
            use_source_change = !change_key_unavailable;
        } else {
            dest = *op_dest;
            scriptChange = GetScriptForDestination(dest);
        }
        CHECK_NONFATAL(IsValidDestination(dest) != scriptChange.empty());
        if (use_source_change || change_key_unavailable) {
            scriptChange = BuildTransparentChangeSizingScript();
        }
    }

    // Set discard feerate
    coin_selection_params.m_discard_feerate = GetDiscardRate(wallet);

    // Get the fee rate to use effective values in coin selection
    FeeCalculation feeCalc;
    coin_selection_params.m_effective_feerate = GetMinimumFeeRate(wallet, coin_control, &feeCalc);
    // Do not, ever, assume that it's fine to change the fee rate if the user has explicitly
    // provided one
    if (coin_control.m_feerate && coin_selection_params.m_effective_feerate > *coin_control.m_feerate) {
        return util::Error{strprintf(_("Fee rate (%s) is lower than the minimum fee rate setting (%s)"), coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), coin_selection_params.m_effective_feerate.ToString(FeeEstimateMode::SAT_VB))};
    }
    if (feeCalc.reason == FeeReason::FALLBACK && !wallet.m_allow_fallback_fee) {
        // eventually allow a fallback fee
        return util::Error{strprintf(_("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable %s."), "-fallbackfee")};
    }

    SetTransparentChangeSizing(wallet, coin_selection_params, scriptChange);

    coin_selection_params.m_min_change_target = GenerateChangeTarget(std::floor(recipients_sum / vecSend.size()), coin_selection_params.m_change_fee, rng_fast);

    // Static vsize overhead + outputs vsize. 4 nVersion, 4 nLocktime, 1 input count, 1 witness overhead (dummy, flag, stack size)
    coin_selection_params.tx_noinputs_size = 10 + GetSizeOfCompactSize(vecSend.size()); // bytes for output count

    // vouts to the payees
    for (const auto& recipient : vecSend)
    {
        CTxOut txout(recipient.nAmount, GetScriptForDestination(recipient.dest));

        // Include the fee cost for outputs.
        coin_selection_params.tx_noinputs_size += ::GetSerializeSize(txout);

        if (IsDust(txout, wallet.chain().relayDustFee())) {
            return util::Error{_("Transaction amount too small")};
        }
        txNew.vout.push_back(txout);
    }

    // Include the fees for things that aren't inputs, excluding the change output
    const CAmount not_input_fees = coin_selection_params.m_effective_feerate.GetFee(coin_selection_params.m_subtract_fee_outputs ? 0 : coin_selection_params.tx_noinputs_size);
    CAmount selection_target = recipients_sum + not_input_fees;

    // This can only happen if feerate is 0, and requested destinations are value of 0 (e.g. OP_RETURN)
    // and no pre-selected inputs. This will result in 0-input transaction, which is consensus-invalid anyways
    if (selection_target == 0 && !coin_control.HasSelected()) {
        return util::Error{_("Transaction requires one destination of non-0 value, a non-0 feerate, or a pre-selected input")};
    }

    // Fetch manually selected coins
    PreSelectedInputs preset_inputs;
    if (coin_control.HasSelected()) {
        auto res_fetch_inputs = FetchSelectedInputs(wallet, coin_control, coin_selection_params);
        if (!res_fetch_inputs) return util::Error{util::ErrorString(res_fetch_inputs)};
        preset_inputs = *res_fetch_inputs;
    }

    // Fetch wallet available coins if "other inputs" are
    // allowed (coins automatically selected by the wallet)
    CoinsResult available_coins;
    if (coin_control.m_allow_other_inputs) {
        available_coins = AvailableCoins(wallet, &coin_control, coin_selection_params.m_effective_feerate);
    }

    // Choose coins to use
    auto select_coins_res = SelectCoins(wallet, available_coins, preset_inputs, /*nTargetValue=*/selection_target, coin_control, coin_selection_params);
    if (!select_coins_res) {
        // 'SelectCoins' either returns a specific error message or, if empty, means a general "Insufficient funds".
        const bilingual_str& err = util::ErrorString(select_coins_res);
        return util::Error{err.empty() ?_("Insufficient funds") : err};
    }
    const SelectionResult& result = *select_coins_res;
    TRACE5(coin_selection, selected_coins,
           wallet.GetName().c_str(),
           GetAlgorithmName(result.GetAlgo()).c_str(),
           result.GetTarget(),
           result.GetWaste(),
           result.GetSelectedValue());

    if (use_source_change) {
        auto change_dest_res = GetDominantTransparentChangeDestination(wallet, result);
        if (!change_dest_res) return util::Error{util::ErrorString(change_dest_res)};
        scriptChange = GetScriptForDestination(*change_dest_res);
        SetTransparentChangeSizing(wallet, coin_selection_params, scriptChange);
    }

    const CAmount change_amount = result.GetChange(coin_selection_params.min_viable_change, coin_selection_params.m_change_fee);
    if (change_amount > 0) {
        if (change_key_unavailable) {
            return util::Error{_("Transaction needs a change address, but we can't generate it.")};
        }
        CTxOut newTxOut(change_amount, scriptChange);
        if (!change_pos) {
            // Insert change txn at random position:
            change_pos = rng_fast.randrange(txNew.vout.size() + 1);
        } else if ((unsigned int)*change_pos > txNew.vout.size()) {
            return util::Error{_("Transaction change output index out of range")};
        }
        txNew.vout.insert(txNew.vout.begin() + *change_pos, newTxOut);
    } else {
        change_pos = std::nullopt;
    }

    // Shuffle selected coins and fill in final vin
    std::vector<std::shared_ptr<COutput>> selected_coins = result.GetShuffledInputVector();

    if (coin_control.HasSelected() && coin_control.HasSelectedOrder()) {
        // When there are preselected inputs, we need to move them to be the first UTXOs
        // and have them be in the order selected. We can use stable_sort for this, where we
        // compare with the positions stored in coin_control. The COutputs that have positions
        // will be placed before those that don't, and those positions will be in order.
        std::stable_sort(selected_coins.begin(), selected_coins.end(),
            [&coin_control](const std::shared_ptr<COutput>& a, const std::shared_ptr<COutput>& b) {
                auto a_pos = coin_control.GetSelectionPos(a->outpoint);
                auto b_pos = coin_control.GetSelectionPos(b->outpoint);
                if (a_pos.has_value() && b_pos.has_value()) {
                    return a_pos.value() < b_pos.value();
                } else if (a_pos.has_value() && !b_pos.has_value()) {
                    return true;
                } else {
                    return false;
                }
            });
    }

    // The sequence number is set to non-maxint so that DiscourageFeeSniping
    // works.
    //
    // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
    // we use the highest possible value in that range (maxint-2)
    // to avoid conflicting with other possible uses of nSequence,
    // and in the spirit of "smallest possible change from prior
    // behavior."
    bool use_anti_fee_sniping = true;
    const uint32_t default_sequence{coin_control.m_signal_bip125_rbf.value_or(wallet.m_signal_rbf) ? MAX_BIP125_RBF_SEQUENCE : CTxIn::MAX_SEQUENCE_NONFINAL};
    for (const auto& coin : selected_coins) {
        std::optional<uint32_t> sequence = coin_control.GetSequence(coin->outpoint);
        if (sequence) {
            // If an input has a preset sequence, we can't do anti-fee-sniping
            use_anti_fee_sniping = false;
        }
        txNew.vin.emplace_back(coin->outpoint, CScript{}, sequence.value_or(default_sequence));

        auto scripts = coin_control.GetScripts(coin->outpoint);
        if (scripts.first) {
            txNew.vin.back().scriptSig = *scripts.first;
        }
        if (scripts.second) {
            txNew.vin.back().scriptWitness = *scripts.second;
        }
    }
    if (coin_control.m_locktime) {
        txNew.nLockTime = coin_control.m_locktime.value();
        // If we have a locktime set, we can't use anti-fee-sniping
        use_anti_fee_sniping = false;
    }
    if (use_anti_fee_sniping) {
        DiscourageFeeSniping(txNew, rng_fast, wallet.chain(), wallet.GetLastBlockHash(), wallet.GetLastBlockHeight());
    }

    // Calculate the transaction fee
    TxSize tx_sizes = CalculateMaximumSignedTxSize(CTransaction(txNew), &wallet, &coin_control);
    int nBytes = tx_sizes.vsize;
    if (nBytes == -1) {
        return util::Error{_("Missing solving data for estimating transaction size")};
    }
    CAmount fee_needed = coin_selection_params.m_effective_feerate.GetFee(nBytes) + result.GetTotalBumpFees();
    const CAmount output_value = CalculateOutputValue(txNew);
    Assume(recipients_sum + change_amount == output_value);
    CAmount current_fee = result.GetSelectedValue() - output_value;

    // Sanity check that the fee cannot be negative as that means we have more output value than input value
    if (current_fee < 0) {
        return util::Error{Untranslated(STR_INTERNAL_BUG("Fee paid < 0"))};
    }

    // If there is a change output and we overpay the fees then increase the change to match the fee needed
    if (change_pos && fee_needed < current_fee) {
        auto& change = txNew.vout.at(*change_pos);
        change.nValue += current_fee - fee_needed;
        current_fee = result.GetSelectedValue() - CalculateOutputValue(txNew);
        if (fee_needed != current_fee) {
            return util::Error{Untranslated(STR_INTERNAL_BUG("Change adjustment: Fee needed != fee paid"))};
        }
    }

    // Reduce output values for subtractFeeFromAmount
    if (coin_selection_params.m_subtract_fee_outputs) {
        CAmount to_reduce = fee_needed - current_fee;
        unsigned int i = 0;
        bool fFirst = true;
        for (const auto& recipient : vecSend)
        {
            if (change_pos && i == *change_pos) {
                ++i;
            }
            CTxOut& txout = txNew.vout[i];

            if (recipient.fSubtractFeeFromAmount)
            {
                txout.nValue -= to_reduce / outputs_to_subtract_fee_from; // Subtract fee equally from each selected recipient

                if (fFirst) // first receiver pays the remainder not divisible by output count
                {
                    fFirst = false;
                    txout.nValue -= to_reduce % outputs_to_subtract_fee_from;
                }

                // Error if this output is reduced to be below dust
                if (IsDust(txout, wallet.chain().relayDustFee())) {
                    if (txout.nValue < 0) {
                        return util::Error{_("The transaction amount is too small to pay the fee")};
                    } else {
                        return util::Error{_("The transaction amount is too small to send after the fee has been deducted")};
                    }
                }
            }
            ++i;
        }
        current_fee = result.GetSelectedValue() - CalculateOutputValue(txNew);
        if (fee_needed != current_fee) {
            return util::Error{Untranslated(STR_INTERNAL_BUG("SFFO: Fee needed != fee paid"))};
        }
    }

    // fee_needed should now always be less than or equal to the current fees that we pay.
    // If it is not, it is a bug.
    if (fee_needed > current_fee) {
        return util::Error{Untranslated(STR_INTERNAL_BUG("Fee needed > fee paid"))};
    }

    if (sign && !wallet.SignTransaction(txNew)) {
        return util::Error{_("Signing transaction failed")};
    }

    // Return the constructed transaction data.
    CTransactionRef tx = MakeTransactionRef(std::move(txNew));

    // Limit size
    if ((sign && GetTransactionWeight(*tx) > MAX_STANDARD_TX_WEIGHT) ||
        (!sign && tx_sizes.weight > MAX_STANDARD_TX_WEIGHT))
    {
        return util::Error{_("Transaction too large")};
    }

    if (current_fee > wallet.m_default_max_tx_fee) {
        return util::Error{TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED)};
    }

    if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        auto result = wallet.chain().checkChainLimits(tx);
        if (!result) {
            return util::Error{util::ErrorString(result)};
        }
    }

    if (change_pos) {
        reservedest.KeepDestination();
    }

    wallet.WalletLogPrintf("Coin Selection: Algorithm:%s, Waste Metric Score:%d\n", GetAlgorithmName(result.GetAlgo()), result.GetWaste());
    wallet.WalletLogPrintf("Fee Calculation: Fee:%d Bytes:%u Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
              current_fee, nBytes, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
              feeCalc.est.pass.start, feeCalc.est.pass.end,
              (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool) > 0.0 ? 100 * feeCalc.est.pass.withinTarget / (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool) : 0.0,
              feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed, feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
              feeCalc.est.fail.start, feeCalc.est.fail.end,
              (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool + feeCalc.est.fail.leftMempool) > 0.0 ? 100 * feeCalc.est.fail.withinTarget / (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool + feeCalc.est.fail.leftMempool) : 0.0,
              feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed, feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);
    return CreatedTransactionResult(tx, current_fee, change_pos, feeCalc);
}

util::Result<CreatedTransactionResult> CreateTransaction(
        CWallet& wallet,
        const std::vector<CRecipient>& vecSend,
        std::optional<unsigned int> change_pos,
        const CCoinControl& coin_control,
        bool sign)
{
    if (vecSend.empty()) {
        return util::Error{_("Transaction must have at least one recipient")};
    }

    if (std::any_of(vecSend.cbegin(), vecSend.cend(), [](const auto& recipient){ return recipient.nAmount < 0; })) {
        return util::Error{_("Transaction amounts must not be negative")};
    }

    LOCK(wallet.cs_wallet);
    if (wallet.IsAvailableBalanceSyncPending()) {
        return util::Error{WalletSyncPendingMessage()};
    }

    auto res = CreateTransactionInternal(wallet, vecSend, change_pos, coin_control, sign);
    TRACE4(coin_selection, normal_create_tx_internal,
           wallet.GetName().c_str(),
           bool(res),
           res ? res->fee : 0,
           res && res->change_pos.has_value() ? int32_t(*res->change_pos) : -1);
    if (!res) return res;
    const auto& txr_ungrouped = *res;
    if (txr_ungrouped.tx->HasPrivateBundle()) {
        return res;
    }
    // try with avoidpartialspends unless it's enabled already
    if (txr_ungrouped.fee > 0 /* 0 means non-functional fee rate estimation */ && wallet.m_max_aps_fee > -1 && !coin_control.m_avoid_partial_spends) {
        TRACE1(coin_selection, attempting_aps_create_tx, wallet.GetName().c_str());
        CCoinControl tmp_cc = coin_control;
        tmp_cc.m_avoid_partial_spends = true;

        // Reuse the change destination from the first creation attempt to avoid skipping BIP44 indexes
        if (txr_ungrouped.change_pos) {
            ExtractDestination(txr_ungrouped.tx->vout[*txr_ungrouped.change_pos].scriptPubKey, tmp_cc.destChange);
        }

        auto txr_grouped = CreateTransactionInternal(wallet, vecSend, change_pos, tmp_cc, sign);
        // if fee of this alternative one is within the range of the max fee, we use this one
        const bool use_aps{txr_grouped.has_value() ? (txr_grouped->fee <= txr_ungrouped.fee + wallet.m_max_aps_fee) : false};
        TRACE5(coin_selection, aps_create_tx_internal,
               wallet.GetName().c_str(),
               use_aps,
               txr_grouped.has_value(),
               txr_grouped.has_value() ? txr_grouped->fee : 0,
               txr_grouped.has_value() && txr_grouped->change_pos.has_value() ? int32_t(*txr_grouped->change_pos) : -1);
        if (txr_grouped) {
            wallet.WalletLogPrintf("Fee non-grouped = %lld, grouped = %lld, using %s\n",
                txr_ungrouped.fee, txr_grouped->fee, use_aps ? "grouped" : "non-grouped");
            if (use_aps) return txr_grouped;
        }
    }
    return res;
}

util::Result<CreatedTransactionResult> FundTransaction(CWallet& wallet, const CMutableTransaction& tx, const std::vector<CRecipient>& vecSend, std::optional<unsigned int> change_pos, bool lockUnspents, CCoinControl coinControl, bool sign)
{
    // We want to make sure tx.vout is not used now that we are passing outputs as a vector of recipients.
    // This sets us up to remove tx completely in a future PR in favor of passing the inputs directly.
    assert(tx.vout.empty());

    // Set the user desired locktime
    coinControl.m_locktime = tx.nLockTime;

    // Set the user desired version
    coinControl.m_version = tx.nVersion;
    if (sign &&
        coinControl.m_private_tx_source == CCoinControl::PrivateTxSource::PRIVATE_NOTES &&
        tx.nVersion == CTransaction::CURRENT_VERSION) {
        coinControl.m_version.reset();
    }

    // Acquire the locks to prevent races to the new locked unspents between the
    // CreateTransaction call and LockCoin calls (when lockUnspents is true).
    LOCK(wallet.cs_wallet);

    // Fetch specified UTXOs from the UTXO set to get the scriptPubKeys and values of the outputs being selected
    // and to match with the given solving_data. Only used for non-wallet outputs.
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : tx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    wallet.chain().findCoins(coins);

    for (const CTxIn& txin : tx.vin) {
        const auto& outPoint = txin.prevout;
        PreselectedInput& preset_txin = coinControl.Select(outPoint);
        if (!wallet.IsMine(outPoint)) {
            if (coins[outPoint].out.IsNull()) {
                return util::Error{_("Unable to find UTXO for external input")};
            }

            // The input was not in the wallet, but is in the UTXO set, so select as external
            preset_txin.SetTxOut(coins[outPoint].out);
        }
        preset_txin.SetSequence(txin.nSequence);
        preset_txin.SetScriptSig(txin.scriptSig);
        preset_txin.SetScriptWitness(txin.scriptWitness);
    }

    auto res = CreateTransaction(wallet, vecSend, change_pos, coinControl, sign);
    if (!res) {
        return res;
    }

    if (lockUnspents) {
        for (const CTxIn& txin : res->tx->vin) {
            wallet.LockCoin(txin.prevout);
        }
    }

    return res;
}
} // namespace wallet
