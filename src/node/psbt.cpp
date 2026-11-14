// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/tx_verify.h>
#include <node/psbt.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <tinyformat.h>

#include <ios>
#include <numeric>

namespace node {
PSBTAnalysis AnalyzePSBT(PartiallySignedTransaction psbtx)
{
    // Go through each input and build status
    PSBTAnalysis result;
    try {
        psbtx.ApplyNitoPrivateAuthProprietary();
    } catch (const std::ios_base::failure& e) {
        result.SetInvalid(strprintf("PSBT is not valid. %s", e.what()));
        return result;
    }
    NitoPrivatePSBTSigningData private_signing_data;
    try {
        private_signing_data = psbtx.GetNitoPrivateSigningData();
    } catch (const std::ios_base::failure& e) {
        result.SetInvalid(strprintf("PSBT is not valid. %s", e.what()));
        return result;
    }
    if (private_signing_data.HasAny() && psbtx.tx->HasPrivateAuth()) {
        result.SetInvalid("PSBT is not valid. Nito Orchard signing material is mixed with private authorization");
        return result;
    }

    bool calc_fee = true;

    CAmount in_amt = 0;

    result.inputs.resize(psbtx.tx->vin.size());

    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);

    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& input = psbtx.inputs[i];
        PSBTInputAnalysis& input_analysis = result.inputs[i];

        // We set next role here and ratchet backwards as required
        input_analysis.next = PSBTRole::EXTRACTOR;

        // Check for a UTXO
        CTxOut utxo;
        if (psbtx.GetInputUTXO(utxo, i)) {
            if (!MoneyRange(utxo.nValue) || !MoneyRange(in_amt + utxo.nValue)) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u has invalid value", i));
                return result;
            }
            in_amt += utxo.nValue;
            input_analysis.has_utxo = true;
        } else {
            if (input.non_witness_utxo && psbtx.tx->vin[i].prevout.n >= input.non_witness_utxo->vout.size()) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u specifies invalid prevout", i));
                return result;
            }
            input_analysis.has_utxo = false;
            input_analysis.is_final = false;
            input_analysis.next = PSBTRole::UPDATER;
            calc_fee = false;
        }

        if (!utxo.IsNull() && utxo.scriptPubKey.IsUnspendable()) {
            result.SetInvalid(strprintf("PSBT is not valid. Input %u spends unspendable output", i));
            return result;
        }

        // Check if it is final
        if (!PSBTInputSignedAndVerified(psbtx, i, &txdata)) {
            input_analysis.is_final = false;

            // Figure out what is missing
            SignatureData outdata;
            bool complete = SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, 1, &outdata);

            // Things are missing
            if (!complete) {
                input_analysis.missing_pubkeys = outdata.missing_pubkeys;
                input_analysis.missing_redeem_script = outdata.missing_redeem_script;
                input_analysis.missing_witness_script = outdata.missing_witness_script;
                input_analysis.missing_sigs = outdata.missing_sigs;

                // If we are only missing signatures and nothing else, then next is signer
                if (outdata.missing_pubkeys.empty() && outdata.missing_redeem_script.IsNull() && outdata.missing_witness_script.IsNull() && !outdata.missing_sigs.empty()) {
                    input_analysis.next = PSBTRole::SIGNER;
                } else {
                    input_analysis.next = PSBTRole::UPDATER;
                }
            } else {
                input_analysis.next = PSBTRole::FINALIZER;
            }
        } else if (!utxo.IsNull()){
            input_analysis.is_final = true;
        }
    }

    // Calculate next role for PSBT by grabbing "minimum" PSBTInput next role
    result.next = PSBTRole::EXTRACTOR;
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInputAnalysis& input_analysis = result.inputs[i];
        result.next = std::min(result.next, input_analysis.next);
    }
    if (private_signing_data.HasAny()) {
        result.next = std::min(result.next, PSBTRole::SIGNER);
    }
    assert(result.next > PSBTRole::CREATOR);

    if (calc_fee) {
        // Get the output amount
        CAmount out_amt = std::accumulate(psbtx.tx->vout.begin(), psbtx.tx->vout.end(), CAmount(0),
            [](CAmount a, const CTxOut& b) {
                if (!MoneyRange(a) || !MoneyRange(b.nValue) || !MoneyRange(a + b.nValue)) {
                    return CAmount(-1);
                }
                return a += b.nValue;
            }
        );
        if (!MoneyRange(out_amt)) {
            result.SetInvalid("PSBT is not valid. Output amount invalid");
            return result;
        }

        // Get the fee. Private bundles carry their shielded value balance as
        // txid data, so account for it the same way consensus validation does.
        CAmount value_in_effective = in_amt;
        CAmount private_value_balance{0};
        if (private_signing_data.plan) {
            private_value_balance = private_signing_data.plan->value_balance;
            if (psbtx.tx->HasPrivateBundle() && psbtx.tx->m_private_bundle->GetValueBalance() != private_value_balance) {
                result.SetInvalid("PSBT is not valid. Private signing plan value balance mismatch");
                return result;
            }
        } else if (psbtx.tx->HasPrivateBundle()) {
            private_value_balance = psbtx.tx->m_private_bundle->GetValueBalance();
        }
        if (!MoneyAddSigned(value_in_effective, private_value_balance, value_in_effective)) {
            result.SetInvalid("PSBT is not valid. Private value balance overflow");
            return result;
        }
        CAmount fee = value_in_effective - out_amt;
        result.fee = fee;

        // Estimate the size
        CMutableTransaction mtx(*psbtx.tx);
        CCoinsView view_dummy;
        CCoinsViewCache view(&view_dummy);
        bool success = !private_signing_data.HasAny();

        for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
            PSBTInput& input = psbtx.inputs[i];
            Coin newcoin;

            if (!SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, nullptr, 1) || !psbtx.GetInputUTXO(newcoin.out, i)) {
                success = false;
                break;
            } else {
                mtx.vin[i].scriptSig = input.final_script_sig;
                mtx.vin[i].scriptWitness = input.final_script_witness;
                newcoin.nHeight = 1;
                view.AddCoin(psbtx.tx->vin[i].prevout, std::move(newcoin), true);
            }
        }

        if (success) {
            CTransaction ctx = CTransaction(mtx);
            size_t size(GetVirtualTransactionSize(ctx, GetTransactionSigOpCost(ctx, view, STANDARD_SCRIPT_VERIFY_FLAGS), ::nBytesPerSigOp));
            result.estimated_vsize = size;
            // Estimate fee rate
            CFeeRate feerate(fee, size);
            result.estimated_feerate = feerate;
        }

    }

    return result;
}
} // namespace node
