// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <hash.h>
#include <private/orchard_verifier.h>
#include <policy/policy.h>
#include <script/signingprovider.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <algorithm>
#include <ios>
#include <map>

namespace {
bool IsNitoPrivateKnownProprietarySubtype(uint64_t subtype)
{
    return subtype == PSBT_NITO_GLOBAL_RESERVED_LEGACY_PRIVATE_AUTH ||
        subtype == PSBT_NITO_GLOBAL_ORCHARD_ACTION_AUTH_V1 ||
        subtype == PSBT_NITO_GLOBAL_ORCHARD_BUNDLE_AUTH_V1 ||
        subtype == PSBT_NITO_GLOBAL_ORCHARD_SPEND_MATERIAL_V1 ||
        subtype == PSBT_NITO_GLOBAL_ORCHARD_OUTPUT_MATERIAL_V1 ||
        subtype == PSBT_NITO_GLOBAL_ORCHARD_BUNDLE_PLAN_V1;
}

bool IsNitoPrivateAuthProprietarySubtype(uint64_t subtype)
{
    return subtype == PSBT_NITO_GLOBAL_ORCHARD_ACTION_AUTH_V1 ||
        subtype == PSBT_NITO_GLOBAL_ORCHARD_BUNDLE_AUTH_V1;
}

bool IsNitoPrivateAuthOrReservedProprietarySubtype(uint64_t subtype)
{
    return subtype == PSBT_NITO_GLOBAL_RESERVED_LEGACY_PRIVATE_AUTH ||
        IsNitoPrivateAuthProprietarySubtype(subtype);
}

bool IsNitoPrivateSigningMaterialProprietarySubtype(uint64_t subtype)
{
    return subtype == PSBT_NITO_GLOBAL_ORCHARD_SPEND_MATERIAL_V1 ||
        subtype == PSBT_NITO_GLOBAL_ORCHARD_OUTPUT_MATERIAL_V1 ||
        subtype == PSBT_NITO_GLOBAL_ORCHARD_BUNDLE_PLAN_V1;
}

DataStream ParseNitoProprietaryKeyData(const PSBTProprietary& entry)
{
    DataStream ss_key{MakeByteSpan(entry.key)};
    const uint64_t type = ReadCompactSize(ss_key);
    if (type != PSBT_GLOBAL_PROPRIETARY) {
        throw std::ios_base::failure("Nito proprietary key has unexpected map type");
    }
    std::vector<unsigned char> identifier;
    ss_key >> identifier;
    if (identifier != NitoPSBTProprietaryIdentifier()) {
        throw std::ios_base::failure("Nito proprietary key has unexpected identifier");
    }
    const uint64_t subtype = ReadCompactSize(ss_key);
    if (subtype != entry.subtype) {
        throw std::ios_base::failure("Nito proprietary key subtype mismatch");
    }
    return ss_key;
}
} // namespace

PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx) : tx(tx)
{
    inputs.resize(tx.vin.size());
    outputs.resize(tx.vout.size());
    if (tx.HasPrivateAuth()) {
        const CPrivateAuth& auth = *tx.m_private_bundle->auth;
        m_proprietary.insert(MakeNitoPSBTOrchardBundleAuthProprietary(auth.BundleAuth()));
        for (uint64_t i = 0; i < auth.actions_auth.size(); ++i) {
            m_proprietary.insert(MakeNitoPSBTOrchardActionAuthProprietary(i, auth.actions_auth[i]));
        }
    }
}

bool PartiallySignedTransaction::IsNull() const
{
    return !tx && inputs.empty() && outputs.empty() && unknown.empty();
}

bool PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psbt)
{
    // Prohibited to merge two PSBTs over different transactions
    if (tx->GetHash() != psbt.tx->GetHash()) {
        return false;
    }

    for (unsigned int i = 0; i < inputs.size(); ++i) {
        inputs[i].Merge(psbt.inputs[i]);
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        outputs[i].Merge(psbt.outputs[i]);
    }
    for (auto& xpub_pair : psbt.m_xpubs) {
        if (m_xpubs.count(xpub_pair.first) == 0) {
            m_xpubs[xpub_pair.first] = xpub_pair.second;
        } else {
            m_xpubs[xpub_pair.first].insert(xpub_pair.second.begin(), xpub_pair.second.end());
        }
    }
    unknown.insert(psbt.unknown.begin(), psbt.unknown.end());
    for (const auto& entry : psbt.m_proprietary) {
        auto [it, inserted] = m_proprietary.insert(entry);
        if (!inserted &&
            entry.identifier == NitoPSBTProprietaryIdentifier() &&
            IsNitoPrivateKnownProprietarySubtype(entry.subtype) &&
            it->value != entry.value) {
            return false;
        }
    }
    ApplyNitoPrivateAuthProprietary();

    return true;
}

void PartiallySignedTransaction::ApplyNitoPrivateAuthProprietary()
{
    const bool has_reserved_legacy_auth_record = std::any_of(m_proprietary.begin(), m_proprietary.end(), [](const PSBTProprietary& entry) {
        return entry.identifier == NitoPSBTProprietaryIdentifier() && entry.subtype == PSBT_NITO_GLOBAL_RESERVED_LEGACY_PRIVATE_AUTH;
    });
    if (has_reserved_legacy_auth_record) {
        throw std::ios_base::failure("Unsupported legacy Nito private authorization record");
    }

    const bool has_private_auth_record = std::any_of(m_proprietary.begin(), m_proprietary.end(), [](const PSBTProprietary& entry) {
        return entry.identifier == NitoPSBTProprietaryIdentifier() && IsNitoPrivateAuthProprietarySubtype(entry.subtype);
    });
    if (!tx || !tx->m_private_bundle) {
        if (has_private_auth_record) {
            throw std::ios_base::failure("Nito private authorization without private effects");
        }
        return;
    }

    bool found_bundle_auth{false};
    CPrivateBundleAuth bundle_auth;
    std::map<uint64_t, CPrivateActionAuth> action_auths;

    for (const auto& entry : m_proprietary) {
        if (entry.identifier != NitoPSBTProprietaryIdentifier()) continue;
        if (!IsNitoPrivateAuthOrReservedProprietarySubtype(entry.subtype)) {
            continue;
        }
        DataStream ss_key = ParseNitoProprietaryKeyData(entry);
        if (entry.subtype == PSBT_NITO_GLOBAL_ORCHARD_BUNDLE_AUTH_V1) {
            if (!ss_key.empty()) {
                throw std::ios_base::failure("Nito Orchard bundle authorization has unsupported key data");
            }
            if (found_bundle_auth) {
                throw std::ios_base::failure("Duplicate Nito Orchard bundle authorization");
            }
            DataStream ss_auth{MakeByteSpan(entry.value)};
            ss_auth >> bundle_auth;
            if (!ss_auth.empty()) {
                throw std::ios_base::failure("Nito Orchard bundle authorization has trailing data");
            }
            found_bundle_auth = true;
        } else if (entry.subtype == PSBT_NITO_GLOBAL_ORCHARD_ACTION_AUTH_V1) {
            const uint64_t action_index = ReadCompactSize(ss_key);
            if (!ss_key.empty()) {
                throw std::ios_base::failure("Nito Orchard action authorization has unsupported key data");
            }
            if (action_index >= tx->m_private_bundle->effects.actions.size()) {
                throw std::ios_base::failure("Nito Orchard action authorization index out of range");
            }
            CPrivateActionAuth action_auth;
            DataStream ss_auth{MakeByteSpan(entry.value)};
            ss_auth >> action_auth;
            if (!ss_auth.empty()) {
                throw std::ios_base::failure("Nito Orchard action authorization has trailing data");
            }
            if (!action_auths.emplace(action_index, std::move(action_auth)).second) {
                throw std::ios_base::failure("Duplicate Nito Orchard action authorization");
            }
        }
    }

    if (!found_bundle_auth && action_auths.empty()) return;

    if (!found_bundle_auth || action_auths.size() != tx->m_private_bundle->effects.actions.size()) {
        tx->m_private_bundle->auth.reset();
        return;
    }

    CPrivateAuth auth;
    auth.proof = std::move(bundle_auth.proof);
    auth.binding_sig = std::move(bundle_auth.binding_sig);
    auth.actions_auth.resize(tx->m_private_bundle->effects.actions.size());
    for (size_t i = 0; i < auth.actions_auth.size(); ++i) {
        auto it = action_auths.find(i);
        if (it == action_auths.end()) {
            tx->m_private_bundle->auth.reset();
            return;
        }
        auth.actions_auth[i] = std::move(it->second);
    }
    tx->m_private_bundle->auth = std::move(auth);
}

NitoPrivatePSBTSigningData PartiallySignedTransaction::GetNitoPrivateSigningData() const
{
    NitoPrivatePSBTSigningData data;

    for (const auto& entry : m_proprietary) {
        if (entry.identifier != NitoPSBTProprietaryIdentifier()) continue;
        if (!IsNitoPrivateSigningMaterialProprietarySubtype(entry.subtype)) continue;

        DataStream ss_key = ParseNitoProprietaryKeyData(entry);
        if (entry.subtype == PSBT_NITO_GLOBAL_ORCHARD_BUNDLE_PLAN_V1) {
            if (!ss_key.empty()) {
                throw std::ios_base::failure("Nito Orchard bundle signing plan has unsupported key data");
            }
            if (data.plan) {
                throw std::ios_base::failure("Duplicate Nito Orchard bundle signing plan");
            }
            CPrivatePSBTOrchardBundlePlan plan;
            DataStream ss_value{MakeByteSpan(entry.value)};
            ss_value >> plan;
            if (!ss_value.empty()) {
                throw std::ios_base::failure("Nito Orchard bundle signing plan has trailing data");
            }
            data.plan = std::move(plan);
        } else if (entry.subtype == PSBT_NITO_GLOBAL_ORCHARD_SPEND_MATERIAL_V1) {
            const uint64_t spend_index = ReadCompactSize(ss_key);
            if (!ss_key.empty()) {
                throw std::ios_base::failure("Nito Orchard spend material has unsupported key data");
            }
            CPrivatePSBTOrchardSpendMaterial material;
            DataStream ss_value{MakeByteSpan(entry.value)};
            ss_value >> material;
            if (!ss_value.empty()) {
                throw std::ios_base::failure("Nito Orchard spend material has trailing data");
            }
            if (!data.spends.emplace(spend_index, std::move(material)).second) {
                throw std::ios_base::failure("Duplicate Nito Orchard spend material");
            }
        } else if (entry.subtype == PSBT_NITO_GLOBAL_ORCHARD_OUTPUT_MATERIAL_V1) {
            const uint64_t output_index = ReadCompactSize(ss_key);
            if (!ss_key.empty()) {
                throw std::ios_base::failure("Nito Orchard output material has unsupported key data");
            }
            CPrivatePSBTOrchardOutputMaterial material;
            DataStream ss_value{MakeByteSpan(entry.value)};
            ss_value >> material;
            if (!ss_value.empty()) {
                throw std::ios_base::failure("Nito Orchard output material has trailing data");
            }
            if (!data.outputs.emplace(output_index, std::move(material)).second) {
                throw std::ios_base::failure("Duplicate Nito Orchard output material");
            }
        }
    }

    if (!data.HasAny()) return data;
    if (!data.plan) {
        throw std::ios_base::failure("Nito Orchard signing material without bundle plan");
    }
    if (data.spends.size() != data.plan->spend_count) {
        throw std::ios_base::failure("Nito Orchard spend material count mismatch");
    }
    if (data.outputs.size() != data.plan->output_count) {
        throw std::ios_base::failure("Nito Orchard output material count mismatch");
    }
    for (uint64_t i = 0; i < data.plan->spend_count; ++i) {
        if (data.spends.find(i) == data.spends.end()) {
            throw std::ios_base::failure("Nito Orchard spend material index missing");
        }
    }
    for (uint64_t i = 0; i < data.plan->output_count; ++i) {
        if (data.outputs.find(i) == data.outputs.end()) {
            throw std::ios_base::failure("Nito Orchard output material index missing");
        }
    }
    return data;
}

std::optional<uint256> PartiallySignedTransaction::GetNitoPrivateIntentHash() const
{
    const NitoPrivatePSBTSigningData signing_data = GetNitoPrivateSigningData();
    if (!signing_data.HasAny()) return std::nullopt;
    if (!tx) {
        throw std::ios_base::failure("Nito Orchard signing material without unsigned transaction");
    }

    HashWriter hasher{};
    hasher << std::string{"NitoPrivatePSBTIntentV1"} << TX_NO_WITNESS(*tx);
    for (const auto& entry : m_proprietary) {
        if (entry.identifier == NitoPSBTProprietaryIdentifier() &&
            IsNitoPrivateSigningMaterialProprietarySubtype(entry.subtype)) {
            hasher << entry.key << entry.value;
        }
    }
    return hasher.GetHash();
}

bool PartiallySignedTransaction::HasNitoPrivateSigningMaterial() const
{
    return std::any_of(m_proprietary.begin(), m_proprietary.end(), [](const PSBTProprietary& entry) {
        return entry.identifier == NitoPSBTProprietaryIdentifier() && IsNitoPrivateSigningMaterialProprietarySubtype(entry.subtype);
    });
}

void PartiallySignedTransaction::ClearNitoPrivateSigningMaterialProprietary()
{
    for (auto it = m_proprietary.begin(); it != m_proprietary.end();) {
        if (it->identifier == NitoPSBTProprietaryIdentifier() && IsNitoPrivateSigningMaterialProprietarySubtype(it->subtype)) {
            it = m_proprietary.erase(it);
        } else {
            ++it;
        }
    }
}

void PartiallySignedTransaction::SetNitoPrivateAuthProprietaryFromTx()
{
    for (auto it = m_proprietary.begin(); it != m_proprietary.end();) {
        if (it->identifier == NitoPSBTProprietaryIdentifier() && IsNitoPrivateAuthOrReservedProprietarySubtype(it->subtype)) {
            it = m_proprietary.erase(it);
        } else {
            ++it;
        }
    }
    if (!tx || !tx->HasPrivateAuth()) return;

    const CPrivateAuth& auth = *tx->m_private_bundle->auth;
    m_proprietary.insert(MakeNitoPSBTOrchardBundleAuthProprietary(auth.BundleAuth()));
    for (uint64_t i = 0; i < auth.actions_auth.size(); ++i) {
        m_proprietary.insert(MakeNitoPSBTOrchardActionAuthProprietary(i, auth.actions_auth[i]));
    }
}

bool PartiallySignedTransaction::AddInput(const CTxIn& txin, PSBTInput& psbtin)
{
    if (std::find(tx->vin.begin(), tx->vin.end(), txin) != tx->vin.end()) {
        return false;
    }
    tx->vin.push_back(txin);
    psbtin.partial_sigs.clear();
    psbtin.final_script_sig.clear();
    psbtin.final_script_witness.SetNull();
    inputs.push_back(psbtin);
    return true;
}

bool PartiallySignedTransaction::AddOutput(const CTxOut& txout, const PSBTOutput& psbtout)
{
    tx->vout.push_back(txout);
    outputs.push_back(psbtout);
    return true;
}

bool PartiallySignedTransaction::GetInputUTXO(CTxOut& utxo, int input_index) const
{
    const PSBTInput& input = inputs[input_index];
    uint32_t prevout_index = tx->vin[input_index].prevout.n;
    if (input.non_witness_utxo) {
        if (prevout_index >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != tx->vin[input_index].prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout_index];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
    } else {
        return false;
    }
    return true;
}

bool PSBTInput::IsNull() const
{
    return !non_witness_utxo && witness_utxo.IsNull() && partial_sigs.empty() && unknown.empty() && hd_keypaths.empty() && redeem_script.empty() && witness_script.empty();
}

void PSBTInput::FillSignatureData(SignatureData& sigdata) const
{
    if (!final_script_sig.empty()) {
        sigdata.scriptSig = final_script_sig;
        sigdata.complete = true;
    }
    if (!final_script_witness.IsNull()) {
        sigdata.scriptWitness = final_script_witness;
        sigdata.complete = true;
    }
    if (sigdata.complete) {
        return;
    }

    sigdata.signatures.insert(partial_sigs.begin(), partial_sigs.end());
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_key_sig.empty()) {
        sigdata.taproot_key_path_sig = m_tap_key_sig;
    }
    for (const auto& [pubkey_leaf, sig] : m_tap_script_sigs) {
        sigdata.taproot_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!m_tap_internal_key.IsNull()) {
        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
    }
    if (!m_tap_merkle_root.IsNull()) {
        sigdata.tr_spenddata.merkle_root = m_tap_merkle_root;
    }
    for (const auto& [leaf_script, control_block] : m_tap_scripts) {
        sigdata.tr_spenddata.scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
        sigdata.tap_pubkeys.emplace(Hash160(pubkey), pubkey);
    }
    for (const auto& [hash, preimage] : ripemd160_preimages) {
        sigdata.ripemd160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sha256_preimages) {
        sigdata.sha256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : hash160_preimages) {
        sigdata.hash160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : hash256_preimages) {
        sigdata.hash256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
}

void PSBTInput::FromSignatureData(const SignatureData& sigdata)
{
    if (sigdata.complete) {
        partial_sigs.clear();
        hd_keypaths.clear();
        redeem_script.clear();
        witness_script.clear();

        if (!sigdata.scriptSig.empty()) {
            final_script_sig = sigdata.scriptSig;
        }
        if (!sigdata.scriptWitness.IsNull()) {
            final_script_witness = sigdata.scriptWitness;
        }
        return;
    }

    partial_sigs.insert(sigdata.signatures.begin(), sigdata.signatures.end());
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.taproot_key_path_sig.empty()) {
        m_tap_key_sig = sigdata.taproot_key_path_sig;
    }
    for (const auto& [pubkey_leaf, sig] : sigdata.taproot_script_sigs) {
        m_tap_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (!sigdata.tr_spenddata.merkle_root.IsNull()) {
        m_tap_merkle_root = sigdata.tr_spenddata.merkle_root;
    }
    for (const auto& [leaf_script, control_block] : sigdata.tr_spenddata.scripts) {
        m_tap_scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
}

void PSBTInput::Merge(const PSBTInput& input)
{
    if (!non_witness_utxo && input.non_witness_utxo) non_witness_utxo = input.non_witness_utxo;
    if (witness_utxo.IsNull() && !input.witness_utxo.IsNull()) {
        witness_utxo = input.witness_utxo;
    }

    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    ripemd160_preimages.insert(input.ripemd160_preimages.begin(), input.ripemd160_preimages.end());
    sha256_preimages.insert(input.sha256_preimages.begin(), input.sha256_preimages.end());
    hash160_preimages.insert(input.hash160_preimages.begin(), input.hash160_preimages.end());
    hash256_preimages.insert(input.hash256_preimages.begin(), input.hash256_preimages.end());
    hd_keypaths.insert(input.hd_keypaths.begin(), input.hd_keypaths.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());
    m_tap_script_sigs.insert(input.m_tap_script_sigs.begin(), input.m_tap_script_sigs.end());
    m_tap_scripts.insert(input.m_tap_scripts.begin(), input.m_tap_scripts.end());
    m_tap_bip32_paths.insert(input.m_tap_bip32_paths.begin(), input.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !input.redeem_script.empty()) redeem_script = input.redeem_script;
    if (witness_script.empty() && !input.witness_script.empty()) witness_script = input.witness_script;
    if (final_script_sig.empty() && !input.final_script_sig.empty()) final_script_sig = input.final_script_sig;
    if (final_script_witness.IsNull() && !input.final_script_witness.IsNull()) final_script_witness = input.final_script_witness;
    if (m_tap_key_sig.empty() && !input.m_tap_key_sig.empty()) m_tap_key_sig = input.m_tap_key_sig;
    if (m_tap_internal_key.IsNull() && !input.m_tap_internal_key.IsNull()) m_tap_internal_key = input.m_tap_internal_key;
    if (m_tap_merkle_root.IsNull() && !input.m_tap_merkle_root.IsNull()) m_tap_merkle_root = input.m_tap_merkle_root;
}

void PSBTOutput::FillSignatureData(SignatureData& sigdata) const
{
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_tree.empty() && m_tap_internal_key.IsFullyValid()) {
        TaprootBuilder builder;
        for (const auto& [depth, leaf_ver, script] : m_tap_tree) {
            builder.Add((int)depth, script, (int)leaf_ver, /*track=*/true);
        }
        assert(builder.IsComplete());
        builder.Finalize(m_tap_internal_key);
        TaprootSpendData spenddata = builder.GetSpendData();

        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
        sigdata.tr_spenddata.Merge(spenddata);
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
        sigdata.tap_pubkeys.emplace(Hash160(pubkey), pubkey);
    }
}

void PSBTOutput::FromSignatureData(const SignatureData& sigdata)
{
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (sigdata.tr_builder.has_value() && sigdata.tr_builder->HasScripts()) {
        m_tap_tree = sigdata.tr_builder->GetTreeTuples();
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
}

bool PSBTOutput::IsNull() const
{
    return redeem_script.empty() && witness_script.empty() && hd_keypaths.empty() && unknown.empty();
}

void PSBTOutput::Merge(const PSBTOutput& output)
{
    hd_keypaths.insert(output.hd_keypaths.begin(), output.hd_keypaths.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());
    m_tap_bip32_paths.insert(output.m_tap_bip32_paths.begin(), output.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !output.redeem_script.empty()) redeem_script = output.redeem_script;
    if (witness_script.empty() && !output.witness_script.empty()) witness_script = output.witness_script;
    if (m_tap_internal_key.IsNull() && !output.m_tap_internal_key.IsNull()) m_tap_internal_key = output.m_tap_internal_key;
    if (m_tap_tree.empty() && !output.m_tap_tree.empty()) m_tap_tree = output.m_tap_tree;
}

bool PSBTInputSigned(const PSBTInput& input)
{
    return !input.final_script_sig.empty() || !input.final_script_witness.IsNull();
}

bool PSBTInputSignedAndVerified(const PartiallySignedTransaction psbt, unsigned int input_index, const PrecomputedTransactionData* txdata)
{
    CTxOut utxo;
    assert(psbt.inputs.size() >= input_index);
    const PSBTInput& input = psbt.inputs[input_index];

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = psbt.tx->vin[input_index].prevout;
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
    } else {
        return false;
    }

    if (txdata) {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&(*psbt.tx), input_index, utxo.nValue, *txdata, MissingDataBehavior::FAIL});
    } else {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&(*psbt.tx), input_index, utxo.nValue, MissingDataBehavior::FAIL});
    }
}

size_t CountPSBTUnsignedInputs(const PartiallySignedTransaction& psbt) {
    size_t count = 0;
    for (const auto& input : psbt.inputs) {
        if (!PSBTInputSigned(input)) {
            count++;
        }
    }

    return count;
}

void UpdatePSBTOutput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index)
{
    CMutableTransaction& tx = *Assert(psbt.tx);
    const CTxOut& out = tx.vout.at(index);
    PSBTOutput& psbt_out = psbt.outputs.at(index);

    // Fill a SignatureData with output info
    SignatureData sigdata;
    psbt_out.FillSignatureData(sigdata);

    // Construct a would-be spend of this output, to update sigdata with.
    // Note that ProduceSignature is used to fill in metadata (not actual signatures),
    // so provider does not need to provide any private keys (it can be a HidingSigningProvider).
    MutableTransactionSignatureCreator creator(tx, /*input_idx=*/0, out.nValue, SIGHASH_ALL);
    ProduceSignature(provider, creator, out.scriptPubKey, sigdata);

    // Put redeem_script, witness_script, key paths, into PSBTOutput.
    psbt_out.FromSignatureData(sigdata);
}

PrecomputedTransactionData PrecomputePSBTData(const PartiallySignedTransaction& psbt)
{
    const CMutableTransaction& tx = *psbt.tx;
    bool have_all_spent_outputs = true;
    std::vector<CTxOut> utxos(tx.vin.size());
    for (size_t idx = 0; idx < tx.vin.size(); ++idx) {
        if (!psbt.GetInputUTXO(utxos[idx], idx)) have_all_spent_outputs = false;
    }
    PrecomputedTransactionData txdata;
    if (have_all_spent_outputs) {
        txdata.Init(tx, std::move(utxos), true);
    } else {
        txdata.Init(tx, {}, true);
    }
    return txdata;
}

bool SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, const PrecomputedTransactionData* txdata, int sighash,  SignatureData* out_sigdata, bool finalize)
{
    PSBTInput& input = psbt.inputs.at(index);
    const CMutableTransaction& tx = *psbt.tx;

    if (PSBTInputSignedAndVerified(psbt, index, txdata)) {
        return true;
    }

    // Fill SignatureData with input info
    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    // Get UTXO
    bool require_witness_sig = false;
    CTxOut utxo;

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = tx.vin[index].prevout;
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
        // When we're taking our information from a witness UTXO, we can't verify it is actually data from
        // the output being spent. This is safe in case a witness signature is produced (which includes this
        // information directly in the hash), but not for non-witness signatures. Remember that we require
        // a witness signature in this situation.
        require_witness_sig = true;
    } else {
        return false;
    }

    sigdata.witness = false;
    bool sig_complete;
    if (txdata == nullptr) {
        sig_complete = ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, utxo.scriptPubKey, sigdata);
    } else {
        MutableTransactionSignatureCreator creator(tx, index, utxo.nValue, txdata, sighash);
        sig_complete = ProduceSignature(provider, creator, utxo.scriptPubKey, sigdata);
    }
    // Verify that a witness signature was produced in case one was required.
    if (require_witness_sig && !sigdata.witness) return false;

    // If we are not finalizing, set sigdata.complete to false to not set the scriptWitness
    if (!finalize && sigdata.complete) sigdata.complete = false;

    input.FromSignatureData(sigdata);

    // If we have a witness signature, put a witness UTXO.
    if (sigdata.witness) {
        input.witness_utxo = utxo;
        // We can remove the non_witness_utxo if and only if there are no non-segwit or segwit v0
        // inputs in this transaction. Since this requires inspecting the entire transaction, this
        // is something for the caller to deal with (i.e. FillPSBT).
    }

    // Fill in the missing info
    if (out_sigdata) {
        out_sigdata->missing_pubkeys = sigdata.missing_pubkeys;
        out_sigdata->missing_sigs = sigdata.missing_sigs;
        out_sigdata->missing_redeem_script = sigdata.missing_redeem_script;
        out_sigdata->missing_witness_script = sigdata.missing_witness_script;
    }

    return sig_complete;
}

void RemoveUnnecessaryTransactions(PartiallySignedTransaction& psbtx, const int& sighash_type)
{
    // Only drop non_witness_utxos if sighash_type != SIGHASH_ANYONECANPAY
    if ((sighash_type & 0x80) != SIGHASH_ANYONECANPAY) {
        // Figure out if any non_witness_utxos should be dropped
        std::vector<unsigned int> to_drop;
        for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
            const auto& input = psbtx.inputs.at(i);
            int wit_ver;
            std::vector<unsigned char> wit_prog;
            if (input.witness_utxo.IsNull() || !input.witness_utxo.scriptPubKey.IsWitnessProgram(wit_ver, wit_prog)) {
                // There's a non-segwit input or Segwit v0, so we cannot drop any witness_utxos
                to_drop.clear();
                break;
            }
            if (wit_ver == 0) {
                // Segwit v0, so we cannot drop any non_witness_utxos
                to_drop.clear();
                break;
            }
            if (input.non_witness_utxo) {
                to_drop.push_back(i);
            }
        }

        // Drop the non_witness_utxos that we can drop
        for (unsigned int i : to_drop) {
            psbtx.inputs.at(i).non_witness_utxo = nullptr;
        }
    }
}

bool FinalizePSBT(PartiallySignedTransaction& psbtx)
{
    // Finalize input signatures -- in case we have partial signatures that add up to a complete
    //   signature, but have not combined them yet (e.g. because the combiner that created this
    //   PartiallySignedTransaction did not understand them), this will combine them into a final
    //   script.
    psbtx.ApplyNitoPrivateAuthProprietary();
    bool complete = true;
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        complete &= SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, SIGHASH_ALL, nullptr, true);
    }
    if (psbtx.HasNitoPrivateSigningMaterial()) {
        complete = false;
    }
    if (psbtx.tx->HasPrivateBundle()) {
        if (!psbtx.tx->HasPrivateAuth()) {
            complete = false;
        } else {
            std::string private_error;
            if (VerifyPrivateOrchardBundle(CTransaction(*psbtx.tx), private_error) != PrivateOrchardVerifyResult::OK) {
                complete = false;
            }
        }
    }

    return complete;
}

bool FinalizeAndExtractPSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& result)
{
    // It's not safe to extract a PSBT that isn't finalized, and there's no easy way to check
    //   whether a PSBT is finalized without finalizing it, so we just do this.
    if (!FinalizePSBT(psbtx)) {
        return false;
    }

    result = *psbtx.tx;
    for (unsigned int i = 0; i < result.vin.size(); ++i) {
        result.vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
        result.vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
    }
    return true;
}

TransactionError CombinePSBTs(PartiallySignedTransaction& out, const std::vector<PartiallySignedTransaction>& psbtxs)
{
    out = psbtxs[0]; // Copy the first one

    // Merge
    for (auto it = std::next(psbtxs.begin()); it != psbtxs.end(); ++it) {
        if (!out.Merge(*it)) {
            return TransactionError::PSBT_MISMATCH;
        }
    }
    return TransactionError::OK;
}

std::string PSBTRoleName(PSBTRole role) {
    switch (role) {
    case PSBTRole::CREATOR: return "creator";
    case PSBTRole::UPDATER: return "updater";
    case PSBTRole::SIGNER: return "signer";
    case PSBTRole::FINALIZER: return "finalizer";
    case PSBTRole::EXTRACTOR: return "extractor";
        // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}

bool DecodeBase64PSBT(PartiallySignedTransaction& psbt, const std::string& base64_tx, std::string& error)
{
    auto tx_data = DecodeBase64(base64_tx);
    if (!tx_data) {
        error = "invalid base64";
        return false;
    }
    return DecodeRawPSBT(psbt, MakeByteSpan(*tx_data), error);
}

bool DecodeRawPSBT(PartiallySignedTransaction& psbt, Span<const std::byte> tx_data, std::string& error)
{
    DataStream ss_data{tx_data};
    try {
        ss_data >> psbt;
        if (!ss_data.empty()) {
            error = "extra data after PSBT";
            return false;
        }
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    return true;
}

uint32_t PartiallySignedTransaction::GetVersion() const
{
    if (m_version != std::nullopt) {
        return *m_version;
    }
    return 0;
}
