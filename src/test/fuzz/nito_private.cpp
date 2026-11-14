// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/amount.h>
#include <private/orchard_verifier.h>
#include <private/private_state.h>
#include <primitives/private_transaction.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <ios>
#include <optional>
#include <string>
#include <vector>

namespace {
template <typename T>
void RoundTripSerialize(const T& obj)
{
    DataStream ss{};
    ss << obj;
}

void RoundTripSerialize(const CMutableTransaction& tx)
{
    DataStream ss{};
    ss << TX_WITH_WITNESS(tx);
}

std::optional<PSBTProprietary> ConsumePSBTProprietary(FuzzedDataProvider& fuzzed_data_provider)
{
    PSBTProprietary entry;
    if (fuzzed_data_provider.ConsumeBool()) {
        const uint64_t subtype{fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(0, 8)};
        const std::vector<unsigned char> keydata{ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 256)};
        entry.identifier = NitoPSBTProprietaryIdentifier();
        entry.subtype = subtype;
        entry.key = MakeNitoPSBTProprietaryKey(subtype, Span<const unsigned char>{keydata});
    } else {
        std::vector<unsigned char> key{ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 1024)};
        SpanReader skey{key};
        try {
            if (ReadCompactSize(skey) != PSBT_GLOBAL_PROPRIETARY) return std::nullopt;
            skey >> entry.identifier;
            entry.subtype = ReadCompactSize(skey);
        } catch (const std::ios_base::failure&) {
            return std::nullopt;
        }
        entry.key = std::move(key);
    }
    entry.value = ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 8192);
    return entry;
}

void RoundTripPSBTWithProprietary(const PSBTProprietary& entry)
{
    PartiallySignedTransaction psbt{CMutableTransaction{}};
    psbt.m_proprietary.insert(entry);
    DataStream ss{};
    ss << psbt;
    PartiallySignedTransaction decoded;
    ss >> decoded;
    if (decoded.HasNitoPrivateSigningMaterial()) {
        (void)decoded.GetNitoPrivateSigningData();
    }
}

template <size_t N>
std::array<unsigned char, N> ConsumeByteArray(FuzzedDataProvider& fuzzed_data_provider)
{
    const std::vector<unsigned char> bytes{ConsumeFixedLengthByteVector<unsigned char>(fuzzed_data_provider, N)};
    std::array<unsigned char, N> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}
} // namespace

FUZZ_TARGET(nito_private_serialization)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    CallOneOf(
        fuzzed_data_provider,
        [&] {
            const std::optional<CPrivateActionEffects> action{ConsumeDeserializable<CPrivateActionEffects>(fuzzed_data_provider, std::optional<size_t>{4096})};
            if (action) RoundTripSerialize(*action);
        },
        [&] {
            const std::optional<CPrivateEffects> effects{ConsumeDeserializable<CPrivateEffects>(fuzzed_data_provider, std::optional<size_t>{8192})};
            if (effects) RoundTripSerialize(*effects);
        },
        [&] {
            const std::optional<CPrivateAuth> auth{ConsumeDeserializable<CPrivateAuth>(fuzzed_data_provider, std::optional<size_t>{8192})};
            if (auth) RoundTripSerialize(*auth);
        },
        [&] {
            const std::optional<CPrivateBundleAuth> auth{ConsumeDeserializable<CPrivateBundleAuth>(fuzzed_data_provider, std::optional<size_t>{8192})};
            if (auth) RoundTripSerialize(*auth);
        },
        [&] {
            const std::optional<CPrivateTxUndo> undo{ConsumeDeserializable<CPrivateTxUndo>(fuzzed_data_provider, std::optional<size_t>{8192})};
            if (undo) RoundTripSerialize(*undo);
        },
        [&] {
            const std::optional<CPrivateBlockUndo> undo{ConsumeDeserializable<CPrivateBlockUndo>(fuzzed_data_provider, std::optional<size_t>{8192})};
            if (undo) RoundTripSerialize(*undo);
        },
        [&] {
            const std::optional<PSBTProprietary> proprietary{ConsumePSBTProprietary(fuzzed_data_provider)};
            try {
                if (proprietary) RoundTripPSBTWithProprietary(*proprietary);
            } catch (const std::ios_base::failure&) {
                // Fuzz-created PSBT maps are often intentionally malformed.
            }
        },
        [&] {
            const std::optional<PartiallySignedTransaction> psbt{ConsumeDeserializable<PartiallySignedTransaction>(fuzzed_data_provider, std::optional<size_t>{32768})};
            if (psbt) RoundTripSerialize(*psbt);
        },
        [&] {
            const std::optional<CMutableTransaction> tx{ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS, std::optional<size_t>{32768})};
            if (tx) {
                RoundTripSerialize(*tx);
                if (tx->HasPrivateBundle()) {
                    (void)PrivateBundleSighash(*tx);
                }
            }
        });
}

FUZZ_TARGET(nito_orchard_ffi)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    const auto spending_key{ConsumeByteArray<32>(fuzzed_data_provider)};
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> recipient_raw{};
    std::array<unsigned char, NITO_ORCHARD_FULL_VIEWING_KEY_SIZE> full_viewing_key{};
    std::string error;

    const uint32_t diversifier_index{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
    (void)DerivePrivateOrchardFullViewingKey(Span<const unsigned char>{spending_key.data(), spending_key.size()}, full_viewing_key, error);
    if (DerivePrivateOrchardRawAddressScoped(Span<const unsigned char>{spending_key.data(), spending_key.size()},
                                             diversifier_index,
                                             fuzzed_data_provider.ConsumeBool(),
                                             recipient_raw,
                                             error) != PrivateOrchardBuildResult::OK) {
        return;
    }

    const CAmount value{fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 1'000'000 * COIN)};
    const auto rho{ConsumeByteArray<NITO_ORCHARD_RHO_SIZE>(fuzzed_data_provider)};
    const auto rseed{ConsumeByteArray<NITO_ORCHARD_RSEED_SIZE>(fuzzed_data_provider)};
    uint256 cmx;
    if (ComputePrivateOrchardNoteCommitment(Span<const unsigned char>{recipient_raw.data(), recipient_raw.size()},
                                            value,
                                            Span<const unsigned char>{rho.data(), rho.size()},
                                            Span<const unsigned char>{rseed.data(), rseed.size()},
                                            cmx,
                                            error) != PrivateOrchardBuildResult::OK) {
        return;
    }

    std::vector<uint256> commitments;
    commitments.push_back(cmx);
    const size_t extra_commitments{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 7)};
    for (size_t i = 0; i < extra_commitments; ++i) {
        commitments.push_back(ConsumeUInt256(fuzzed_data_provider));
    }

    uint256 root;
    std::vector<uint256> auth_path;
    (void)ComputePrivateOrchardAuthPath(Span<const uint256>{commitments.data(), commitments.size()},
                                        fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, commitments.size() - 1),
                                        auth_path,
                                        root,
                                        error);

    std::vector<unsigned char> frontier;
    (void)AppendPrivateCommitmentsToFrontier({}, commitments, root, frontier, error);
    if (!frontier.empty()) {
        std::vector<unsigned char> next_frontier;
        const std::vector<uint256> next_commitments{ConsumeUInt256(fuzzed_data_provider)};
        (void)AppendPrivateCommitmentsToFrontier(frontier, next_commitments, root, next_frontier, error);
    }
}

FUZZ_TARGET(nito_private_state)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    const auto spending_key{ConsumeByteArray<32>(fuzzed_data_provider)};
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> recipient_raw{};
    std::string error;
    if (DerivePrivateOrchardRawAddress(Span<const unsigned char>{spending_key.data(), spending_key.size()},
                                       fuzzed_data_provider.ConsumeIntegral<uint32_t>(),
                                       recipient_raw,
                                       error) != PrivateOrchardBuildResult::OK) {
        return;
    }

    const auto rho{ConsumeByteArray<NITO_ORCHARD_RHO_SIZE>(fuzzed_data_provider)};
    const auto rseed{ConsumeByteArray<NITO_ORCHARD_RSEED_SIZE>(fuzzed_data_provider)};
    uint256 cmx;
    if (ComputePrivateOrchardNoteCommitment(Span<const unsigned char>{recipient_raw.data(), recipient_raw.size()},
                                            fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 1'000'000 * COIN),
                                            Span<const unsigned char>{rho.data(), rho.size()},
                                            Span<const unsigned char>{rseed.data(), rseed.size()},
                                            cmx,
                                            error) != PrivateOrchardBuildResult::OK) {
        return;
    }

    uint256 empty_root;
    if (!GetPrivateEmptyRoot(empty_root, error)) return;

    CAmount connected_value_pool{0};
    std::string pool_error;
    (void)CheckPrivateValuePoolTransition(fuzzed_data_provider.ConsumeIntegral<CAmount>(),
                                          fuzzed_data_provider.ConsumeIntegral<CAmount>(),
                                          connected_value_pool,
                                          pool_error);

    CCoinsView backend;
    CCoinsViewCache view{&backend, /*deterministic=*/true};
    view.AddPrivateAnchor(empty_root);
    view.SetPrivateRoot(empty_root);
    view.SetPrivateCommitmentCount(0);
    view.SetPrivateFrontier({});
    view.SetPrivateValuePool(0);

    CPrivateActionEffects action;
    action.nullifier = ConsumeUInt256(fuzzed_data_provider);
    action.cmx = cmx;

    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.m_private_bundle = CPrivateBundle{};
    mtx.m_private_bundle->effects.anchor = empty_root;
    mtx.m_private_bundle->effects.actions.push_back(action);

    CPrivateTxUndo undo;
    assert(ApplyPrivateTransaction(CTransaction{mtx}, view, undo, error));
    assert(view.HavePrivateNullifier(action.nullifier));
    assert(view.GetPrivateValuePool(connected_value_pool));
    assert(connected_value_pool == 0);

    CPrivateTxUndo conflict_undo;
    std::string conflict_error;
    assert(!ApplyPrivateTransaction(CTransaction{mtx}, view, conflict_undo, conflict_error));
    assert(!conflict_error.empty());

    std::string undo_error;
    assert(UndoPrivateTransaction(view, undo, undo_error));
    assert(!view.HavePrivateNullifier(action.nullifier));
    uint64_t count{1};
    assert(view.GetPrivateCommitmentCount(count));
    assert(count == 0);
    uint256 restored_root;
    assert(view.GetPrivateRoot(restored_root));
    assert(restored_root == empty_root);
    assert(view.GetPrivateValuePool(connected_value_pool));
    assert(connected_value_pool == 0);
}
