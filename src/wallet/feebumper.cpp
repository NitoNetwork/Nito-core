// Copyright (c) 2017-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <chainparams.h>
#include <consensus/private_tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/hmac_sha256.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <private/private_address.h>
#include <streams.h>
#include <support/cleanse.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/fees.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string_view>
#include <uint256.h>

namespace wallet {
namespace {
constexpr std::string_view PRIVATE_BUMP_RECIPE_KEY{"nito_private_bump_recipe"};
constexpr std::string_view PRIVATE_BUMP_SOURCE_KEY{"nito_private_bump_source"};
constexpr std::string_view PRIVATE_BUMP_RECIPIENTS_KEY{"nito_private_bump_recipients"};
constexpr std::string_view PRIVATE_BUMP_NOTES_KEY{"nito_private_bump_notes"};
constexpr uint8_t PRIVATE_BUMP_ENVELOPE_VERSION{1};
constexpr uint8_t PRIVATE_BUMP_RECIPE_VERSION{1};
constexpr uint8_t PRIVATE_BUMP_PLAINTEXT{0};
constexpr uint8_t PRIVATE_BUMP_ENCRYPTED{1};
constexpr uint8_t PRIVATE_BUMP_TRANSPARENT_RECIPIENT{0};
constexpr uint8_t PRIVATE_BUMP_ORCHARD_RECIPIENT{1};
constexpr size_t PRIVATE_BUMP_TAG_SIZE{32};
constexpr size_t MAX_PRIVATE_BUMP_ENVELOPE_SIZE{256 * 1024};
constexpr size_t MAX_PRIVATE_BUMP_RECIPIENTS{1000};
constexpr size_t MAX_PRIVATE_BUMP_DESTINATION_SIZE{128};

struct PrivateBumpWireRecipient
{
    uint8_t kind{PRIVATE_BUMP_TRANSPARENT_RECIPIENT};
    std::vector<unsigned char> destination;
    CAmount amount{0};
    uint8_t subtract_fee{0};

    SERIALIZE_METHODS(PrivateBumpWireRecipient, obj)
    {
        READWRITE(obj.kind, obj.destination, obj.amount, obj.subtract_fee);
    }
};

struct PrivateBumpWireRecipe
{
    uint8_t version{PRIVATE_BUMP_RECIPE_VERSION};
    uint256 txid;
    uint8_t source{0};
    std::vector<PrivateBumpWireRecipient> recipients;
    std::vector<uint256> private_note_ids;

    SERIALIZE_METHODS(PrivateBumpWireRecipe, obj)
    {
        READWRITE(obj.version, obj.txid, obj.source, obj.recipients, obj.private_note_ids);
    }
};

struct PrivateBumpEnvelope
{
    uint8_t version{PRIVATE_BUMP_ENVELOPE_VERSION};
    uint8_t protection{PRIVATE_BUMP_PLAINTEXT};
    std::vector<unsigned char> payload;
    std::array<unsigned char, PRIVATE_BUMP_TAG_SIZE> tag{};
};

struct PrivateBumpRecipe
{
    CCoinControl::PrivateTxSource source{CCoinControl::PrivateTxSource::AUTO};
    std::vector<CRecipient> recipients;
    std::vector<uint256> private_note_ids;
};

template <typename ByteVector>
void Cleanse(ByteVector& value)
{
    if (!value.empty()) memory_cleanse(value.data(), value.size());
    value.clear();
}

void EraseUnsupportedPrivateBumpMetadata(mapValue_t& map_value)
{
    map_value.erase(std::string{PRIVATE_BUMP_SOURCE_KEY});
    map_value.erase(std::string{PRIVATE_BUMP_RECIPIENTS_KEY});
    map_value.erase(std::string{PRIVATE_BUMP_NOTES_KEY});
}

uint256 PrivateBumpEncryptionIV(const uint256& txid)
{
    HashWriter writer;
    writer << std::string{"nito/private-bump/encryption-iv/v1"} << txid;
    return writer.GetHash();
}

std::array<unsigned char, PRIVATE_BUMP_TAG_SIZE> PrivateBumpMacKey(const CKeyingMaterial& master_key)
{
    static constexpr std::string_view domain{"nito/private-bump/mac-key/v1"};
    std::array<unsigned char, PRIVATE_BUMP_TAG_SIZE> key{};
    CHMAC_SHA256(master_key.data(), master_key.size())
        .Write(reinterpret_cast<const unsigned char*>(domain.data()), domain.size())
        .Finalize(key.data());
    return key;
}

std::array<unsigned char, PRIVATE_BUMP_TAG_SIZE> PrivateBumpTag(const CKeyingMaterial& master_key,
                                                               const uint256& txid,
                                                               Span<const unsigned char> ciphertext)
{
    static constexpr std::string_view domain{"nito/private-bump/envelope/v1"};
    std::array<unsigned char, PRIVATE_BUMP_TAG_SIZE> mac_key{PrivateBumpMacKey(master_key)};
    std::array<unsigned char, PRIVATE_BUMP_TAG_SIZE> tag{};
    const uint8_t version{PRIVATE_BUMP_ENVELOPE_VERSION};
    CHMAC_SHA256(mac_key.data(), mac_key.size())
        .Write(reinterpret_cast<const unsigned char*>(domain.data()), domain.size())
        .Write(&version, sizeof(version))
        .Write(txid.begin(), txid.size())
        .Write(ciphertext.data(), ciphertext.size())
        .Finalize(tag.data());
    memory_cleanse(mac_key.data(), mac_key.size());
    return tag;
}

std::string EncodePrivateBumpEnvelope(const PrivateBumpEnvelope& envelope)
{
    DataStream stream;
    stream << envelope.version << envelope.protection << envelope.payload;
    if (envelope.protection == PRIVATE_BUMP_ENCRYPTED) stream << envelope.tag;
    return EncodeBase64(stream);
}

util::Result<PrivateBumpEnvelope> DecodePrivateBumpEnvelope(std::string_view encoded)
{
    if (encoded.empty() || encoded.size() > MAX_PRIVATE_BUMP_ENVELOPE_SIZE * 2) {
        return util::Error{Untranslated("Private-bundle fee-bump recipe envelope is malformed.")};
    }
    const auto decoded{DecodeBase64(encoded)};
    if (!decoded || decoded->empty() || decoded->size() > MAX_PRIVATE_BUMP_ENVELOPE_SIZE) {
        return util::Error{Untranslated("Private-bundle fee-bump recipe envelope is malformed.")};
    }
    try {
        SpanReader stream{Span<const uint8_t>{*decoded}};
        PrivateBumpEnvelope envelope;
        stream >> envelope.version >> envelope.protection;
        const uint64_t payload_size{ReadCompactSize(stream)};
        if (envelope.version != PRIVATE_BUMP_ENVELOPE_VERSION ||
            (envelope.protection != PRIVATE_BUMP_PLAINTEXT && envelope.protection != PRIVATE_BUMP_ENCRYPTED) ||
            payload_size == 0 || payload_size > MAX_PRIVATE_BUMP_ENVELOPE_SIZE) {
            return util::Error{Untranslated("Private-bundle fee-bump recipe envelope is malformed.")};
        }
        const size_t tag_size{envelope.protection == PRIVATE_BUMP_ENCRYPTED ? PRIVATE_BUMP_TAG_SIZE : 0};
        if (payload_size > stream.size() || stream.size() - payload_size != tag_size) {
            return util::Error{Untranslated("Private-bundle fee-bump recipe envelope is malformed.")};
        }
        envelope.payload.resize(payload_size);
        stream.read(MakeWritableByteSpan(envelope.payload));
        if (envelope.protection == PRIVATE_BUMP_ENCRYPTED) stream >> envelope.tag;
        if (!stream.empty()) {
            return util::Error{Untranslated("Private-bundle fee-bump recipe envelope is malformed.")};
        }
        return envelope;
    } catch (...) {
        return util::Error{Untranslated("Private-bundle fee-bump recipe envelope is malformed.")};
    }
}

util::Result<std::vector<unsigned char>> EncryptPrivateBumpPayload(const CKeyingMaterial& master_key,
                                                                  const uint256& txid,
                                                                  Span<const unsigned char> payload,
                                                                  std::array<unsigned char, PRIVATE_BUMP_TAG_SIZE>& tag)
{
    if (master_key.empty() || payload.empty() || payload.size() > MAX_PRIVATE_BUMP_ENVELOPE_SIZE) {
        return util::Error{Untranslated("Unable to encrypt private-bundle fee-bump metadata.")};
    }
    CKeyingMaterial plaintext(payload.begin(), payload.end());
    std::vector<unsigned char> ciphertext;
    const bool encrypted{EncryptSecret(master_key, plaintext, PrivateBumpEncryptionIV(txid), ciphertext)};
    Cleanse(plaintext);
    if (!encrypted || ciphertext.empty() || ciphertext.size() > MAX_PRIVATE_BUMP_ENVELOPE_SIZE) {
        Cleanse(ciphertext);
        return util::Error{Untranslated("Unable to encrypt private-bundle fee-bump metadata.")};
    }
    tag = PrivateBumpTag(master_key, txid, ciphertext);
    return ciphertext;
}

util::Result<std::vector<unsigned char>> DecryptPrivateBumpPayload(const CKeyingMaterial& master_key,
                                                                  const uint256& txid,
                                                                  const PrivateBumpEnvelope& envelope)
{
    if (master_key.empty() || envelope.protection != PRIVATE_BUMP_ENCRYPTED) {
        return util::Error{Untranslated("Wallet is locked; private fee-bump metadata is unavailable.")};
    }
    const auto expected_tag{PrivateBumpTag(master_key, txid, envelope.payload)};
    if (!TimingResistantEqual(expected_tag, envelope.tag)) {
        return util::Error{Untranslated("Private-bundle fee-bump recipe authentication failed.")};
    }
    CKeyingMaterial plaintext;
    if (!DecryptSecret(master_key, envelope.payload, PrivateBumpEncryptionIV(txid), plaintext) ||
        plaintext.empty() || plaintext.size() > MAX_PRIVATE_BUMP_ENVELOPE_SIZE) {
        Cleanse(plaintext);
        return util::Error{Untranslated("Private-bundle fee-bump recipe decryption failed.")};
    }
    std::vector<unsigned char> result(plaintext.begin(), plaintext.end());
    Cleanse(plaintext);
    return result;
}

util::Result<PrivateBumpRecipe> DecodePrivateBumpRecipe(Span<const unsigned char> payload, const uint256& expected_txid)
{
    if (payload.empty() || payload.size() > MAX_PRIVATE_BUMP_ENVELOPE_SIZE) {
        return util::Error{Untranslated("Private-bundle fee-bump recipe is malformed.")};
    }
    try {
        SpanReader stream{payload};
        uint8_t version;
        uint256 txid;
        uint8_t source;
        stream >> version >> txid >> source;
        if (version != PRIVATE_BUMP_RECIPE_VERSION || txid != expected_txid) {
            return util::Error{Untranslated("Private-bundle fee-bump recipe is malformed.")};
        }

        PrivateBumpRecipe recipe;
        if (source == static_cast<uint8_t>(CCoinControl::PrivateTxSource::TRANSPARENT_COINS)) {
            recipe.source = CCoinControl::PrivateTxSource::TRANSPARENT_COINS;
        } else if (source == static_cast<uint8_t>(CCoinControl::PrivateTxSource::PRIVATE_NOTES)) {
            recipe.source = CCoinControl::PrivateTxSource::PRIVATE_NOTES;
        } else {
            return util::Error{Untranslated("Private-bundle fee-bump recipe has an unknown source policy.")};
        }

        const uint64_t recipient_count{ReadCompactSize(stream)};
        if (recipient_count == 0 || recipient_count > MAX_PRIVATE_BUMP_RECIPIENTS) {
            return util::Error{Untranslated("Private-bundle fee-bump recipe is malformed.")};
        }
        recipe.recipients.reserve(recipient_count);
        CAmount total{0};
        for (uint64_t i{0}; i < recipient_count; ++i) {
            uint8_t kind;
            stream >> kind;
            const uint64_t destination_size{ReadCompactSize(stream)};
            if (destination_size == 0 || destination_size > MAX_PRIVATE_BUMP_DESTINATION_SIZE || destination_size > stream.size()) {
                return util::Error{Untranslated("Private-bundle fee-bump recipe contains an invalid address.")};
            }
            std::vector<unsigned char> destination(destination_size);
            stream.read(MakeWritableByteSpan(destination));
            CAmount amount;
            uint8_t subtract_fee;
            stream >> amount >> subtract_fee;
            if (!MoneyRange(amount) || amount <= 0 || subtract_fee > 1 || !MoneyRange(total + amount)) {
                return util::Error{Untranslated("Private-bundle fee-bump recipe contains an invalid recipient amount.")};
            }
            total += amount;
            if (kind == PRIVATE_BUMP_ORCHARD_RECIPIENT) {
                if (destination.size() != NITO_ORCHARD_RAW_ADDRESS_SIZE) {
                    return util::Error{Untranslated("Private-bundle fee-bump recipe contains an invalid private address.")};
                }
                std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> raw{};
                std::memcpy(raw.data(), destination.data(), raw.size());
                recipe.recipients.emplace_back(CRecipient{CNoDestination{}, amount, subtract_fee != 0, raw});
            } else if (kind == PRIVATE_BUMP_TRANSPARENT_RECIPIENT) {
                const std::string address{destination.begin(), destination.end()};
                CTxDestination dest{DecodeDestination(address)};
                if (!IsValidDestination(dest)) {
                    return util::Error{Untranslated("Private-bundle fee-bump recipe contains an invalid transparent address.")};
                }
                recipe.recipients.emplace_back(CRecipient{dest, amount, subtract_fee != 0});
            } else {
                return util::Error{Untranslated("Private-bundle fee-bump recipe contains an unknown recipient type.")};
            }
        }
        const uint64_t note_count{ReadCompactSize(stream)};
        if (note_count > MAX_PRIVATE_ORCHARD_ACTIONS || note_count > stream.size() / uint256::size()) {
            return util::Error{Untranslated("Private-bundle fee-bump recipe contains too many private note ids.")};
        }
        recipe.private_note_ids.reserve(note_count);
        for (uint64_t i{0}; i < note_count; ++i) {
            uint256 cmx;
            stream >> cmx;
            if (cmx.IsNull() || std::find(recipe.private_note_ids.begin(), recipe.private_note_ids.end(), cmx) != recipe.private_note_ids.end()) {
                return util::Error{Untranslated("Private-bundle fee-bump recipe contains an invalid or duplicate private note id.")};
            }
            recipe.private_note_ids.push_back(cmx);
        }
        if (!stream.empty()) {
            return util::Error{Untranslated("Private-bundle fee-bump recipe is malformed.")};
        }
        return recipe;
    } catch (...) {
        return util::Error{Untranslated("Private-bundle fee-bump recipe is malformed.")};
    }
}

std::vector<unsigned char> EncodePrivateBumpRecipe(const uint256& txid, const PrivateBumpRecipe& recipe)
{
    PrivateBumpWireRecipe wire;
    wire.txid = txid;
    wire.source = static_cast<uint8_t>(recipe.source);
    wire.private_note_ids = recipe.private_note_ids;
    for (const CRecipient& recipient : recipe.recipients) {
        PrivateBumpWireRecipient wire_recipient;
        wire_recipient.amount = recipient.nAmount;
        wire_recipient.subtract_fee = recipient.fSubtractFeeFromAmount ? 1 : 0;
        if (recipient.IsPrivate()) {
            wire_recipient.kind = PRIVATE_BUMP_ORCHARD_RECIPIENT;
            wire_recipient.destination.assign(recipient.private_raw_address->begin(), recipient.private_raw_address->end());
        } else {
            wire_recipient.kind = PRIVATE_BUMP_TRANSPARENT_RECIPIENT;
            const std::string address{EncodeDestination(recipient.dest)};
            wire_recipient.destination.assign(address.begin(), address.end());
        }
        wire.recipients.push_back(std::move(wire_recipient));
    }
    DataStream stream;
    stream << wire;
    std::vector<unsigned char> encoded{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
    if (!stream.empty()) memory_cleanse(stream.data(), stream.size());
    return encoded;
}

util::Result<void> StorePrivateBumpRecipe(const CWallet& wallet,
                                          const uint256& txid,
                                          mapValue_t& map_value,
                                          const PrivateBumpRecipe& recipe)
{
    PrivateBumpEnvelope envelope;
    envelope.payload = EncodePrivateBumpRecipe(txid, recipe);
    if (wallet.IsCrypted()) {
        if (wallet.IsLocked()) {
            Cleanse(envelope.payload);
            return util::Error{Untranslated("Wallet is locked; private fee-bump metadata cannot be saved.")};
        }
        envelope.protection = PRIVATE_BUMP_ENCRYPTED;
        util::Result<std::vector<unsigned char>> encrypted{util::Error{Untranslated("Unable to access the wallet encryption key.")}};
        wallet.WithEncryptionKey([&](const CKeyingMaterial& master_key) {
            encrypted = EncryptPrivateBumpPayload(master_key, txid, envelope.payload, envelope.tag);
            return static_cast<bool>(encrypted);
        });
        Cleanse(envelope.payload);
        if (!encrypted) return util::Error{util::ErrorString(encrypted)};
        envelope.payload = std::move(*encrypted);
    }
    EraseUnsupportedPrivateBumpMetadata(map_value);
    map_value[std::string{PRIVATE_BUMP_RECIPE_KEY}] = EncodePrivateBumpEnvelope(envelope);
    Cleanse(envelope.payload);
    return {};
}
} // namespace

//! Check whether transaction has descendant in wallet or mempool, or has been
//! mined, or conflicts with a mined transaction. Return a feebumper::Result.
static feebumper::Result PreconditionChecks(const CWallet& wallet, const CWalletTx& wtx, bool require_mine, std::vector<bilingual_str>& errors) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (wallet.HasWalletSpend(wtx.tx)) {
        errors.push_back(Untranslated("Transaction has descendants in the wallet"));
        return feebumper::Result::INVALID_PARAMETER;
    }

    {
        if (wallet.chain().hasDescendantsInMempool(wtx.GetHash())) {
            errors.push_back(Untranslated("Transaction has descendants in the mempool"));
            return feebumper::Result::INVALID_PARAMETER;
        }
    }

    if (wallet.GetTxDepthInMainChain(wtx) != 0) {
        errors.push_back(Untranslated("Transaction has been mined, or is conflicted with a mined transaction"));
        return feebumper::Result::WALLET_ERROR;
    }

    if (!SignalsOptInRBF(*wtx.tx) && wtx.tx->nVersion != 3) {
        errors.push_back(Untranslated("Transaction is not BIP 125 replaceable"));
        return feebumper::Result::WALLET_ERROR;
    }

    if (wtx.mapValue.count("replaced_by_txid")) {
        errors.push_back(strprintf(Untranslated("Cannot bump transaction %s which was already bumped by transaction %s"), wtx.GetHash().ToString(), wtx.mapValue.at("replaced_by_txid")));
        return feebumper::Result::WALLET_ERROR;
    }

    if (require_mine) {
        // check that original tx consists entirely of our inputs
        // if not, we can't bump the fee, because the wallet has no way of knowing the value of the other inputs (thus the fee)
        isminefilter filter = wallet.GetLegacyScriptPubKeyMan() && wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) ? ISMINE_WATCH_ONLY : ISMINE_SPENDABLE;
        if (!AllInputsMine(wallet, *wtx.tx, filter)) {
            errors.push_back(Untranslated("Transaction contains inputs that don't belong to this wallet"));
            return feebumper::Result::WALLET_ERROR;
        }
    }

    return feebumper::Result::OK;
}

//! Check if the user provided a valid feeRate
static feebumper::Result CheckFeeRate(const CWallet& wallet, const CMutableTransaction& mtx, const CFeeRate& newFeerate, const int64_t maxTxSize, CAmount old_fee, std::vector<bilingual_str>& errors)
{
    // check that fee rate is higher than mempool's minimum fee
    // (no point in bumping fee if we know that the new tx won't be accepted to the mempool)
    // This may occur if the user set fee_rate or paytxfee too low, if fallbackfee is too low, or, perhaps,
    // in a rare situation where the mempool minimum fee increased significantly since the fee estimation just a
    // moment earlier. In this case, we report an error to the user, who may adjust the fee.
    CFeeRate minMempoolFeeRate = wallet.chain().mempoolMinFee();

    if (newFeerate.GetFeePerK() < minMempoolFeeRate.GetFeePerK()) {
        errors.push_back(strprintf(
            Untranslated("New fee rate (%s) is lower than the minimum fee rate (%s) to get into the mempool -- "),
            FormatMoney(newFeerate.GetFeePerK()),
            FormatMoney(minMempoolFeeRate.GetFeePerK())));
        return feebumper::Result::WALLET_ERROR;
    }

    std::vector<COutPoint> reused_inputs;
    reused_inputs.reserve(mtx.vin.size());
    for (const CTxIn& txin : mtx.vin) {
        reused_inputs.push_back(txin.prevout);
    }

    std::optional<CAmount> combined_bump_fee = wallet.chain().calculateCombinedBumpFee(reused_inputs, newFeerate);
    if (!combined_bump_fee.has_value()) {
        errors.push_back(strprintf(Untranslated("Failed to calculate bump fees, because unconfirmed UTXOs depend on enormous cluster of unconfirmed transactions.")));
    }
    CAmount new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee.value();

    CFeeRate incrementalRelayFee = std::max(wallet.chain().relayIncrementalFee(), CFeeRate(WALLET_INCREMENTAL_RELAY_FEE));

    // Min total fee is old fee + relay fee
    CAmount minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize);

    if (new_total_fee < minTotalFee) {
        errors.push_back(strprintf(Untranslated("Insufficient total fee %s, must be at least %s (oldFee %s + incrementalFee %s)"),
            FormatMoney(new_total_fee), FormatMoney(minTotalFee), FormatMoney(old_fee), FormatMoney(incrementalRelayFee.GetFee(maxTxSize))));
        return feebumper::Result::INVALID_PARAMETER;
    }

    CAmount requiredFee = GetRequiredFee(wallet, maxTxSize);
    if (new_total_fee < requiredFee) {
        errors.push_back(strprintf(Untranslated("Insufficient total fee (cannot be less than required fee %s)"),
            FormatMoney(requiredFee)));
        return feebumper::Result::INVALID_PARAMETER;
    }

    // Check that in all cases the new fee doesn't violate maxTxFee
    const CAmount max_tx_fee = wallet.m_default_max_tx_fee;
    if (new_total_fee > max_tx_fee) {
        errors.push_back(strprintf(Untranslated("Specified or calculated fee %s is too high (cannot be higher than -maxtxfee %s)"),
            FormatMoney(new_total_fee), FormatMoney(max_tx_fee)));
        return feebumper::Result::WALLET_ERROR;
    }

    return feebumper::Result::OK;
}

static CFeeRate EstimateFeeRate(const CWallet& wallet, const CWalletTx& wtx, const CAmount old_fee, const CCoinControl& coin_control)
{
    // Get the fee rate of the original transaction. This is calculated from
    // the tx fee/vsize, so it may have been rounded down. Add 1 satoshi to the
    // result.
    int64_t txSize = GetVirtualTransactionSize(*(wtx.tx));
    CFeeRate feerate(old_fee, txSize);
    feerate += CFeeRate(1);

    // The node has a configurable incremental relay fee. Increment the fee by
    // the minimum of that and the wallet's conservative
    // WALLET_INCREMENTAL_RELAY_FEE value to future proof against changes to
    // network wide policy for incremental relay fee that our node may not be
    // aware of. This ensures we're over the required relay fee rate
    // (Rule 4).  The replacement tx will be at least as large as the
    // original tx, so the total fee will be greater (Rule 3)
    CFeeRate node_incremental_relay_fee = wallet.chain().relayIncrementalFee();
    CFeeRate wallet_incremental_relay_fee = CFeeRate(WALLET_INCREMENTAL_RELAY_FEE);
    feerate += std::max(node_incremental_relay_fee, wallet_incremental_relay_fee);

    // Fee rate must also be at least the wallet's GetMinimumFeeRate
    CFeeRate min_feerate(GetMinimumFeeRate(wallet, coin_control, /*feeCalc=*/nullptr));

    // Set the required fee rate for the replacement transaction in coin control.
    return std::max(feerate, min_feerate);
}

static util::Result<PrivateBumpRecipe> LoadPrivateBumpRecipe(const CWallet& wallet, const CWalletTx& wtx)
{
    const auto recipe_it = wtx.mapValue.find(std::string{PRIVATE_BUMP_RECIPE_KEY});
    if (recipe_it == wtx.mapValue.end()) {
        return util::Error{Untranslated("This private-bundle transaction does not contain wallet-local recipient metadata required for fee bumping.")};
    }
    auto envelope{DecodePrivateBumpEnvelope(recipe_it->second)};
    if (!envelope) return util::Error{util::ErrorString(envelope)};

    std::vector<unsigned char> plaintext;
    if (wallet.IsCrypted()) {
        if (envelope->protection != PRIVATE_BUMP_ENCRYPTED || wallet.IsLocked()) {
            return util::Error{Untranslated("Wallet is locked or private fee-bump metadata is not encrypted.")};
        }
        util::Result<std::vector<unsigned char>> decrypted{util::Error{Untranslated("Unable to access the wallet encryption key.")}};
        wallet.WithEncryptionKey([&](const CKeyingMaterial& master_key) {
            decrypted = DecryptPrivateBumpPayload(master_key, wtx.GetHash(), *envelope);
            return static_cast<bool>(decrypted);
        });
        if (!decrypted) return util::Error{util::ErrorString(decrypted)};
        plaintext = std::move(*decrypted);
    } else {
        if (envelope->protection != PRIVATE_BUMP_PLAINTEXT) {
            return util::Error{Untranslated("Private-bundle fee-bump metadata uses an unavailable encryption key.")};
        }
        plaintext = envelope->payload;
    }

    auto recipe{DecodePrivateBumpRecipe(plaintext, wtx.GetHash())};
    Cleanse(plaintext);
    if (!recipe) return util::Error{util::ErrorString(recipe)};

    if (recipe->source == CCoinControl::PrivateTxSource::PRIVATE_NOTES && !recipe->private_note_ids.empty()) {
        if (!wtx.tx->m_private_bundle) {
            return util::Error{Untranslated("Private-bundle fee-bump recipe references notes without a private bundle.")};
        }
        std::vector<uint256> original_note_ids;
        for (const auto& action : wtx.tx->m_private_bundle->effects.actions) {
            const auto note_it{std::find_if(wallet.mapPrivateNotes.begin(), wallet.mapPrivateNotes.end(),
                [&](const auto& item) { return !item.second.nullifier.IsNull() && item.second.nullifier == action.nullifier; })};
            if (note_it != wallet.mapPrivateNotes.end()) {
                original_note_ids.push_back(note_it->first);
            }
        }
        if (original_note_ids.size() != recipe->private_note_ids.size() ||
            std::any_of(recipe->private_note_ids.begin(), recipe->private_note_ids.end(), [&](const uint256& cmx) {
                return std::find(original_note_ids.begin(), original_note_ids.end(), cmx) == original_note_ids.end();
            })) {
            return util::Error{Untranslated("Private-bundle fee-bump recipe does not match the notes spent by the original transaction.")};
        }
    }
    return recipe;
}

util::Result<void> feebumper::AddPrivateBumpMetadata(const CWallet& wallet,
                                                     const uint256& txid,
                                                     mapValue_t& map_value,
                                                     const CCoinControl& coin_control,
                                                     const std::vector<CRecipient>& recipients,
                                                     const std::vector<uint256>& private_note_ids)
{
    LOCK(wallet.cs_wallet);
    PrivateBumpRecipe recipe;
    switch (coin_control.m_private_tx_source) {
    case CCoinControl::PrivateTxSource::TRANSPARENT_COINS:
        recipe.source = CCoinControl::PrivateTxSource::TRANSPARENT_COINS;
        break;
    case CCoinControl::PrivateTxSource::PRIVATE_NOTES:
        recipe.source = CCoinControl::PrivateTxSource::PRIVATE_NOTES;
        break;
    case CCoinControl::PrivateTxSource::AUTO:
        recipe.source = std::any_of(recipients.begin(), recipients.end(), [](const CRecipient& recipient) {
            return recipient.IsPrivate();
        }) ? CCoinControl::PrivateTxSource::TRANSPARENT_COINS : CCoinControl::PrivateTxSource::PRIVATE_NOTES;
        break;
    }
    recipe.recipients = recipients;
    recipe.private_note_ids = private_note_ids;
    std::vector<unsigned char> payload{EncodePrivateBumpRecipe(txid, recipe)};
    auto valid{DecodePrivateBumpRecipe(payload, txid)};
    Cleanse(payload);
    if (!valid) return util::Error{util::ErrorString(valid)};
    return StorePrivateBumpRecipe(wallet, txid, map_value, recipe);
}

util::Result<bool> feebumper::EncryptPrivateBumpMetadata(const CKeyingMaterial& master_key,
                                                         const uint256& txid,
                                                         mapValue_t& map_value)
{
    mapValue_t updated{map_value};
    bool changed{false};
    for (const std::string_view key : {PRIVATE_BUMP_SOURCE_KEY, PRIVATE_BUMP_RECIPIENTS_KEY, PRIVATE_BUMP_NOTES_KEY}) {
        changed |= updated.erase(std::string{key}) != 0;
    }
    const auto recipe_it{updated.find(std::string{PRIVATE_BUMP_RECIPE_KEY})};
    if (recipe_it == updated.end()) {
        if (changed) map_value = std::move(updated);
        return changed;
    }

    auto envelope{DecodePrivateBumpEnvelope(recipe_it->second)};
    if (!envelope || envelope->protection != PRIVATE_BUMP_PLAINTEXT) {
        updated.erase(recipe_it);
        map_value = std::move(updated);
        return true;
    }
    auto recipe{DecodePrivateBumpRecipe(envelope->payload, txid)};
    if (!recipe) {
        Cleanse(envelope->payload);
        updated.erase(recipe_it);
        map_value = std::move(updated);
        return true;
    }
    PrivateBumpEnvelope protected_envelope;
    protected_envelope.protection = PRIVATE_BUMP_ENCRYPTED;
    auto encrypted{EncryptPrivateBumpPayload(master_key, txid, envelope->payload, protected_envelope.tag)};
    Cleanse(envelope->payload);
    if (!encrypted) return util::Error{util::ErrorString(encrypted)};
    protected_envelope.payload = std::move(*encrypted);
    recipe_it->second = EncodePrivateBumpEnvelope(protected_envelope);
    Cleanse(protected_envelope.payload);
    map_value = std::move(updated);
    return true;
}

util::Result<void> feebumper::RebindPrivateBumpMetadata(const CWallet& wallet,
                                                        const CWalletTx& old_wtx,
                                                        const uint256& replacement_txid,
                                                        mapValue_t& map_value)
{
    LOCK(wallet.cs_wallet);
    auto recipe{LoadPrivateBumpRecipe(wallet, old_wtx)};
    if (!recipe) return util::Error{util::ErrorString(recipe)};
    mapValue_t rebound{map_value};
    rebound.erase(std::string{PRIVATE_BUMP_RECIPE_KEY});
    auto stored{StorePrivateBumpRecipe(wallet, replacement_txid, rebound, *recipe)};
    if (!stored) return util::Error{util::ErrorString(stored)};
    map_value = std::move(rebound);
    return {};
}

static feebumper::Result CreatePrivateRateBumpTransaction(CWallet& wallet,
                                                          const CWalletTx& wtx,
                                                          const CCoinControl& coin_control,
                                                          std::vector<bilingual_str>& errors,
                                                          CAmount& old_fee,
                                                          CAmount& new_fee,
                                                          CMutableTransaction& mtx,
                                                          bool require_mine,
                                                          const std::vector<CTxOut>& outputs,
                                                          std::optional<uint32_t> original_change_index,
                                                          std::vector<PSBTProprietary>* private_psbt_records) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (!outputs.empty() || original_change_index.has_value()) {
        errors.push_back(Untranslated("Private-bundle fee bumping rebuilds the original private recipient set; custom replacement outputs and original_change_index are not supported."));
        return feebumper::Result::INVALID_PARAMETER;
    }

    const auto recipe_res = LoadPrivateBumpRecipe(wallet, wtx);
    if (!recipe_res) {
        errors.push_back(util::ErrorString(recipe_res));
        return feebumper::Result::WALLET_ERROR;
    }
    const PrivateBumpRecipe& recipe = *recipe_res;

    feebumper::Result result = PreconditionChecks(wallet, wtx, /*require_mine=*/false, errors);
    if (result != feebumper::Result::OK) {
        return result;
    }

    old_fee = CachedTxGetFee(wallet, wtx, ISMINE_SPENDABLE);

    CCoinControl new_coin_control(coin_control);
    new_coin_control.m_private_tx_source = recipe.source;
    new_coin_control.m_min_depth = 1;
    new_coin_control.m_signal_bip125_rbf = true;
    if (!new_coin_control.m_feerate) {
        new_coin_control.m_feerate = EstimateFeeRate(wallet, wtx, old_fee, new_coin_control);
    }

    if (recipe.source == CCoinControl::PrivateTxSource::PRIVATE_NOTES) {
        if (!wtx.tx->m_private_bundle) {
            errors.push_back(Untranslated("Private-bundle fee-bump metadata requests private-note funding but the transaction has no private bundle."));
            return feebumper::Result::WALLET_ERROR;
        }
        size_t selected_notes{0};
        if (!recipe.private_note_ids.empty()) {
            for (const uint256& cmx : recipe.private_note_ids) {
                if (!wallet.mapPrivateNotes.contains(cmx)) {
                    errors.push_back(Untranslated("The wallet cannot find the private note spent by the transaction being bumped."));
                    return feebumper::Result::WALLET_ERROR;
                }
                new_coin_control.SelectPrivateNote(cmx);
                ++selected_notes;
            }
        } else {
            for (const auto& action : wtx.tx->m_private_bundle->effects.actions) {
                if (action.nullifier.IsNull()) continue;
                bool selected{false};
                for (const auto& [cmx, note] : wallet.mapPrivateNotes) {
                    if (note.nullifier == action.nullifier) {
                        new_coin_control.SelectPrivateNote(cmx);
                        selected = true;
                        ++selected_notes;
                        break;
                    }
                }
                if (!selected) {
                    errors.push_back(Untranslated("The wallet cannot find the private note spent by the transaction being bumped."));
                    return feebumper::Result::WALLET_ERROR;
                }
            }
        }
        if (selected_notes == 0) {
            errors.push_back(Untranslated("Private-bundle fee-bump metadata requests private-note funding but the transaction spends no private note."));
            return feebumper::Result::WALLET_ERROR;
        }
        new_coin_control.m_allow_other_inputs = false;
        new_coin_control.m_allow_spent_private_note_replacement = true;
    } else {
        std::map<COutPoint, Coin> coins;
        for (const CTxIn& txin : wtx.tx->vin) {
            coins[txin.prevout];
        }
        wallet.chain().findCoins(coins);
        for (const CTxIn& txin : wtx.tx->vin) {
            const Coin& coin = coins.at(txin.prevout);
            if (coin.out.IsNull()) {
                errors.push_back(Untranslated(strprintf("%s:%u is already spent", txin.prevout.hash.GetHex(), txin.prevout.n)));
                return feebumper::Result::MISC_ERROR;
            }
            PreselectedInput& preset_txin = new_coin_control.Select(txin.prevout);
            if (!wallet.IsMine(txin.prevout)) {
                preset_txin.SetTxOut(coin.out);
            }
        }
        new_coin_control.m_allow_other_inputs = true;
    }

    auto txr_res = CreateTransaction(wallet, recipe.recipients, /*change_pos=*/std::nullopt, new_coin_control, require_mine);
    if (!txr_res) {
        errors.push_back(Untranslated("Unable to create private fee-bump transaction.") + Untranslated(" ") + util::ErrorString(txr_res));
        return feebumper::Result::WALLET_ERROR;
    }
    const CreatedTransactionResult& txr = *txr_res;
    new_fee = txr.fee;

    const CFeeRate incrementalRelayFee = std::max(wallet.chain().relayIncrementalFee(), CFeeRate(WALLET_INCREMENTAL_RELAY_FEE));
    const CAmount min_total_fee = old_fee + incrementalRelayFee.GetFee(GetVirtualTransactionSize(*txr.tx));
    if (new_fee < min_total_fee) {
        errors.push_back(strprintf(Untranslated("Insufficient total fee %s, must be at least %s (oldFee %s + incrementalFee %s)"),
            FormatMoney(new_fee), FormatMoney(min_total_fee), FormatMoney(old_fee), FormatMoney(incrementalRelayFee.GetFee(GetVirtualTransactionSize(*txr.tx)))));
        return feebumper::Result::INVALID_PARAMETER;
    }
    if (new_fee > wallet.m_default_max_tx_fee) {
        errors.push_back(strprintf(Untranslated("Specified or calculated fee %s is too high (cannot be higher than -maxtxfee %s)"),
            FormatMoney(new_fee), FormatMoney(wallet.m_default_max_tx_fee)));
        return feebumper::Result::WALLET_ERROR;
    }

    mtx = CMutableTransaction(*txr.tx);
    if (private_psbt_records) {
        *private_psbt_records = txr.private_psbt_records;
    }
    return feebumper::Result::OK;
}

namespace feebumper {

bool TransactionCanBeBumped(const CWallet& wallet, const uint256& txid)
{
    LOCK(wallet.cs_wallet);
    const CWalletTx* wtx = wallet.GetWalletTx(txid);
    if (wtx == nullptr) return false;

    std::vector<bilingual_str> errors_dummy;
    if (wtx->tx->HasPrivateBundle()) {
        if (wallet.IsLocked()) {
            // Eligibility can be displayed while locked. Replacement creation
            // authenticates and decrypts the recipe after the wallet is unlocked.
            const auto metadata = wtx->mapValue.find(std::string{PRIVATE_BUMP_RECIPE_KEY});
            if (metadata == wtx->mapValue.end()) return false;
            const auto envelope = DecodePrivateBumpEnvelope(metadata->second);
            if (!envelope || envelope->protection != PRIVATE_BUMP_ENCRYPTED) return false;
        } else if (!LoadPrivateBumpRecipe(wallet, *wtx)) {
            return false;
        }
    }
    feebumper::Result res = PreconditionChecks(wallet, *wtx, /*require_mine=*/!wtx->tx->HasPrivateBundle(), errors_dummy);
    return res == feebumper::Result::OK;
}

Result CreateRateBumpTransaction(CWallet& wallet, const uint256& txid, const CCoinControl& coin_control, std::vector<bilingual_str>& errors,
                                 CAmount& old_fee, CAmount& new_fee, CMutableTransaction& mtx, bool require_mine, const std::vector<CTxOut>& outputs,
                                 std::optional<uint32_t> original_change_index, std::vector<PSBTProprietary>* private_psbt_records)
{
    // For now, cannot specify both new outputs to use and an output index to send change
    if (!outputs.empty() && original_change_index.has_value()) {
        errors.push_back(Untranslated("The options 'outputs' and 'original_change_index' are incompatible. You can only either specify a new set of outputs, or designate a change output to be recycled."));
        return Result::INVALID_PARAMETER;
    }

    // We are going to modify coin control later, copy to reuse
    CCoinControl new_coin_control(coin_control);

    LOCK(wallet.cs_wallet);
    errors.clear();
    auto it = wallet.mapWallet.find(txid);
    if (it == wallet.mapWallet.end()) {
        errors.push_back(Untranslated("Invalid or non-wallet transaction id"));
        return Result::INVALID_ADDRESS_OR_KEY;
    }
    const CWalletTx& wtx = it->second;
    if (wtx.tx->HasPrivateBundle()) {
        return CreatePrivateRateBumpTransaction(wallet, wtx, coin_control, errors, old_fee, new_fee, mtx, require_mine, outputs, original_change_index, private_psbt_records);
    }

    // Make sure that original_change_index is valid
    if (original_change_index.has_value() && original_change_index.value() >= wtx.tx->vout.size()) {
        errors.push_back(Untranslated("Change position is out of range"));
        return Result::INVALID_PARAMETER;
    }

    // Retrieve all of the UTXOs and add them to coin control
    // While we're here, calculate the input amount
    std::map<COutPoint, Coin> coins;
    CAmount input_value = 0;
    std::vector<CTxOut> spent_outputs;
    for (const CTxIn& txin : wtx.tx->vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    wallet.chain().findCoins(coins);
    for (const CTxIn& txin : wtx.tx->vin) {
        const Coin& coin = coins.at(txin.prevout);
        if (coin.out.IsNull()) {
            errors.push_back(Untranslated(strprintf("%s:%u is already spent", txin.prevout.hash.GetHex(), txin.prevout.n)));
            return Result::MISC_ERROR;
        }
        PreselectedInput& preset_txin = new_coin_control.Select(txin.prevout);
        if (!wallet.IsMine(txin.prevout)) {
            preset_txin.SetTxOut(coin.out);
        }
        input_value += coin.out.nValue;
        spent_outputs.push_back(coin.out);
    }

    // Figure out if we need to compute the input weight, and do so if necessary
    PrecomputedTransactionData txdata;
    txdata.Init(*wtx.tx, std::move(spent_outputs), /* force=*/ true);
    for (unsigned int i = 0; i < wtx.tx->vin.size(); ++i) {
        const CTxIn& txin = wtx.tx->vin.at(i);
        const Coin& coin = coins.at(txin.prevout);

        if (new_coin_control.IsExternalSelected(txin.prevout)) {
            // For external inputs, we estimate the size using the size of this input
            int64_t input_weight = GetTransactionInputWeight(txin);
            // Because signatures can have different sizes, we need to figure out all of the
            // signature sizes and replace them with the max sized signature.
            // In order to do this, we verify the script with a special SignatureChecker which
            // will observe the signatures verified and record their sizes.
            SignatureWeights weights;
            TransactionSignatureChecker tx_checker(wtx.tx.get(), i, coin.out.nValue, txdata, MissingDataBehavior::FAIL);
            SignatureWeightChecker size_checker(weights, tx_checker);
            VerifyScript(txin.scriptSig, coin.out.scriptPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, size_checker);
            // Add the difference between max and current to input_weight so that it represents the largest the input could be
            input_weight += weights.GetWeightDiffToMax();
            new_coin_control.SetInputWeight(txin.prevout, input_weight);
        }
    }

    Result result = PreconditionChecks(wallet, wtx, require_mine, errors);
    if (result != Result::OK) {
        return result;
    }

    // Calculate the old output amount.
    CAmount output_value = 0;
    for (const auto& old_output : wtx.tx->vout) {
        output_value += old_output.nValue;
    }

    old_fee = input_value - output_value;

    // Fill in recipients (and preserve a single change key if there
    // is one). If outputs vector is non-empty, replace original
    // outputs with its contents, otherwise use original outputs.
    std::vector<CRecipient> recipients;
    CAmount new_outputs_value = 0;
    const auto& txouts = outputs.empty() ? wtx.tx->vout : outputs;
    for (size_t i = 0; i < txouts.size(); ++i) {
        const CTxOut& output = txouts.at(i);
        CTxDestination dest;
        ExtractDestination(output.scriptPubKey, dest);
        if (original_change_index.has_value() ?  original_change_index.value() == i : OutputIsChange(wallet, output)) {
            new_coin_control.destChange = dest;
        } else {
            CRecipient recipient = {dest, output.nValue, false};
            recipients.push_back(recipient);
        }
        new_outputs_value += output.nValue;
    }

    // If no recipients, means that we are sending coins to a change address
    if (recipients.empty()) {
        // Just as a sanity check, ensure that the change address exist
        if (std::get_if<CNoDestination>(&new_coin_control.destChange)) {
            errors.emplace_back(Untranslated("Unable to create transaction. Transaction must have at least one recipient"));
            return Result::INVALID_PARAMETER;
        }

        // Add change as recipient with SFFO flag enabled, so fees are deduced from it.
        // If the output differs from the original tx output (because the user customized it) a new change output will be created.
        recipients.emplace_back(CRecipient{new_coin_control.destChange, new_outputs_value, /*fSubtractFeeFromAmount=*/true});
        new_coin_control.destChange = CNoDestination();
    }

    if (coin_control.m_feerate) {
        // The user provided a feeRate argument.
        // We calculate this here to avoid compiler warning on the cs_wallet lock
        // We need to make a temporary transaction with no input witnesses as the dummy signer expects them to be empty for external inputs
        CMutableTransaction temp_mtx{*wtx.tx};
        for (auto& txin : temp_mtx.vin) {
            txin.scriptSig.clear();
            txin.scriptWitness.SetNull();
        }
        temp_mtx.vout = txouts;
        const int64_t maxTxSize{CalculateMaximumSignedTxSize(CTransaction(temp_mtx), &wallet, &new_coin_control).vsize};
        Result res = CheckFeeRate(wallet, temp_mtx, *new_coin_control.m_feerate, maxTxSize, old_fee, errors);
        if (res != Result::OK) {
            return res;
        }
    } else {
        // The user did not provide a feeRate argument
        new_coin_control.m_feerate = EstimateFeeRate(wallet, wtx, old_fee, new_coin_control);
    }

    // Fill in required inputs we are double-spending(all of them)
    // N.B.: bip125 doesn't require all the inputs in the replaced transaction to be
    // used in the replacement transaction, but it's very important for wallets to make
    // sure that happens. If not, it would be possible to bump a transaction A twice to
    // A2 and A3 where A2 and A3 don't conflict (or alternatively bump A to A2 and A2
    // to A3 where A and A3 don't conflict). If both later get confirmed then the sender
    // has accidentally double paid.
    for (const auto& inputs : wtx.tx->vin) {
        new_coin_control.Select(COutPoint(inputs.prevout));
    }
    new_coin_control.m_allow_other_inputs = true;

    // We cannot source new unconfirmed inputs(bip125 rule 2)
    new_coin_control.m_min_depth = 1;

    auto res = CreateTransaction(wallet, recipients, /*change_pos=*/std::nullopt, new_coin_control, false);
    if (!res) {
        errors.push_back(Untranslated("Unable to create transaction.") + Untranslated(" ") + util::ErrorString(res));
        return Result::WALLET_ERROR;
    }

    const auto& txr = *res;
    // Write back new fee if successful
    new_fee = txr.fee;

    // Write back transaction
    mtx = CMutableTransaction(*txr.tx);

    return Result::OK;
}

bool SignTransaction(CWallet& wallet, CMutableTransaction& mtx) {
    LOCK(wallet.cs_wallet);

    if (wallet.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        // Make a blank psbt
        PartiallySignedTransaction psbtx(mtx);

        // First fill transaction with our data without signing,
        // so external signers are not asked to sign more than once.
        bool complete;
        wallet.FillPSBT(psbtx, complete, SIGHASH_ALL, false /* sign */, true /* bip32derivs */);
        const TransactionError err = wallet.FillPSBT(psbtx, complete, SIGHASH_ALL, true /* sign */, false  /* bip32derivs */);
        if (err != TransactionError::OK) return false;
        complete = FinalizeAndExtractPSBT(psbtx, mtx);
        return complete;
    } else {
        return wallet.SignTransaction(mtx);
    }
}

Result CommitTransaction(CWallet& wallet, const uint256& txid, CMutableTransaction&& mtx, std::vector<bilingual_str>& errors, uint256& bumped_txid)
{
    LOCK(wallet.cs_wallet);
    if (!errors.empty()) {
        return Result::MISC_ERROR;
    }
    auto it = txid.IsNull() ? wallet.mapWallet.end() : wallet.mapWallet.find(txid);
    if (it == wallet.mapWallet.end()) {
        errors.push_back(Untranslated("Invalid or non-wallet transaction id"));
        return Result::MISC_ERROR;
    }
    const CWalletTx& oldWtx = it->second;

    // make sure the transaction still has no descendants and hasn't been mined in the meantime
    Result result = PreconditionChecks(wallet, oldWtx, /* require_mine=*/ false, errors);
    if (result != Result::OK) {
        return result;
    }

    // commit/broadcast the tx
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    mapValue_t mapValue = oldWtx.mapValue;
    if (oldWtx.tx->HasPrivateBundle()) {
        auto rebound{RebindPrivateBumpMetadata(wallet, oldWtx, tx->GetHash(), mapValue)};
        if (!rebound) {
            errors.push_back(util::ErrorString(rebound));
            return Result::WALLET_ERROR;
        }
    }
    mapValue["replaces_txid"] = oldWtx.GetHash().ToString();

    auto commit_result = wallet.CommitTransaction(tx, std::move(mapValue), oldWtx.vOrderForm);
    if (!commit_result) {
        errors.push_back(util::ErrorString(commit_result));
        return Result::MISC_ERROR;
    }

    // mark the original tx as bumped
    bumped_txid = tx->GetHash();
    if (!wallet.MarkReplaced(oldWtx.GetHash(), bumped_txid)) {
        errors.push_back(Untranslated("Created new bumpfee transaction but could not mark the original transaction as replaced"));
    }
    return Result::OK;
}

} // namespace feebumper
} // namespace wallet
