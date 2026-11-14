// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/bip39_seed.h>

#include <crypto/common.h>
#include <crypto/hmac_sha256.h>
#include <crypto/sha256.h>
#include <random.h>
#include <support/cleanse.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <vector>

namespace wallet {
namespace {

static constexpr size_t DERIVED_SEED_SIZE{64};
static constexpr size_t ENCRYPTED_DERIVED_SEED_SIZE{80};
static constexpr size_t INTEGRITY_SIZE{CHMAC_SHA256::OUTPUT_SIZE};

static constexpr std::string_view ENCRYPTION_KEY_DOMAIN{"nito/bip39-derived-seed/encryption-key/v1"};
static constexpr std::string_view MAC_KEY_DOMAIN{"nito/bip39-derived-seed/mac-key/v1"};
static constexpr std::string_view ENVELOPE_DOMAIN{"nito/bip39-derived-seed/envelope/v1"};
static constexpr std::string_view CHECKSUM_DOMAIN{"nito/bip39-derived-seed/plaintext-checksum/v1"};

template <typename ByteVector>
void Cleanse(ByteVector& value)
{
    if (!value.empty()) memory_cleanse(value.data(), value.size() * sizeof(typename ByteVector::value_type));
    value.clear();
}

bool IsSupportedScope(uint8_t scope)
{
    return scope == static_cast<uint8_t>(PrivateSeedScope::FULL_WALLET) ||
           scope == static_cast<uint8_t>(PrivateSeedScope::ORCHARD_ONLY);
}

template <typename Hasher>
void WriteRecordFields(Hasher& hasher, const CBIP39DerivedSeedRecord& record)
{
    std::array<unsigned char, sizeof(uint64_t)> payload_size{};
    WriteLE64(payload_size.data(), record.payload.size());
    hasher.Write(&record.version, sizeof(record.version))
        .Write(&record.protection, sizeof(record.protection))
        .Write(record.hd_seed_id.begin(), record.hd_seed_id.size())
        .Write(&record.seed_scope, sizeof(record.seed_scope))
        .Write(&record.flags, sizeof(record.flags))
        .Write(record.iv.begin(), record.iv.size())
        .Write(payload_size.data(), payload_size.size())
        .Write(record.payload.data(), record.payload.size());
}

uint256 PlaintextChecksum(const CBIP39DerivedSeedRecord& record)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> checksum{};
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(CHECKSUM_DOMAIN.data()), CHECKSUM_DOMAIN.size());
    WriteRecordFields(hasher, record);
    hasher.Finalize(checksum.data());

    uint256 result;
    std::copy(checksum.begin(), checksum.end(), result.begin());
    memory_cleanse(checksum.data(), checksum.size());
    return result;
}

CKeyingMaterial DeriveEnvelopeKey(const CKeyingMaterial& master_key, std::string_view domain)
{
    CKeyingMaterial key(CHMAC_SHA256::OUTPUT_SIZE);
    CHMAC_SHA256(master_key.data(), master_key.size())
        .Write(reinterpret_cast<const unsigned char*>(domain.data()), domain.size())
        .Finalize(key.data());
    return key;
}

std::array<unsigned char, INTEGRITY_SIZE> EnvelopeTag(
    const CBIP39DerivedSeedRecord& record,
    const CKeyingMaterial& mac_key)
{
    std::array<unsigned char, INTEGRITY_SIZE> tag{};
    CHMAC_SHA256 hasher(mac_key.data(), mac_key.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(ENVELOPE_DOMAIN.data()), ENVELOPE_DOMAIN.size());
    WriteRecordFields(hasher, record);
    hasher.Finalize(tag.data());
    return tag;
}

std::array<unsigned char, INTEGRITY_SIZE> IntegrityBytes(const uint256& integrity)
{
    std::array<unsigned char, INTEGRITY_SIZE> result{};
    std::copy(integrity.begin(), integrity.end(), result.begin());
    return result;
}

void SetIntegrity(CBIP39DerivedSeedRecord& record, const std::array<unsigned char, INTEGRITY_SIZE>& integrity)
{
    std::copy(integrity.begin(), integrity.end(), record.integrity.begin());
}

util::Result<void> ValidateShape(const CBIP39DerivedSeedRecord& record)
{
    if (record.version != BIP39_DERIVED_SEED_RECORD_VERSION) {
        return util::Error{Untranslated("Unsupported BIP39 derived-seed record version.")};
    }
    if (record.protection != BIP39_DERIVED_SEED_CLEAR && record.protection != BIP39_DERIVED_SEED_ENCRYPTED) {
        return util::Error{Untranslated("BIP39 derived-seed record has an invalid protection mode.")};
    }
    if (record.hd_seed_id.IsNull()) {
        return util::Error{Untranslated("BIP39 derived-seed record is not bound to a mnemonic entropy key.")};
    }
    if (!IsSupportedScope(record.seed_scope)) {
        return util::Error{Untranslated("BIP39 derived-seed record has an invalid seed scope.")};
    }
    if ((record.flags & ~BIP39_DERIVED_SEED_KNOWN_FLAGS) != 0) {
        return util::Error{Untranslated("BIP39 derived-seed record contains unknown flags.")};
    }
    if (record.protection == BIP39_DERIVED_SEED_CLEAR) {
        if (!record.iv.IsNull() || record.payload.size() != DERIVED_SEED_SIZE) {
            return util::Error{Untranslated("Clear BIP39 derived-seed record is malformed.")};
        }
    } else if (record.iv.IsNull() || record.payload.size() != ENCRYPTED_DERIVED_SEED_SIZE) {
        return util::Error{Untranslated("Encrypted BIP39 derived-seed record is malformed.")};
    }
    return {};
}

} // namespace

util::Result<void> ValidateBIP39DerivedSeedRecord(const CBIP39DerivedSeedRecord& record)
{
    auto shape{ValidateShape(record)};
    if (!shape) return util::Error{util::ErrorString(shape)};

    if (record.protection == BIP39_DERIVED_SEED_CLEAR &&
        PlaintextChecksum(record) != record.integrity) {
        return util::Error{Untranslated("BIP39 derived-seed record checksum does not match.")};
    }
    return {};
}

util::Result<CBIP39DerivedSeedRecord> CreateBIP39DerivedSeedRecord(
    const CKeyID& hd_seed_id,
    PrivateSeedScope seed_scope,
    bool passphrase_enabled,
    const BIP39Seed& seed)
{
    if (hd_seed_id.IsNull() || !IsSupportedScope(static_cast<uint8_t>(seed_scope))) {
        return util::Error{Untranslated("Cannot create a BIP39 derived-seed record without a valid mnemonic key and seed scope.")};
    }

    CBIP39DerivedSeedRecord record;
    record.hd_seed_id = hd_seed_id;
    record.seed_scope = static_cast<uint8_t>(seed_scope);
    record.flags = passphrase_enabled ? BIP39_DERIVED_SEED_FLAG_PASSPHRASE : 0;
    record.payload.assign(
        reinterpret_cast<const unsigned char*>(seed.data()),
        reinterpret_cast<const unsigned char*>(seed.data()) + seed.size());
    record.integrity = PlaintextChecksum(record);

    auto valid{ValidateBIP39DerivedSeedRecord(record)};
    if (!valid) {
        Cleanse(record.payload);
        return util::Error{util::ErrorString(valid)};
    }
    return record;
}

util::Result<CBIP39DerivedSeedRecord> EncryptBIP39DerivedSeedRecord(
    const CBIP39DerivedSeedRecord& clear_record,
    const CKeyingMaterial& master_key)
{
    auto valid{ValidateBIP39DerivedSeedRecord(clear_record)};
    if (!valid || clear_record.protection != BIP39_DERIVED_SEED_CLEAR) {
        return util::Error{Untranslated("Only a valid clear BIP39 derived-seed record can be encrypted.")};
    }
    if (master_key.size() != WALLET_CRYPTO_KEY_SIZE) {
        return util::Error{Untranslated("Wallet encryption key has an invalid size.")};
    }

    CBIP39DerivedSeedRecord encrypted;
    encrypted.protection = BIP39_DERIVED_SEED_ENCRYPTED;
    encrypted.hd_seed_id = clear_record.hd_seed_id;
    encrypted.seed_scope = clear_record.seed_scope;
    encrypted.flags = clear_record.flags;
    GetStrongRandBytes(Span<unsigned char>{encrypted.iv.begin(), encrypted.iv.size()});

    CKeyingMaterial encryption_key{DeriveEnvelopeKey(master_key, ENCRYPTION_KEY_DOMAIN)};
    CKeyingMaterial plaintext(clear_record.payload.begin(), clear_record.payload.end());
    std::vector<unsigned char> ciphertext;
    const bool encrypted_ok{EncryptSecret(encryption_key, plaintext, encrypted.iv, ciphertext)};
    Cleanse(plaintext);
    Cleanse(encryption_key);
    if (!encrypted_ok || ciphertext.size() != ENCRYPTED_DERIVED_SEED_SIZE) {
        Cleanse(ciphertext);
        Cleanse(encrypted.payload);
        return util::Error{Untranslated("Unable to encrypt the BIP39 derived-seed record.")};
    }
    encrypted.payload.assign(ciphertext.begin(), ciphertext.end());
    Cleanse(ciphertext);

    CKeyingMaterial mac_key{DeriveEnvelopeKey(master_key, MAC_KEY_DOMAIN)};
    std::array<unsigned char, INTEGRITY_SIZE> tag{EnvelopeTag(encrypted, mac_key)};
    Cleanse(mac_key);
    SetIntegrity(encrypted, tag);
    memory_cleanse(tag.data(), tag.size());

    auto encrypted_valid{ValidateBIP39DerivedSeedRecord(encrypted)};
    if (!encrypted_valid) {
        Cleanse(encrypted.payload);
        return util::Error{util::ErrorString(encrypted_valid)};
    }
    return encrypted;
}

util::Result<CKeyingMaterial> DecryptBIP39DerivedSeedRecord(
    const CBIP39DerivedSeedRecord& encrypted_record,
    const CKeyingMaterial& master_key)
{
    auto valid{ValidateBIP39DerivedSeedRecord(encrypted_record)};
    if (!valid || encrypted_record.protection != BIP39_DERIVED_SEED_ENCRYPTED) {
        return util::Error{Untranslated("BIP39 derived-seed record is not a valid encrypted record.")};
    }
    if (master_key.size() != WALLET_CRYPTO_KEY_SIZE) {
        return util::Error{Untranslated("Wallet encryption key has an invalid size.")};
    }

    CKeyingMaterial mac_key{DeriveEnvelopeKey(master_key, MAC_KEY_DOMAIN)};
    std::array<unsigned char, INTEGRITY_SIZE> expected_tag{EnvelopeTag(encrypted_record, mac_key)};
    Cleanse(mac_key);
    std::array<unsigned char, INTEGRITY_SIZE> stored_tag{IntegrityBytes(encrypted_record.integrity)};
    const bool authenticated{TimingResistantEqual(expected_tag, stored_tag)};
    memory_cleanse(expected_tag.data(), expected_tag.size());
    memory_cleanse(stored_tag.data(), stored_tag.size());
    if (!authenticated) {
        return util::Error{Untranslated("BIP39 derived-seed record authentication failed.")};
    }

    CKeyingMaterial encryption_key{DeriveEnvelopeKey(master_key, ENCRYPTION_KEY_DOMAIN)};
    const std::vector<unsigned char> ciphertext{
        encrypted_record.payload.begin(), encrypted_record.payload.end()};
    CKeyingMaterial seed;
    const bool decrypted{DecryptSecret(encryption_key, ciphertext, encrypted_record.iv, seed)};
    Cleanse(encryption_key);
    if (!decrypted || seed.size() != DERIVED_SEED_SIZE) {
        Cleanse(seed);
        return util::Error{Untranslated("BIP39 derived-seed record decryption failed.")};
    }
    return seed;
}

util::Result<CKeyingMaterial> ExtractBIP39DerivedSeed(
    const CBIP39DerivedSeedRecord& record,
    const CKeyingMaterial* master_key)
{
    auto valid{ValidateBIP39DerivedSeedRecord(record)};
    if (!valid) return util::Error{util::ErrorString(valid)};

    if (record.protection == BIP39_DERIVED_SEED_CLEAR) {
        return CKeyingMaterial{record.payload.begin(), record.payload.end()};
    }
    if (master_key == nullptr) {
        return util::Error{Untranslated("Wallet is locked; the BIP39 derived seed is unavailable.")};
    }
    return DecryptBIP39DerivedSeedRecord(record, *master_key);
}

} // namespace wallet
