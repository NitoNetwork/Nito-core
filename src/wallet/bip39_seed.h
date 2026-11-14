// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BIP39_SEED_H
#define BITCOIN_WALLET_BIP39_SEED_H

#include <key.h>
#include <serialize.h>
#include <uint256.h>
#include <util/result.h>
#include <wallet/bip39.h>
#include <wallet/crypter.h>
#include <wallet/private_wallet.h>

#include <cstdint>
namespace wallet {

static constexpr uint8_t BIP39_DERIVED_SEED_RECORD_VERSION{1};
static constexpr uint8_t BIP39_DERIVED_SEED_CLEAR{0};
static constexpr uint8_t BIP39_DERIVED_SEED_ENCRYPTED{1};
static constexpr uint8_t BIP39_DERIVED_SEED_FLAG_PASSPHRASE{1U << 0};
static constexpr uint8_t BIP39_DERIVED_SEED_KNOWN_FLAGS{BIP39_DERIVED_SEED_FLAG_PASSPHRASE};

/**
 * Versioned wallet record for the final 64-byte BIP39 seed.
 *
 * The mnemonic entropy remains stored as its existing CKey so dumpmnemonic can
 * reproduce it. This record stores the already-derived seed instead of the
 * passphrase, and binds it to that entropy key and to its intended scope.
 */
struct CBIP39DerivedSeedRecord
{
    uint8_t version{BIP39_DERIVED_SEED_RECORD_VERSION};
    uint8_t protection{BIP39_DERIVED_SEED_CLEAR};
    CKeyID hd_seed_id;
    uint8_t seed_scope{static_cast<uint8_t>(PrivateSeedScope::UNKNOWN)};
    uint8_t flags{0};
    uint256 iv;
    CKeyingMaterial payload;
    uint256 integrity;

    bool PassphraseEnabled() const { return (flags & BIP39_DERIVED_SEED_FLAG_PASSPHRASE) != 0; }
    PrivateSeedScope SeedScope() const { return static_cast<PrivateSeedScope>(seed_scope); }

    SERIALIZE_METHODS(CBIP39DerivedSeedRecord, obj)
    {
        READWRITE(obj.version,
                  obj.protection,
                  obj.hd_seed_id,
                  obj.seed_scope,
                  obj.flags,
                  obj.iv,
                  obj.payload,
                  obj.integrity);
    }
};

/** Validate the record shape and, for a clear record, its checksum. */
util::Result<void> ValidateBIP39DerivedSeedRecord(const CBIP39DerivedSeedRecord& record);

/** Create an authenticated clear record for an unencrypted wallet. */
util::Result<CBIP39DerivedSeedRecord> CreateBIP39DerivedSeedRecord(
    const CKeyID& hd_seed_id,
    PrivateSeedScope seed_scope,
    bool passphrase_enabled,
    const BIP39Seed& seed);

/** Convert a valid clear record to an encrypt-then-MAC wallet record. */
util::Result<CBIP39DerivedSeedRecord> EncryptBIP39DerivedSeedRecord(
    const CBIP39DerivedSeedRecord& clear_record,
    const CKeyingMaterial& master_key);

/** Authenticate and decrypt an encrypted record into secure memory. */
util::Result<CKeyingMaterial> DecryptBIP39DerivedSeedRecord(
    const CBIP39DerivedSeedRecord& encrypted_record,
    const CKeyingMaterial& master_key);

/**
 * Read either form of the record. Encrypted records require master_key;
 * passing one for a clear record is harmless and ignored.
 */
util::Result<CKeyingMaterial> ExtractBIP39DerivedSeed(
    const CBIP39DerivedSeedRecord& record,
    const CKeyingMaterial* master_key = nullptr);

} // namespace wallet

#endif // BITCOIN_WALLET_BIP39_SEED_H
