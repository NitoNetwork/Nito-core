// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BIP39_H
#define BITCOIN_WALLET_BIP39_H

#include <key.h>
#include <span.h>
#include <support/allocators/secure.h>
#include <util/result.h>

#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace wallet {

//! Maximum accepted UTF-8 byte length, both before and after NFKD normalization.
static constexpr size_t MAX_BIP39_PASSPHRASE_SIZE{1024};

//! Decode a supported BIP39 English 12- or 24-word mnemonic into encrypted-wallet-storable seed metadata.
util::Result<CKey> DecodeBIP39Mnemonic(const std::string& mnemonic);

//! Encode encrypted-wallet-storable seed metadata as its original BIP39 English mnemonic length.
util::Result<std::string> EncodeBIP39Mnemonic(const CKey& hd_seed);

//! Canonical lowercase, single-space mnemonic form after word and checksum validation.
util::Result<std::string> NormalizeBIP39Mnemonic(const std::string& mnemonic);

//! Validate and normalize an optional BIP39 passphrase with Unicode NFKD.
//! No trimming, case conversion, or whitespace rewriting is performed.
util::Result<SecureString> NormalizeBIP39Passphrase(const SecureString& passphrase);

//! Standard BIP39 PBKDF2-HMAC-SHA512 seed bytes for a validated mnemonic.
using BIP39Seed = std::array<std::byte, 64>;
util::Result<BIP39Seed> DeriveBIP39SeedFromMnemonic(const std::string& mnemonic);
util::Result<BIP39Seed> DeriveBIP39SeedFromMnemonic(const std::string& mnemonic, const SecureString& passphrase);

//! Derive the BIP39 seed represented by a 32-byte mnemonic entropy key.
util::Result<BIP39Seed> DeriveBIP39SeedFromEntropyKey(const CKey& hd_seed);
util::Result<BIP39Seed> DeriveBIP39SeedFromEntropyKey(const CKey& hd_seed, const SecureString& passphrase);

//! Construct a BIP32 master key directly from an already-derived BIP39 seed.
CExtKey MakeBIP39MasterKey(const BIP39Seed& seed);

//! Construct the BIP32 master key used by descriptor and Orchard wallets.
util::Result<CExtKey> MakeBIP39MasterKeyFromEntropyKey(const CKey& hd_seed);
util::Result<CExtKey> MakeBIP39MasterKeyFromEntropyKey(const CKey& hd_seed, const SecureString& passphrase);

//! Explicitly erase derived seed bytes before releasing their storage.
void ClearBIP39Seed(BIP39Seed& seed);

//! Scope guard that erases a derived seed on every exit path, including exceptions.
class BIP39SeedGuard
{
public:
    explicit BIP39SeedGuard(BIP39Seed& seed) : m_seed(seed) {}
    ~BIP39SeedGuard();
    BIP39SeedGuard(const BIP39SeedGuard&) = delete;
    BIP39SeedGuard& operator=(const BIP39SeedGuard&) = delete;

private:
    BIP39Seed& m_seed;
};

//! Explicitly erase a normalized passphrase before releasing its secure buffer.
void ClearBIP39Passphrase(SecureString& passphrase);

//! Return true when the string has the shape of a supported mnemonic.
bool LooksLikeBIP39Mnemonic(const std::string& mnemonic);

} // namespace wallet

#endif // BITCOIN_WALLET_BIP39_H
