// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRIVATE_NOTES_H
#define BITCOIN_WALLET_PRIVATE_NOTES_H

#include <consensus/amount.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace wallet {

static constexpr int PRIVATE_WALLET_NOTE_VERSION = 2;

class CPrivateWalletNote
{
public:
    int nVersion{PRIVATE_WALLET_NOTE_VERSION};
    uint256 cmx;
    uint256 nullifier;
    uint256 txid;
    uint256 block_hash;
    CAmount value{0};
    int block_height{-1};
    uint32_t derivation_version{1};
    uint32_t account{0};
    bool internal{false};
    uint32_t diversifier_index{0};
    uint64_t commitment_index{std::numeric_limits<uint64_t>::max()};
    uint32_t action_index{0};
    bool spent{false};
    bool decrypted{false};
    std::vector<unsigned char> recipient_raw;
    std::vector<unsigned char> rho;
    std::vector<unsigned char> rseed;
    std::vector<unsigned char> memo;
    std::vector<unsigned char> enc_ciphertext;
    std::vector<unsigned char> out_ciphertext;

    // Memory only; recovered from the sender's internal OVK, not the receive branch.
    mutable std::optional<bool> m_is_change;

    uint256 GetId() const { return cmx; }
    bool IsConfirmed() const { return block_height >= 0 && !block_hash.IsNull(); }
    bool HasNullifier() const { return !nullifier.IsNull(); }
    bool HasWitnessPosition() const { return commitment_index != std::numeric_limits<uint64_t>::max(); }
    bool HasSpendSecrets() const { return decrypted && !recipient_raw.empty() && !rho.empty() && !rseed.empty(); }
    bool IsSpendable() const { return !spent && HasNullifier() && HasWitnessPosition() && HasSpendSecrets() && value > 0; }

    SERIALIZE_METHODS(CPrivateWalletNote, obj)
    {
        SER_WRITE(obj, {
            const int nVersion{PRIVATE_WALLET_NOTE_VERSION};
            const uint32_t derivation_version{obj.derivation_version == 0 ? 1 : obj.derivation_version};
            s << nVersion << obj.cmx << obj.nullifier << obj.txid << obj.block_hash << obj.value
              << obj.block_height << derivation_version << obj.account << obj.internal << obj.diversifier_index
              << obj.commitment_index << obj.action_index << obj.spent << obj.decrypted << obj.recipient_raw
              << obj.rho << obj.rseed << obj.memo << obj.enc_ciphertext << obj.out_ciphertext;
        });
        SER_READ(obj, {
            obj.m_is_change.reset();
            s >> obj.nVersion;
            if (obj.nVersion != PRIVATE_WALLET_NOTE_VERSION) {
                throw std::ios_base::failure("Unsupported private wallet note version");
            }
            s >> obj.cmx >> obj.nullifier >> obj.txid >> obj.block_hash >> obj.value
              >> obj.block_height >> obj.derivation_version;
            if (obj.derivation_version != 1) {
                throw std::ios_base::failure("Unsupported private note derivation version");
            }
            s >> obj.account >> obj.internal >> obj.diversifier_index >> obj.commitment_index
              >> obj.action_index >> obj.spent >> obj.decrypted >> obj.recipient_raw >> obj.rho
              >> obj.rseed >> obj.memo >> obj.enc_ciphertext >> obj.out_ciphertext;
        });
    }
};

class CPrivateSpentNullifier
{
public:
    uint256 nullifier;
    uint256 txid;
    uint256 block_hash;
    int block_height{-1};
    uint32_t action_index{0};

    uint256 GetId() const { return nullifier; }
    bool IsConfirmed() const { return block_height >= 0 && !block_hash.IsNull(); }

    SERIALIZE_METHODS(CPrivateSpentNullifier, obj)
    {
        READWRITE(obj.nullifier, obj.txid, obj.block_hash, obj.block_height, obj.action_index);
    }
};

} // namespace wallet

#endif // BITCOIN_WALLET_PRIVATE_NOTES_H
