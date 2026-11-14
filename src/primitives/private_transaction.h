// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PRIVATE_TRANSACTION_H
#define BITCOIN_PRIMITIVES_PRIVATE_TRANSACTION_H

#include <consensus/amount.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

static constexpr uint8_t PRIVATE_ACTION_V1 = 1;
static constexpr uint8_t PRIVATE_ORCHARD_SPENDS_ENABLED = 1 << 0;
static constexpr uint8_t PRIVATE_ORCHARD_OUTPUTS_ENABLED = 1 << 1;
static constexpr uint8_t PRIVATE_ORCHARD_FLAGS_MASK = PRIVATE_ORCHARD_SPENDS_ENABLED | PRIVATE_ORCHARD_OUTPUTS_ENABLED;

static constexpr size_t PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE = 32;
static constexpr size_t PRIVATE_ORCHARD_ENC_CIPHERTEXT_SIZE = 580;
static constexpr size_t PRIVATE_ORCHARD_COMPACT_NOTE_SIZE = 52;
static constexpr size_t PRIVATE_ORCHARD_OUT_CIPHERTEXT_SIZE = 80;
static constexpr size_t PRIVATE_ORCHARD_RED_PALLAS_SIG_SIZE = 64;
static constexpr size_t PRIVATE_ORCHARD_PROOF_BASE_SIZE = 2720;
static constexpr size_t PRIVATE_ORCHARD_PROOF_PER_ACTION_SIZE = 2272;
static constexpr uint8_t PRIVATE_ORCHARD_NOTE_PLAINTEXT_VERSION = 0x02;

constexpr size_t PrivateOrchardExpectedProofSize(size_t action_count)
{
    return PRIVATE_ORCHARD_PROOF_BASE_SIZE + PRIVATE_ORCHARD_PROOF_PER_ACTION_SIZE * action_count;
}

class CPrivateActionEffects
{
public:
    uint8_t version{PRIVATE_ACTION_V1};
    uint256 cv;
    uint256 nullifier;
    uint256 rk;
    uint256 cmx;
    std::vector<unsigned char> ephemeral_key;
    std::vector<unsigned char> enc_ciphertext;
    std::vector<unsigned char> out_ciphertext;

    SERIALIZE_METHODS(CPrivateActionEffects, obj)
    {
        READWRITE(obj.version, obj.cv, obj.nullifier, obj.rk, obj.cmx,
                  obj.ephemeral_key, obj.enc_ciphertext, obj.out_ciphertext);
    }
};

class CPrivateActionAuth
{
public:
    std::vector<unsigned char> spend_auth_sig;

    SERIALIZE_METHODS(CPrivateActionAuth, obj)
    {
        READWRITE(obj.spend_auth_sig);
    }
};

class CPrivateBundleAuth
{
public:
    std::vector<unsigned char> proof;
    std::vector<unsigned char> binding_sig;

    SERIALIZE_METHODS(CPrivateBundleAuth, obj)
    {
        READWRITE(obj.proof, obj.binding_sig);
    }
};

class CPrivateEffects
{
public:
    int32_t version{1};
    uint8_t flags{PRIVATE_ORCHARD_FLAGS_MASK};
    uint256 anchor;
    CAmount value_balance{0};
    std::vector<CPrivateActionEffects> actions;

    bool HasActions() const { return !actions.empty(); }

    SERIALIZE_METHODS(CPrivateEffects, obj)
    {
        READWRITE(obj.version, obj.flags, obj.anchor, obj.value_balance, obj.actions);
    }
};

class CPrivateAuth
{
public:
    std::vector<CPrivateActionAuth> actions_auth;
    std::vector<unsigned char> proof;
    std::vector<unsigned char> binding_sig;

    CPrivateBundleAuth BundleAuth() const
    {
        CPrivateBundleAuth bundle_auth;
        bundle_auth.proof = proof;
        bundle_auth.binding_sig = binding_sig;
        return bundle_auth;
    }

    SERIALIZE_METHODS(CPrivateAuth, obj)
    {
        READWRITE(obj.actions_auth, obj.proof, obj.binding_sig);
    }
};

class CPrivateBundle
{
public:
    CPrivateEffects effects;
    std::optional<CPrivateAuth> auth;

    bool HasActions() const { return effects.HasActions(); }
    bool HasAuth() const { return auth.has_value(); }
    CAmount GetValueBalance() const { return effects.value_balance; }
    uint256 GetEffectsHash() const;
    uint256 GetAuthDigest() const;
};

class CPrivateCompactAction
{
public:
    uint8_t version{PRIVATE_ACTION_V1};
    uint256 nullifier;
    uint256 cmx;
    std::vector<unsigned char> ephemeral_key;
    std::vector<unsigned char> enc_ciphertext;
    uint8_t view_tag{0};

    SERIALIZE_METHODS(CPrivateCompactAction, obj)
    {
        READWRITE(obj.version, obj.nullifier, obj.cmx, obj.ephemeral_key, obj.enc_ciphertext, obj.view_tag);
    }
};

class CPrivateCompactEffects
{
public:
    int32_t version{1};
    uint8_t flags{PRIVATE_ORCHARD_FLAGS_MASK};
    uint256 anchor;
    CAmount value_balance{0};
    std::vector<CPrivateCompactAction> actions;

    bool HasActions() const { return !actions.empty(); }

    SERIALIZE_METHODS(CPrivateCompactEffects, obj)
    {
        READWRITE(obj.version, obj.flags, obj.anchor, obj.value_balance, obj.actions);
    }
};

static constexpr uint8_t NITO_ORCHARD_INDEX_RECORD_VERSION = 2;

class CPrivateCompactTx
{
public:
    uint8_t index_version{NITO_ORCHARD_INDEX_RECORD_VERSION};
    int32_t block_position{-1};
    uint256 txid;
    uint256 effects_hash;
    CPrivateCompactEffects effects;

    SERIALIZE_METHODS(CPrivateCompactTx, obj)
    {
        READWRITE(obj.index_version, obj.block_position, obj.txid, obj.effects_hash, obj.effects);
    }
};

#endif // BITCOIN_PRIMITIVES_PRIVATE_TRANSACTION_H
