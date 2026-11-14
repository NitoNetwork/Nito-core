// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIVATE_PRIVATE_ADDRESS_H
#define BITCOIN_PRIVATE_PRIVATE_ADDRESS_H

#include <private/orchard_verifier.h>

#include <array>
#include <cstdint>
#include <string>

class CChainParams;

namespace wallet {

static constexpr uint8_t NITO_PRIVATE_ADDRESS_VERSION = 2;
static constexpr uint8_t NITO_PRIVATE_ADDRESS_ORCHARD_RAW = 1;
static constexpr const char* NITO_PRIVATE_ADDRESS_TYPE_STRING = "bech32x";

std::string NitoPrivateAddressHrp(const CChainParams& params);
std::string NitoPrivateAddressPrefix(const CChainParams& params);

std::string EncodeNitoPrivateAddress(
    const std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
    const CChainParams& params);

bool DecodeNitoPrivateAddress(
    const std::string& encoded,
    const CChainParams& params,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
    std::string& error);

} // namespace wallet

#endif // BITCOIN_PRIVATE_PRIVATE_ADDRESS_H
