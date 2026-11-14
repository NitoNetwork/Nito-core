// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <private/private_address.h>

#include <bech32.h>
#include <chainparams.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <algorithm>
#include <vector>

namespace wallet {
namespace {
static constexpr unsigned char NITO_PRIVATE_ADDRESS_BECH32M_TAG = 6; // Bech32 charset index 6 => 'x', addresses start with nito1x.
} // namespace

std::string NitoPrivateAddressHrp(const CChainParams& params)
{
    return params.Bech32HRP();
}

std::string NitoPrivateAddressPrefix(const CChainParams& params)
{
    return NitoPrivateAddressHrp(params) + "1x";
}

std::string EncodeNitoPrivateAddress(
    const std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
    const CChainParams& params)
{
    std::vector<unsigned char> payload;
    payload.reserve(2 + raw_address.size());
    payload.push_back(NITO_PRIVATE_ADDRESS_VERSION);
    payload.push_back(NITO_PRIVATE_ADDRESS_ORCHARD_RAW);
    payload.insert(payload.end(), raw_address.begin(), raw_address.end());

    std::vector<unsigned char> data;
    data.reserve(1 + (payload.size() * 8 + 4) / 5);
    data.push_back(NITO_PRIVATE_ADDRESS_BECH32M_TAG);
    ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, payload.begin(), payload.end());
    return bech32::Encode(bech32::Encoding::BECH32M, NitoPrivateAddressHrp(params), data);
}

bool DecodeNitoPrivateAddress(
    const std::string& encoded,
    const CChainParams& params,
    std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE>& raw_address,
    std::string& error)
{
    error.clear();
    const auto decoded = bech32::Decode(encoded);
    if (decoded.encoding != bech32::Encoding::BECH32M) {
        error = "private address must use Bech32m";
        return false;
    }
    const std::string expected_hrp = NitoPrivateAddressHrp(params);
    if (decoded.hrp != expected_hrp) {
        error = strprintf("invalid private address prefix: expected %s, got %s", expected_hrp, decoded.hrp);
        return false;
    }
    if (decoded.data.empty() || decoded.data[0] != NITO_PRIVATE_ADDRESS_BECH32M_TAG) {
        error = "invalid private address tag: expected nito1x private address";
        return false;
    }

    std::vector<unsigned char> payload;
    payload.reserve((decoded.data.size() * 5) / 8);
    if (!ConvertBits<5, 8, false>([&](unsigned char c) { payload.push_back(c); }, decoded.data.begin() + 1, decoded.data.end())) {
        error = "invalid private address padding";
        return false;
    }
    if (payload.size() != 2 + raw_address.size()) {
        error = strprintf("invalid private address payload size: %u", static_cast<unsigned>(payload.size()));
        return false;
    }
    if (payload[0] != NITO_PRIVATE_ADDRESS_VERSION) {
        error = strprintf("unsupported private address version: %u", payload[0]);
        return false;
    }
    if (payload[1] != NITO_PRIVATE_ADDRESS_ORCHARD_RAW) {
        error = strprintf("unsupported private receiver type: %u", payload[1]);
        return false;
    }
    std::copy(payload.begin() + 2, payload.end(), raw_address.begin());
    return true;
}

} // namespace wallet
