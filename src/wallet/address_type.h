// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_ADDRESS_TYPE_H
#define BITCOIN_WALLET_ADDRESS_TYPE_H

#include <outputtype.h>
#include <private/private_address.h>

#include <optional>
#include <string>
#include <string_view>

namespace wallet {

enum class WalletAddressKind : int {
    LEGACY = 0,
    P2SH_SEGWIT = 1,
    BECH32 = 2,
    BECH32M = 3,
    PRIVATE = 4,
};

inline WalletAddressKind WalletAddressKindFromOutputType(OutputType type)
{
    switch (type) {
    case OutputType::LEGACY:
        return WalletAddressKind::LEGACY;
    case OutputType::P2SH_SEGWIT:
        return WalletAddressKind::P2SH_SEGWIT;
    case OutputType::BECH32:
        return WalletAddressKind::BECH32;
    case OutputType::BECH32M:
        return WalletAddressKind::BECH32M;
    case OutputType::UNKNOWN:
        break;
    }
    return WalletAddressKind::BECH32;
}

inline std::optional<OutputType> OutputTypeFromWalletAddressKind(WalletAddressKind kind)
{
    switch (kind) {
    case WalletAddressKind::LEGACY:
        return OutputType::LEGACY;
    case WalletAddressKind::P2SH_SEGWIT:
        return OutputType::P2SH_SEGWIT;
    case WalletAddressKind::BECH32:
        return OutputType::BECH32;
    case WalletAddressKind::BECH32M:
        return OutputType::BECH32M;
    case WalletAddressKind::PRIVATE:
        return std::nullopt;
    }
    return std::nullopt;
}

inline bool IsPrivateWalletAddressKind(WalletAddressKind kind)
{
    return kind == WalletAddressKind::PRIVATE;
}

inline const char* FormatWalletAddressKind(WalletAddressKind kind)
{
    switch (kind) {
    case WalletAddressKind::LEGACY:
        return "legacy";
    case WalletAddressKind::P2SH_SEGWIT:
        return "p2sh-segwit";
    case WalletAddressKind::BECH32:
        return "bech32";
    case WalletAddressKind::BECH32M:
        return "bech32m";
    case WalletAddressKind::PRIVATE:
        return NITO_PRIVATE_ADDRESS_TYPE_STRING;
    }
    return "unknown";
}

inline std::optional<WalletAddressKind> ParseWalletAddressKind(std::string_view str)
{
    if (str == std::string_view{NITO_PRIVATE_ADDRESS_TYPE_STRING}) {
        return WalletAddressKind::PRIVATE;
    }
    if (const auto output_type = ParseOutputType(std::string{str})) {
        return WalletAddressKindFromOutputType(*output_type);
    }
    return std::nullopt;
}

} // namespace wallet

#endif // BITCOIN_WALLET_ADDRESS_TYPE_H
