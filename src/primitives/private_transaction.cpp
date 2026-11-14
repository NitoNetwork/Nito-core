// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/private_transaction.h>

#include <hash.h>

uint256 CPrivateBundle::GetEffectsHash() const
{
    return (HashWriter{} << effects).GetHash();
}

uint256 CPrivateBundle::GetAuthDigest() const
{
    if (!auth) {
        return uint256::ZERO;
    }
    return (HashWriter{} << *auth).GetHash();
}
