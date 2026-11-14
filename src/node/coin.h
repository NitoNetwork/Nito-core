// Copyright (c) 2019-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_COIN_H
#define BITCOIN_NODE_COIN_H

#include <script/script.h>

#include <map>
#include <set>

class COutPoint;
class Coin;

namespace node {
struct NodeContext;

/**
 * Look up unspent output information. Returns coins in the mempool and in the
 * current chain UTXO set. Iterates through all the keys in the map and
 * populates the values.
 *
 * @param[in] node The node context to use for lookup
 * @param[in,out] coins map to fill
 */
void FindCoins(const node::NodeContext& node, std::map<COutPoint, Coin>& coins);

/**
 * Scan the active chain UTXO set for outputs whose scriptPubKey is in scripts.
 *
 * This mirrors the core of scantxoutset for wallet recovery code that already
 * owns the scripts. It does not inspect historical spent transactions and does
 * not include mempool-only outputs.
 */
bool FindCoinsByScriptPubKeys(const node::NodeContext& node, const std::set<CScript>& scripts, std::map<COutPoint, Coin>& coins);
} // namespace node

#endif // BITCOIN_NODE_COIN_H
