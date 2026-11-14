// Copyright (c) 2019-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coin.h>

#include <coins.h>
#include <node/context.h>
#include <txmempool.h>
#include <util/check.h>
#include <validation.h>

namespace node {
void FindCoins(const NodeContext& node, std::map<COutPoint, Coin>& coins)
{
    assert(node.mempool);
    assert(node.chainman);
    LOCK2(cs_main, node.mempool->cs);
    CCoinsViewCache& chain_view = node.chainman->ActiveChainstate().CoinsTip();
    CCoinsViewMemPool mempool_view(&chain_view, *node.mempool);
    for (auto& coin : coins) {
        if (!mempool_view.GetCoin(coin.first, coin.second)) {
            // Either the coin is not in the CCoinsViewCache or is spent. Clear it.
            coin.second.Clear();
        }
    }
}

bool FindCoinsByScriptPubKeys(const NodeContext& node, const std::set<CScript>& scripts, std::map<COutPoint, Coin>& coins)
{
    assert(node.chainman);
    if (scripts.empty()) return true;

    std::unique_ptr<CCoinsViewCursor> cursor;
    {
        LOCK(cs_main);
        Chainstate& active_chainstate = node.chainman->ActiveChainstate();
        active_chainstate.ForceFlushStateToDisk();
        cursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
    }

    int64_t count{0};
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin)) return false;

        if (++count % 8192 == 0) {
            node.rpc_interruption_point();
        }

        if (!coin.IsSpent() && scripts.count(coin.out.scriptPubKey)) {
            coins.emplace(outpoint, std::move(coin));
        }
        cursor->Next();
    }
    return true;
}
} // namespace node
