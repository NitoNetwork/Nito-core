// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/transparenthistoryindex.h>

#include <chain.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <tinyformat.h>
#include <undo.h>
#include <uint256.h>
#include <util/fs.h>
#include <validation.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ios>
#include <memory>
#include <optional>
#include <set>
#include <tuple>
#include <thread>
#include <utility>
#include <vector>

constexpr uint8_t DB_TRANSPARENT_SCRIPT_HISTORY{'s'};
constexpr uint8_t DB_TRANSPARENT_HEIGHT{'h'};
constexpr uint8_t DB_TRANSPARENT_VERSION{'V'};
constexpr uint32_t TRANSPARENT_HISTORY_INDEX_DB_VERSION{2};
constexpr uint8_t TRANSPARENT_HISTORY_RECEIVE{0};
constexpr uint8_t TRANSPARENT_HISTORY_SPEND{1};

std::unique_ptr<TransparentHistoryIndex> g_transparent_history_index;

struct TransparentScriptHistoryKey {
    CScript script;
    int height{0};
    uint256 txid;
    uint32_t block_position{0};
    uint8_t event_type{TRANSPARENT_HISTORY_RECEIVE};
    uint32_t io_index{0};

    TransparentScriptHistoryKey() = default;
    TransparentScriptHistoryKey(CScript script_in,
                                int height_in,
                                const uint256& txid_in,
                                uint32_t block_position_in,
                                uint8_t event_type_in,
                                uint32_t io_index_in)
        : script{std::move(script_in)},
          height{height_in},
          txid{txid_in},
          block_position{block_position_in},
          event_type{event_type_in},
          io_index{io_index_in}
    {
    }

    static TransparentScriptHistoryKey SeekKey(const CScript& script, int height)
    {
        return TransparentScriptHistoryKey{script, std::max(0, height), uint256{}, 0, TRANSPARENT_HISTORY_RECEIVE, 0};
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_TRANSPARENT_SCRIPT_HISTORY);
        s << script;
        ser_writedata32be(s, static_cast<uint32_t>(height));
        s << txid;
        ser_writedata32be(s, block_position);
        ser_writedata8(s, event_type);
        ser_writedata32be(s, io_index);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_TRANSPARENT_SCRIPT_HISTORY) {
            throw std::ios_base::failure("Invalid format for transparent history script key");
        }
        s >> script;
        height = static_cast<int>(ser_readdata32be(s));
        s >> txid;
        block_position = ser_readdata32be(s);
        event_type = ser_readdata8(s);
        io_index = ser_readdata32be(s);
    }
};

struct TransparentHeightKey {
    int height{0};

    explicit TransparentHeightKey(int height_in = 0) : height{height_in} {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_TRANSPARENT_HEIGHT);
        ser_writedata32be(s, static_cast<uint32_t>(height));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_TRANSPARENT_HEIGHT) {
            throw std::ios_base::failure("Invalid format for transparent history height key");
        }
        height = static_cast<int>(ser_readdata32be(s));
    }
};

struct TransparentHistoryValue {
    uint256 block_hash;
    CAmount amount{0};

    SERIALIZE_METHODS(TransparentHistoryValue, obj)
    {
        READWRITE(obj.block_hash, obj.amount);
    }
};

struct TransparentHeightValue {
    uint256 block_hash;
    std::vector<TransparentScriptHistoryKey> keys;

    SERIALIZE_METHODS(TransparentHeightValue, obj)
    {
        READWRITE(obj.block_hash, obj.keys);
    }
};

class TransparentHistoryIndex::DB final : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false)
        : BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "transparenthistoryindex", n_cache_size, f_memory, f_wipe)
    {
    }

    bool ReadVersion(uint32_t& version) const
    {
        return Read(DB_TRANSPARENT_VERSION, version);
    }

    void WriteVersion(CDBBatch& batch) const
    {
        batch.Write(DB_TRANSPARENT_VERSION, TRANSPARENT_HISTORY_INDEX_DB_VERSION);
    }

    void WriteBlockEvents(CDBBatch& batch,
                          int height,
                          const uint256& block_hash,
                          const std::vector<std::pair<TransparentScriptHistoryKey, TransparentHistoryValue>>& events)
    {
        std::vector<TransparentScriptHistoryKey> keys;
        keys.reserve(events.size());
        for (const auto& [key, value] : events) {
            batch.Write(key, value);
            keys.push_back(key);
        }
        // Write an inverse entry even for blocks without matching events. This
        // binds every indexed height to one exact active-chain block hash.
        batch.Write(TransparentHeightKey{height}, TransparentHeightValue{block_hash, std::move(keys)});
    }

    bool EraseHeights(CDBBatch& batch, const std::vector<std::pair<int, uint256>>& expected_heights)
    {
        for (const auto& [height, expected_hash] : expected_heights) {
            TransparentHeightValue value;
            // Repeated commits are intentionally idempotent. A present entry,
            // however, must belong to the exact disconnected block.
            if (!Read(TransparentHeightKey{height}, value)) continue;
            if (value.block_hash != expected_hash) {
                return error("%s: transparent history height %d belongs to %s, expected disconnected block %s",
                             __func__, height, value.block_hash.ToString(), expected_hash.ToString());
            }
            for (const TransparentScriptHistoryKey& key : value.keys) {
                batch.Erase(key);
            }
            batch.Erase(TransparentHeightKey{height});
        }
        return true;
    }

    bool LookupScript(const CScript& script,
                      int start_height,
                      int stop_height,
                      std::vector<interfaces::TransparentHistoryEntry>& entries)
    {
        std::unique_ptr<CDBIterator> it{NewIterator()};
        it->Seek(TransparentScriptHistoryKey::SeekKey(script, start_height));

        for (; it->Valid(); it->Next()) {
            TransparentScriptHistoryKey key;
            if (!it->GetKey(key)) break;
            if (key.script != script) break;
            if (key.height > stop_height) break;

            TransparentHistoryValue value;
            if (!it->GetValue(value)) {
                return error("%s: failed to read transparent history entry at height %d", __func__, key.height);
            }

            entries.push_back(interfaces::TransparentHistoryEntry{
                .block_position = static_cast<int>(key.block_position),
                .io_index = key.io_index,
                .spend = key.event_type == TRANSPARENT_HISTORY_SPEND,
                .amount = value.amount,
                .txid = key.txid,
                .block = interfaces::BlockKey{value.block_hash, key.height},
            });
        }
        return true;
    }
};

class TransparentHistoryIndex::PendingUpdate final
{
public:
    enum class Type {
        NONE,
        APPEND,
        REWIND,
    };

    Type type{Type::NONE};
    int height{0};
    uint256 block_hash;
    std::vector<std::pair<TransparentScriptHistoryKey, TransparentHistoryValue>> events;
    std::vector<std::pair<int, uint256>> rewind_heights;

    void SetAppend(int height_in,
                   const uint256& block_hash_in,
                   std::vector<std::pair<TransparentScriptHistoryKey, TransparentHistoryValue>> events_in)
    {
        type = Type::APPEND;
        height = height_in;
        block_hash = block_hash_in;
        events = std::move(events_in);
        rewind_heights.clear();
    }

    void SetRewind(std::vector<std::pair<int, uint256>> heights_in)
    {
        type = Type::REWIND;
        height = 0;
        block_hash.SetNull();
        events.clear();
        rewind_heights = std::move(heights_in);
    }
};

TransparentHistoryIndex::TransparentHistoryIndex(std::unique_ptr<interfaces::Chain> chain,
                                                 size_t n_cache_size,
                                                 bool f_memory,
                                                 bool f_wipe)
    : BaseIndex(std::move(chain), "transparenthistoryindex"),
      m_db{std::make_unique<TransparentHistoryIndex::DB>(n_cache_size, f_memory, f_wipe)},
      m_pending{std::make_unique<TransparentHistoryIndex::PendingUpdate>()}
{
}

TransparentHistoryIndex::~TransparentHistoryIndex() = default;

BaseIndex::DB& TransparentHistoryIndex::GetDB() const
{
    return *m_db;
}

bool TransparentHistoryIndex::CustomInit(const std::optional<interfaces::BlockKey>& block)
{
    if (!block) return true;

    uint32_t version{0};
    if (!m_db->ReadVersion(version) || version != TRANSPARENT_HISTORY_INDEX_DB_VERSION) {
        return error("%s: unsupported transparent history index schema; rebuild the index with -reindex", __func__);
    }
    return true;
}

bool TransparentHistoryIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    assert(block.data);

    std::vector<std::pair<TransparentScriptHistoryKey, TransparentHistoryValue>> events;
    for (uint32_t pos{0}; pos < block.data->vtx.size(); ++pos) {
        const CTransaction& tx{*block.data->vtx[pos]};
        const uint256 txid{tx.GetHash()};
        for (uint32_t output_index{0}; output_index < tx.vout.size(); ++output_index) {
            const CTxOut& output{tx.vout[output_index]};
            if (output.scriptPubKey.IsUnspendable()) continue;
            events.emplace_back(
                TransparentScriptHistoryKey{output.scriptPubKey, block.height, txid, pos, TRANSPARENT_HISTORY_RECEIVE, output_index},
                TransparentHistoryValue{block.hash, output.nValue});
        }
    }

    // A coinbase-only block has no spent outputs to recover from undo data.
    if (block.data->vtx.size() > 1) {
        CBlockUndo block_undo;
        const CBlockIndex* pindex{WITH_LOCK(cs_main, return m_chainstate->m_blockman.LookupBlockIndex(block.hash))};
        if (!pindex || !m_chainstate->m_blockman.UndoReadFromDisk(block_undo, *pindex)) {
            return error("%s: failed to read undo data for block %d [%s]", __func__, block.height, block.hash.ToString());
        }
        if (block_undo.vtxundo.size() + 1 != block.data->vtx.size()) {
            return error("%s: undo transaction count mismatch at block %d [%s]", __func__, block.height, block.hash.ToString());
        }

        for (uint32_t pos{1}; pos < block.data->vtx.size(); ++pos) {
            const CTransaction& tx{*block.data->vtx[pos]};
            const CTxUndo& tx_undo{block_undo.vtxundo[pos - 1]};
            if (tx_undo.vprevout.size() != tx.vin.size()) {
                return error("%s: undo prevout count mismatch at block %d tx %s", __func__, block.height, tx.GetHash().ToString());
            }
            for (uint32_t input_index{0}; input_index < tx.vin.size(); ++input_index) {
                const Coin& coin{tx_undo.vprevout[input_index]};
                if (coin.IsSpent() || coin.out.scriptPubKey.IsUnspendable()) continue;
                events.emplace_back(
                    TransparentScriptHistoryKey{coin.out.scriptPubKey, block.height, tx.GetHash(), pos, TRANSPARENT_HISTORY_SPEND, input_index},
                    TransparentHistoryValue{block.hash, coin.out.nValue});
            }
        }
    }

    m_pending->SetAppend(block.height, block.hash, std::move(events));
    return true;
}

bool TransparentHistoryIndex::CustomCommit(CDBBatch& batch)
{
    m_db->WriteVersion(batch);
    if (m_pending->type == PendingUpdate::Type::APPEND) {
        m_db->WriteBlockEvents(batch, m_pending->height, m_pending->block_hash, m_pending->events);

        // Regtest-only crash failpoint: the event writes are staged in the same
        // batch as the BaseIndex locator, but neither has reached disk yet.
        const int64_t commit_delay{gArgs.GetIntArg("-transparenthistoryindexcommitdelay", 0)};
        if (commit_delay > 0) {
            LogPrintf("transparenthistoryindex: delaying atomic append commit for %d ms\n", commit_delay);
            std::this_thread::sleep_for(std::chrono::milliseconds{commit_delay});
        }
        return true;
    }

    if (m_pending->type == PendingUpdate::Type::REWIND) {
        return m_db->EraseHeights(batch, m_pending->rewind_heights);
    }

    return true;
}

bool TransparentHistoryIndex::CustomRewind(const interfaces::BlockKey& current_tip, const interfaces::BlockKey& new_tip)
{
    std::vector<std::pair<int, uint256>> rewind_heights;
    {
        LOCK(cs_main);
        const CBlockIndex* current{m_chainstate->m_blockman.LookupBlockIndex(current_tip.hash)};
        const CBlockIndex* target{m_chainstate->m_blockman.LookupBlockIndex(new_tip.hash)};
        if (!current || current->nHeight != current_tip.height ||
            !target || target->nHeight != new_tip.height ||
            current->GetAncestor(target->nHeight) != target) {
            return error("%s: transparent history rewind does not describe one known ancestor path", __func__);
        }

        rewind_heights.reserve(current_tip.height - new_tip.height);
        for (const CBlockIndex* cursor{current}; cursor != target; cursor = cursor->pprev) {
            rewind_heights.emplace_back(cursor->nHeight, cursor->GetBlockHash());
        }
    }

    m_pending->SetRewind(std::move(rewind_heights));
    return true;
}

bool TransparentHistoryIndex::LookupScripts(const std::set<CScript>& scripts,
                                            int start_height,
                                            int stop_height,
                                            std::vector<interfaces::TransparentHistoryEntry>& entries) const
{
    entries.clear();
    if (scripts.empty() || start_height > stop_height) return true;
    start_height = std::max(0, start_height);

    for (const CScript& script : scripts) {
        if (!m_db->LookupScript(script, start_height, stop_height, entries)) return false;
    }

    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        return std::tie(a.block.height, a.block_position, a.txid, a.spend, a.io_index) <
               std::tie(b.block.height, b.block_position, b.txid, b.spend, b.io_index);
    });
    return true;
}

TransparentHistoryIndex* GetTransparentHistoryIndex()
{
    return g_transparent_history_index.get();
}

bool InitTransparentHistoryIndex(std::function<std::unique_ptr<interfaces::Chain>()> make_chain,
                                 size_t n_cache_size,
                                 bool f_memory,
                                 bool f_wipe)
{
    if (g_transparent_history_index) return false;
    g_transparent_history_index = std::make_unique<TransparentHistoryIndex>(make_chain(), n_cache_size, f_memory, f_wipe);
    return true;
}

void DestroyTransparentHistoryIndex()
{
    g_transparent_history_index.reset();
}
