// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/orchardindex.h>

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/interface_ui.h>
#include <private/orchard_verifier.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/translation.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <ios>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

constexpr uint8_t DB_ORCHARD_HEIGHT{'h'};
constexpr uint8_t DB_ORCHARD_HASH{'H'};
constexpr uint8_t DB_ORCHARD_MERKLE_NODE{'m'};
constexpr uint8_t DB_ORCHARD_MERKLE_STATE{'s'};
constexpr uint8_t DB_ORCHARD_MERKLE_HEIGHT_STATE{'S'};
constexpr uint8_t DB_ORCHARD_COMMITMENT_INDEX{'c'};
constexpr uint8_t DB_ORCHARD_VERSION{'V'};
constexpr uint8_t DB_ORCHARD_ACTIVATION_HEIGHT{'A'};
constexpr uint8_t DB_ORCHARD_TRANSACTION{'t'};
constexpr uint8_t ORCHARD_MERKLE_DEPTH{32};
constexpr uint32_t ORCHARD_INDEX_DB_VERSION{3};

std::unique_ptr<OrchardIndex> g_orchard_index;

struct OrchardHeightKey {
    int height;

    explicit OrchardHeightKey(int height_in = 0) : height{height_in} {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_ORCHARD_HEIGHT);
        ser_writedata32be(s, height);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_ORCHARD_HEIGHT) {
            throw std::ios_base::failure("Invalid format for orchard index DB height key");
        }
        height = ser_readdata32be(s);
    }
};

struct OrchardHashKey {
    uint256 hash;

    explicit OrchardHashKey(uint256 hash_in = uint256{}) : hash{hash_in} {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_ORCHARD_HASH);
        s << hash;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_ORCHARD_HASH) {
            throw std::ios_base::failure("Invalid format for orchard index DB hash key");
        }
        s >> hash;
    }
};

struct OrchardMerkleNodeKey {
    uint8_t level{0};
    uint64_t index{0};

    OrchardMerkleNodeKey(uint8_t level_in = 0, uint64_t index_in = 0) : level{level_in}, index{index_in} {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_ORCHARD_MERKLE_NODE);
        ser_writedata8(s, level);
        ser_writedata64(s, index);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_ORCHARD_MERKLE_NODE) {
            throw std::ios_base::failure("Invalid format for orchard index DB Merkle node key");
        }
        level = ser_readdata8(s);
        index = ser_readdata64(s);
    }
};

struct OrchardMerkleStateKey {
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_ORCHARD_MERKLE_STATE);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_ORCHARD_MERKLE_STATE) {
            throw std::ios_base::failure("Invalid format for orchard index DB Merkle state key");
        }
    }
};

struct OrchardMerkleHeightStateKey {
    int height{0};
    uint256 hash;

    OrchardMerkleHeightStateKey(int height_in = 0, uint256 hash_in = uint256{}) : height{height_in}, hash{hash_in} {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_ORCHARD_MERKLE_HEIGHT_STATE);
        ser_writedata32be(s, height);
        s << hash;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_ORCHARD_MERKLE_HEIGHT_STATE) {
            throw std::ios_base::failure("Invalid format for orchard index DB Merkle height state key");
        }
        height = ser_readdata32be(s);
        s >> hash;
    }
};

struct OrchardCommitmentKey {
    uint256 commitment;

    explicit OrchardCommitmentKey(uint256 commitment_in = uint256{}) : commitment{commitment_in} {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_ORCHARD_COMMITMENT_INDEX);
        s << commitment;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_ORCHARD_COMMITMENT_INDEX) {
            throw std::ios_base::failure("Invalid format for orchard index DB commitment key");
        }
        s >> commitment;
    }
};

struct OrchardBlockIndexEntry {
    std::vector<CPrivateCompactTx> txs;

    SERIALIZE_METHODS(OrchardBlockIndexEntry, obj) { READWRITE(obj.txs); }
};

struct OrchardStoredTransaction {
    CTransactionRef tx;

    SERIALIZE_METHODS(OrchardStoredTransaction, obj) { READWRITE(TX_WITH_WITNESS(obj.tx)); }
};

struct OrchardMerkleNodeSnapshot {
    uint8_t level{0};
    uint64_t index{0};
    uint256 node;

    SERIALIZE_METHODS(OrchardMerkleNodeSnapshot, obj) { READWRITE(obj.level, obj.index, obj.node); }

    bool operator==(const OrchardMerkleNodeSnapshot&) const = default;
};

struct OrchardMerkleState {
    uint64_t commitment_count{0};
    uint256 root;
    std::vector<OrchardMerkleNodeSnapshot> boundary_nodes;

    SERIALIZE_METHODS(OrchardMerkleState, obj) { READWRITE(obj.commitment_count, obj.root, obj.boundary_nodes); }

    bool operator==(const OrchardMerkleState&) const = default;
};

struct OrchardCurrentMerkleState {
    int height{-1};
    uint256 hash;
    OrchardMerkleState merkle_state;

    SERIALIZE_METHODS(OrchardCurrentMerkleState, obj) { READWRITE(obj.height, obj.hash, obj.merkle_state); }
};

using OrchardMerkleNodeCache = std::map<std::pair<uint8_t, uint64_t>, uint256>;

static CPrivateCompactTx MakeRecord(int32_t block_position, const CTransaction& tx)
{
    CPrivateCompactTx record;
    record.block_position = block_position;
    record.txid = tx.GetHash();
    if (tx.m_private_bundle) {
        record.effects_hash = tx.m_private_bundle->GetEffectsHash();
        record.effects.version = tx.m_private_bundle->effects.version;
        record.effects.flags = tx.m_private_bundle->effects.flags;
        record.effects.anchor = tx.m_private_bundle->effects.anchor;
        record.effects.value_balance = tx.m_private_bundle->effects.value_balance;
        record.effects.actions.reserve(tx.m_private_bundle->effects.actions.size());
        for (const auto& action : tx.m_private_bundle->effects.actions) {
            CPrivateCompactAction compact;
            compact.version = action.version;
            compact.nullifier = action.nullifier;
            compact.cmx = action.cmx;
            compact.ephemeral_key = action.ephemeral_key;
            if (action.enc_ciphertext.size() >= PRIVATE_ORCHARD_COMPACT_NOTE_SIZE) {
                compact.enc_ciphertext.assign(action.enc_ciphertext.begin(),
                                              action.enc_ciphertext.begin() + PRIVATE_ORCHARD_COMPACT_NOTE_SIZE);
                compact.view_tag = compact.enc_ciphertext.front() ^ PRIVATE_ORCHARD_NOTE_PLAINTEXT_VERSION;
            } else {
                compact.enc_ciphertext = action.enc_ciphertext;
            }
            record.effects.actions.push_back(std::move(compact));
        }
    }
    return record;
}

static bool ValidateRecord(const CPrivateCompactTx& record, int height)
{
    if (record.index_version != NITO_ORCHARD_INDEX_RECORD_VERSION) {
        return error("%s: unsupported compact Orchard record version %u at height %d",
                     __func__, record.index_version, height);
    }
    if (record.block_position < 0) {
        return error("%s: invalid compact Orchard transaction position at height %d", __func__, height);
    }
    if (record.txid.IsNull()) {
        return error("%s: compact Orchard transaction has null txid at height %d position %d",
                     __func__, height, record.block_position);
    }
    if (record.effects_hash.IsNull()) {
        return error("%s: compact Orchard transaction has null effects hash at height %d position %d",
                     __func__, height, record.block_position);
    }
    if (!record.effects.HasActions()) {
        return error("%s: empty compact Orchard transaction at height %d position %d",
                     __func__, height, record.block_position);
    }
    for (const auto& action : record.effects.actions) {
        if (action.ephemeral_key.size() != PRIVATE_ORCHARD_EPHEMERAL_KEY_SIZE ||
            action.enc_ciphertext.size() != PRIVATE_ORCHARD_COMPACT_NOTE_SIZE) {
            return error("%s: compact Orchard action ciphertext length mismatch at height %d position %d",
                         __func__, height, record.block_position);
        }
        if (action.view_tag != (action.enc_ciphertext.front() ^ PRIVATE_ORCHARD_NOTE_PLAINTEXT_VERSION)) {
            return error("%s: compact Orchard action view tag mismatch at height %d position %d",
                         __func__, height, record.block_position);
        }
    }
    return true;
}

static bool GetEmptyMerkleRoot(uint8_t level, uint256& root)
{
    using EmptyRoots = std::array<uint256, ORCHARD_MERKLE_DEPTH + 1>;
    static const std::optional<EmptyRoots> empty_roots{[]() -> std::optional<EmptyRoots> {
        EmptyRoots roots;
        for (uint8_t empty_level = 0; empty_level <= ORCHARD_MERKLE_DEPTH; ++empty_level) {
            std::string error_msg;
            const auto result = GetPrivateOrchardEmptyRoot(empty_level, roots[empty_level], error_msg);
            if (result != PrivateOrchardBuildResult::OK) {
                error("%s: unable to compute Orchard empty root at level %u: %s",
                      __func__, empty_level, error_msg);
                return std::nullopt;
            }
        }
        return roots;
    }()};

    if (level > ORCHARD_MERKLE_DEPTH || !empty_roots) return false;
    root = (*empty_roots)[level];
    return true;
}

static bool MakeEmptyMerkleState(OrchardMerkleState& state)
{
    state.commitment_count = 0;
    state.boundary_nodes.clear();
    return GetEmptyMerkleRoot(ORCHARD_MERKLE_DEPTH, state.root);
}

static bool CombineMerkleNodes(uint8_t level, const uint256& left, const uint256& right, uint256& parent)
{
    std::string error_msg;
    const auto result = ComputePrivateOrchardParent(level, left, right, parent, error_msg);
    return result == PrivateOrchardBuildResult::OK ||
           error("%s: unable to combine Orchard Merkle nodes at level %u: %s",
                 __func__, level, error_msg);
}

class OrchardIndex::DB final : public BaseIndex::DB
{
private:
    std::optional<OrchardCurrentMerkleState> m_current_state;
    const int m_activation_height;

public:
    explicit DB(size_t n_cache_size, int activation_height, bool f_memory = false, bool f_wipe = false)
        : BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "orchardindex", n_cache_size, f_memory, f_wipe),
          m_activation_height{activation_height}
    {
    }

    bool ReadVersion(uint32_t& version) const
    {
        return Read(DB_ORCHARD_VERSION, version);
    }

    bool ReadActivationHeight(int& activation_height) const
    {
        return Read(DB_ORCHARD_ACTIVATION_HEIGHT, activation_height);
    }

    bool HasPostActivationData()
    {
        std::unique_ptr<CDBIterator> it{NewIterator()};
        for (const uint8_t prefix : {DB_ORCHARD_HEIGHT, DB_ORCHARD_HASH, DB_ORCHARD_MERKLE_NODE,
                                     DB_ORCHARD_MERKLE_HEIGHT_STATE, DB_ORCHARD_COMMITMENT_INDEX,
                                     DB_ORCHARD_TRANSACTION}) {
            it->Seek(prefix);
            uint8_t key{0};
            if (it->Valid() && (!it->GetKey(key) || key == prefix)) return true;
        }
        return false;
    }

    void SetCurrentState(OrchardCurrentMerkleState state)
    {
        m_current_state = std::move(state);
    }

    bool GetCurrentState(OrchardCurrentMerkleState& state) const
    {
        if (!m_current_state) return false;
        state = *m_current_state;
        return true;
    }

    bool ReadPersistedCurrentState(OrchardCurrentMerkleState& state) const
    {
        return Read(OrchardMerkleStateKey{}, state);
    }

    bool WriteCurrentState(CDBBatch& batch) const
    {
        if (!m_current_state) return false;
        batch.Write(DB_ORCHARD_VERSION, ORCHARD_INDEX_DB_VERSION);
        batch.Write(DB_ORCHARD_ACTIVATION_HEIGHT, m_activation_height);
        batch.Write(OrchardMerkleStateKey{}, *m_current_state);
        return true;
    }

    bool ReadBlockEntry(const CBlockIndex* block_index, OrchardBlockIndexEntry& entry) const
    {
        if (!block_index) return false;

        std::pair<uint256, OrchardBlockIndexEntry> height_entry;
        if (!Read(OrchardHeightKey{block_index->nHeight}, height_entry)) {
            return false;
        }
        if (height_entry.first == block_index->GetBlockHash()) {
            entry = std::move(height_entry.second);
            return true;
        }

        return Read(OrchardHashKey{block_index->GetBlockHash()}, entry);
    }

    bool WriteBlockEntry(int height, const uint256& block_hash, const OrchardBlockIndexEntry& entry)
    {
        return Write(OrchardHeightKey{height}, std::make_pair(block_hash, entry));
    }

    void WriteBlockEntry(CDBBatch& batch, int height, const uint256& block_hash, const OrchardBlockIndexEntry& entry)
    {
        batch.Write(OrchardHeightKey{height}, std::make_pair(block_hash, entry));
    }

    bool ReadMerkleState(OrchardMerkleState& state) const
    {
        OrchardCurrentMerkleState current;
        if (!ReadPersistedCurrentState(current)) return false;
        state = std::move(current.merkle_state);
        return true;
    }

    bool ReadMerkleHeightState(int height, const uint256& block_hash, OrchardMerkleState& state) const
    {
        return Read(OrchardMerkleHeightStateKey{height, block_hash}, state);
    }

    void WriteMerkleHeightState(CDBBatch& batch, int height, const uint256& block_hash, const OrchardMerkleState& state)
    {
        batch.Write(OrchardMerkleHeightStateKey{height, block_hash}, state);
    }

    bool ReadMerkleNode(uint8_t level, uint64_t index, uint256& node) const
    {
        return Read(OrchardMerkleNodeKey{level, index}, node);
    }

    bool ReadCommitmentIndex(const uint256& commitment, uint64_t& index) const
    {
        return Read(OrchardCommitmentKey{commitment}, index);
    }

    void WriteCommitmentIndex(CDBBatch& batch, const uint256& commitment, uint64_t index)
    {
        batch.Write(OrchardCommitmentKey{commitment}, index);
    }

    void WriteMerkleNode(CDBBatch& batch, uint8_t level, uint64_t index, const uint256& node)
    {
        batch.Write(OrchardMerkleNodeKey{level, index}, node);
    }

    bool ReadMerkleNodeOrEmpty(uint8_t level, uint64_t index, uint64_t commitment_count, uint256& node) const
    {
        if (level > ORCHARD_MERKLE_DEPTH) return false;
        if (level == ORCHARD_MERKLE_DEPTH) {
            return ReadMerkleNode(level, index, node);
        }

        const uint64_t subtree_first_leaf = index << level;
        if (subtree_first_leaf >= commitment_count) {
            return GetEmptyMerkleRoot(level, node);
        }
        return ReadMerkleNode(level, index, node);
    }

    bool ReadCachedMerkleNode(const OrchardMerkleNodeCache& cache,
                              uint8_t level,
                              uint64_t index,
                              uint256& node) const
    {
        const auto it = cache.find({level, index});
        if (it != cache.end()) {
            node = it->second;
            return true;
        }
        return ReadMerkleNode(level, index, node);
    }

    void WriteCachedMerkleNode(OrchardMerkleNodeCache& cache,
                               uint8_t level,
                               uint64_t index,
                               const uint256& node)
    {
        cache[{level, index}] = node;
    }

    void FlushMerkleNodes(CDBBatch& batch, const OrchardMerkleNodeCache& cache)
    {
        // Intermediate parents are needed by subsequent appends, but only
        // their final block state belongs in the durable batch.
        for (const auto& [position, node] : cache) {
            WriteMerkleNode(batch, position.first, position.second, node);
        }
    }

    bool SnapshotBoundaryMerkleNodes(const OrchardMerkleNodeCache& cache,
                                     uint64_t commitment_count,
                                     std::vector<OrchardMerkleNodeSnapshot>& boundary_nodes) const
    {
        boundary_nodes.clear();
        if (commitment_count == 0) return true;

        for (uint8_t level = 1; level < ORCHARD_MERKLE_DEPTH; ++level) {
            const uint64_t subtree_size{uint64_t{1} << level};
            if ((commitment_count % subtree_size) == 0) continue;

            const uint64_t index{(commitment_count - 1) >> level};
            if (index == 0) continue;

            uint256 node;
            if (!ReadCachedMerkleNode(cache, level, index, node)) {
                return error("%s: missing Orchard boundary Merkle node at level %u index %llu",
                             __func__, level, static_cast<unsigned long long>(index));
            }
            boundary_nodes.push_back(OrchardMerkleNodeSnapshot{level, index, node});
        }
        return true;
    }

    void WriteBoundaryMerkleNodes(CDBBatch& batch, const OrchardMerkleState& state)
    {
        for (const OrchardMerkleNodeSnapshot& snapshot : state.boundary_nodes) {
            WriteMerkleNode(batch, snapshot.level, snapshot.index, snapshot.node);
        }
    }

    bool AppendMerkleCommitment(CDBBatch& batch,
                                OrchardMerkleNodeCache& cache,
                                const uint256& commitment,
                                OrchardMerkleState& state)
    {
        if (state.commitment_count >= (uint64_t{1} << ORCHARD_MERKLE_DEPTH)) {
            return error("%s: Orchard commitment tree is full", __func__);
        }

        uint256 current{commitment};
        uint64_t node_index{state.commitment_count};
        WriteCommitmentIndex(batch, commitment, node_index);

        WriteCachedMerkleNode(cache, 0, node_index, current);

        for (uint8_t level = 0; level < ORCHARD_MERKLE_DEPTH; ++level) {
            uint256 left;
            uint256 right;

            if ((node_index & 1U) == 0) {
                left = current;
                if (!GetEmptyMerkleRoot(level, right)) return false;
            } else {
                if (!ReadCachedMerkleNode(cache, level, node_index - 1, left)) {
                    return error("%s: missing left Orchard Merkle node at level %u index %llu",
                                 __func__, level, static_cast<unsigned long long>(node_index - 1));
                }
                right = current;
            }

            uint256 parent;
            if (!CombineMerkleNodes(level, left, right, parent)) return false;

            node_index >>= 1;
            WriteCachedMerkleNode(cache, level + 1, node_index, parent);
            current = parent;
        }

        ++state.commitment_count;
        state.root = current;
        return true;
    }

    bool CopyDisconnectedHeightEntriesToHashIndex(int start_height, int stop_height)
    {
        if (start_height > stop_height) return true;

        CDBBatch batch{*this};
        std::unique_ptr<CDBIterator> it{NewIterator()};
        it->Seek(OrchardHeightKey{start_height});

        for (int height = start_height; height <= stop_height; ++height) {
            OrchardHeightKey key;
            if (!it->Valid() || !it->GetKey(key) || key.height != height) {
                return error("%s: missing orchard index height entry %d", __func__, height);
            }

            std::pair<uint256, OrchardBlockIndexEntry> value;
            if (!it->GetValue(value)) {
                return error("%s: unable to read orchard index height entry %d", __func__, height);
            }

            batch.Write(OrchardHashKey{value.first}, std::move(value.second));
            it->Next();
        }

        return WriteBatch(batch);
    }
};

OrchardIndex::OrchardIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "orchardindex"),
      m_db{std::make_unique<OrchardIndex::DB>(n_cache_size, Params().GetConsensus().privateTxActivationHeight, f_memory, f_wipe)},
      m_activation_height{Params().GetConsensus().privateTxActivationHeight}
{
}

OrchardIndex::~OrchardIndex() = default;

BaseIndex::DB& OrchardIndex::GetDB() const
{
    return *m_db;
}

bool OrchardIndex::CustomInit(const std::optional<interfaces::BlockKey>& block)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    if (m_activation_height < 0) return true;

    AssertLockHeld(cs_main);
    const CChain& active_chain = m_chainstate->m_chain;
    const int tip_height = active_chain.Height();

    OrchardMerkleState empty_state;
    if (!MakeEmptyMerkleState(empty_state)) return false;

    if (block) {
        uint32_t version{0};
        if (!m_db->ReadVersion(version) || version != ORCHARD_INDEX_DB_VERSION) {
            return error("%s: unsupported Orchard index schema; rebuild the index with -reindex", __func__);
        }
        int activation_height{-1};
        OrchardCurrentMerkleState current;
        if (!m_db->ReadActivationHeight(activation_height) || activation_height != m_activation_height) {
            // A schedule change before either activation can reuse a provably
            // empty index. Never discard post-activation data or repair corruption.
            if (!active_chain.Tip() || activation_height <= tip_height || m_activation_height <= tip_height ||
                block->height >= activation_height || block->height >= m_activation_height ||
                m_chainstate->m_blockman.NitoPrivateActivationObserved() ||
                !m_db->ReadPersistedCurrentState(current) ||
                current.height != block->height || current.hash != block->hash ||
                current.merkle_state != empty_state || m_db->HasPostActivationData()) {
                return InitError(Untranslated("Orchard index activation height does not match this network; rebuild the index with -reindex"));
            }

            // Persist only Orchard metadata and its empty checkpoint together.
            // No block replay or changes to any other database are needed.
            current = OrchardCurrentMerkleState{tip_height, active_chain.Tip()->GetBlockHash(), std::move(empty_state)};
            m_db->SetCurrentState(std::move(current));
            CDBBatch reset_batch{*m_db};
            m_db->WriteBestBlock(reset_batch, ::GetLocator(active_chain.Tip()));
            if (!m_db->WriteCurrentState(reset_batch) || !m_db->WriteBatch(reset_batch, /*fSync=*/true)) {
                return InitError(Untranslated("Unable to persist the reinitialized Orchard index."));
            }
            SetBestBlockIndex(active_chain.Tip());
            LogPrintf("%s: Reinitialized empty Orchard index for activation height change (%d -> %d) at height %d\n",
                      GetName(), activation_height, m_activation_height, tip_height);
            return true;
        }

        if (!m_db->ReadPersistedCurrentState(current)) {
            return error("%s: missing Orchard current state for locator height %d", __func__, block->height);
        }
        if (current.height != block->height || current.hash != block->hash) {
            if (!RecoveredFromLocator()) {
                return error("%s: Orchard current state does not match locator at height %d", __func__, block->height);
            }

            OrchardMerkleState recovered_state;
            if (block->height >= m_activation_height) {
                if (!m_db->ReadMerkleHeightState(block->height, block->hash, recovered_state)) {
                    return error("%s: missing Orchard Merkle state for recovered locator height %d", __func__, block->height);
                }
            } else {
                recovered_state = empty_state;
            }

            const CBlockIndex* recovered_block{active_chain[block->height]};
            if (!recovered_block || recovered_block->GetBlockHash() != block->hash) {
                return error("%s: recovered Orchard locator is not on the active chain at height %d", __func__, block->height);
            }

            current = OrchardCurrentMerkleState{block->height, block->hash, std::move(recovered_state)};
            m_db->SetCurrentState(current);

            CDBBatch repair_batch{*m_db};
            m_db->WriteBoundaryMerkleNodes(repair_batch, current.merkle_state);
            if (!m_db->WriteCurrentState(repair_batch)) {
                return error("%s: unable to stage recovered Orchard state at height %d", __func__, block->height);
            }
            m_db->WriteBestBlock(repair_batch, ::GetLocator(recovered_block));
            if (!m_db->WriteBatch(repair_batch)) {
                return error("%s: unable to persist recovered Orchard state at height %d", __func__, block->height);
            }

            LogPrintf("%s: recovered Orchard state and locator at durable height %d\n", GetName(), block->height);
            return true;
        }

        if (block->height >= m_activation_height) {
            OrchardMerkleState snapshot;
            if (!m_db->ReadMerkleHeightState(block->height, block->hash, snapshot) || snapshot != current.merkle_state) {
                return error("%s: Orchard current state does not match the exact locator snapshot at height %d", __func__, block->height);
            }
        } else if (current.merkle_state != empty_state) {
            return error("%s: non-empty Orchard state before activation at height %d", __func__, block->height);
        }

        m_db->SetCurrentState(current);

        // An append may have reached LevelDB immediately before an abrupt
        // process stop, while its state/locator commit did not. Restore the
        // boundary nodes selected by the durable current state before serving
        // authentication paths or resuming appends.
        CDBBatch repair_batch{*m_db};
        m_db->WriteBoundaryMerkleNodes(repair_batch, current.merkle_state);
        if (!m_db->WriteBatch(repair_batch)) {
            return error("%s: unable to restore Orchard boundary nodes at height %d", __func__, block->height);
        }
        return true;
    }

    OrchardCurrentMerkleState current;
    current.merkle_state = std::move(empty_state);
    if (tip_height >= 0 && m_activation_height > 0) {
        const int seed_height = std::min(tip_height, m_activation_height - 1);
        const CBlockIndex* seed_block{active_chain[seed_height]};
        current.height = seed_height;
        current.hash = seed_block->GetBlockHash();
        SetBestBlockIndex(seed_block);
    }
    m_db->SetCurrentState(std::move(current));
    return true;
}

bool OrchardIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    if (m_activation_height < 0) return true;

    assert(block.data);

    OrchardCurrentMerkleState current;
    if (!m_db->GetCurrentState(current)) {
        return error("%s: Orchard current state is not initialized", __func__);
    }
    if (current.height != block.height - 1) {
        return error("%s: Orchard append height %d does not follow current height %d", __func__, block.height, current.height);
    }
    if (block.height > 0 && (!block.prev_hash || current.hash != *block.prev_hash)) {
        return error("%s: Orchard append at height %d does not extend the current state", __func__, block.height);
    }

    if (block.height < m_activation_height) {
        current.height = block.height;
        current.hash = block.hash;
        m_db->SetCurrentState(std::move(current));
        return true;
    }

    OrchardBlockIndexEntry entry;
    entry.txs.reserve(block.data->vtx.size());
    std::vector<uint256> commitments;
    for (size_t pos = 0; pos < block.data->vtx.size(); ++pos) {
        const CTransaction& tx = *block.data->vtx[pos];
        if (tx.HasPrivateBundle()) {
            entry.txs.push_back(MakeRecord(static_cast<int32_t>(pos), tx));
            for (const auto& action : tx.m_private_bundle->effects.actions) {
                commitments.push_back(action.cmx);
            }
        }
    }

    OrchardMerkleState state{current.merkle_state};

    CDBBatch batch{*m_db};
    m_db->WriteBlockEntry(batch, block.height, block.hash, entry);
    // Retain only Orchard-bearing transactions, not complete blocks. These
    // public bytes let a locked wallet hydrate matching compact records later.
    // The block hash in the key keeps old and replacement branches separate.
    for (const auto& record : entry.txs) {
        batch.Write(std::make_pair(DB_ORCHARD_TRANSACTION, std::make_pair(block.hash, record.block_position)),
                    OrchardStoredTransaction{block.data->vtx[record.block_position]});
    }
    if (commitments.empty()) {
        m_db->WriteMerkleHeightState(batch, block.height, block.hash, state);
    } else {
        OrchardMerkleNodeCache merkle_node_cache;
        for (const uint256& commitment : commitments) {
            if (!m_db->AppendMerkleCommitment(batch, merkle_node_cache, commitment, state)) return false;
        }
        if (!m_db->SnapshotBoundaryMerkleNodes(merkle_node_cache, state.commitment_count, state.boundary_nodes)) return false;
        m_db->FlushMerkleNodes(batch, merkle_node_cache);
        m_db->WriteMerkleHeightState(batch, block.height, block.hash, state);
    }

    LogPrint(BCLog::BENCH, "orchardindex: append height=%d commitments=%u batch_bytes=%u\n",
             block.height, commitments.size(), batch.SizeEstimate());
    if (!m_db->WriteBatch(batch)) return false;
    current.height = block.height;
    current.hash = block.hash;
    current.merkle_state = std::move(state);
    m_db->SetCurrentState(std::move(current));
    return true;
}

bool OrchardIndex::CustomCommit(CDBBatch& batch)
{
    if (m_activation_height < 0) return true;

    OrchardCurrentMerkleState current;
    if (!m_db->GetCurrentState(current)) {
        return error("%s: Orchard current state is not initialized", __func__);
    }
    m_db->WriteBoundaryMerkleNodes(batch, current.merkle_state);
    return m_db->WriteCurrentState(batch);
}

bool OrchardIndex::CustomRewind(const interfaces::BlockKey& current_tip, const interfaces::BlockKey& new_tip)
{
    if (m_activation_height < 0) return true;

    if (!m_db->CopyDisconnectedHeightEntriesToHashIndex(std::max(m_activation_height, new_tip.height + 1), current_tip.height)) {
        return false;
    }

    OrchardMerkleState state;
    if (m_activation_height >= 0 && new_tip.height >= m_activation_height) {
        if (!m_db->ReadMerkleHeightState(new_tip.height, new_tip.hash, state)) {
            return error("%s: missing Orchard Merkle state for rewound tip height %d", __func__, new_tip.height);
        }
    } else if (!MakeEmptyMerkleState(state)) {
        return false;
    }

    m_db->SetCurrentState(OrchardCurrentMerkleState{new_tip.height, new_tip.hash, std::move(state)});
    return true;
}

bool OrchardIndex::LookupBlockTransactions(const CBlockIndex* block_index, std::vector<interfaces::OrchardIndexedTransaction>& txs) const
{
    txs.clear();
    if (!block_index) return false;
    if (m_activation_height < 0 || block_index->nHeight < m_activation_height) return true;

    OrchardBlockIndexEntry entry;
    if (!m_db->ReadBlockEntry(block_index, entry)) return false;

    txs.reserve(entry.txs.size());
    int32_t last_position{-1};
    for (const auto& record : entry.txs) {
        if (record.block_position <= last_position) {
            return error("%s: non-increasing compact Orchard transaction positions at height %d", __func__, block_index->nHeight);
        }
        if (!ValidateRecord(record, block_index->nHeight)) return false;
        last_position = record.block_position;

        interfaces::OrchardIndexedTransaction indexed;
        indexed.block_position = record.block_position;
        indexed.txid = record.txid;
        indexed.effects_hash = record.effects_hash;
        indexed.effects = record.effects;
        txs.push_back(std::move(indexed));
    }
    return true;
}

CTransactionRef OrchardIndex::LookupTransaction(const CBlockIndex* block_index, int32_t position) const
{
    if (!block_index || position < 0) return {};
    std::vector<interfaces::OrchardIndexedTransaction> records;
    if (!LookupBlockTransactions(block_index, records)) return {};
    const auto found = std::find_if(records.begin(), records.end(),
        [position](const auto& record) { return record.block_position == position; });
    if (found == records.end()) return {};

    OrchardStoredTransaction stored;
    if (!m_db->Read(std::make_pair(DB_ORCHARD_TRANSACTION, std::make_pair(block_index->GetBlockHash(), position)), stored) ||
        !stored.tx || stored.tx->GetHash() != found->txid || !stored.tx->HasPrivateBundle() ||
        stored.tx->m_private_bundle->GetEffectsHash() != found->effects_hash) return {};
    return stored.tx;
}

bool OrchardIndex::LookupCommitmentIndex(const uint256& commitment,
                                         uint64_t& commitment_index,
                                         uint256& root,
                                         uint64_t& commitment_count) const
{
    commitment_index = 0;
    root.SetNull();
    commitment_count = 0;

    OrchardMerkleState state;
    if (!m_db->ReadMerkleState(state)) return false;
    commitment_count = state.commitment_count;
    root = state.root;
    if (commitment_count > (uint64_t{1} << ORCHARD_MERKLE_DEPTH)) return false;

    uint64_t index{0};
    if (!m_db->ReadCommitmentIndex(commitment, index)) return false;
    if (index >= commitment_count) return false;

    uint256 leaf;
    if (!m_db->ReadMerkleNode(0, index, leaf) || leaf != commitment) return false;

    commitment_index = index;
    return true;
}

bool OrchardIndex::LookupMerkleAuthPaths(const std::vector<uint64_t>& commitment_indices,
                                         std::vector<std::vector<uint256>>& auth_paths,
                                         uint256& root,
                                         uint64_t& commitment_count) const
{
    auth_paths.clear();
    root.SetNull();
    commitment_count = 0;
    if (commitment_indices.empty()) return false;

    OrchardMerkleState state;
    if (!m_db->ReadMerkleState(state)) return false;
    commitment_count = state.commitment_count;
    root = state.root;
    if (commitment_count > (uint64_t{1} << ORCHARD_MERKLE_DEPTH)) return false;

    for (uint64_t commitment_index : commitment_indices) {
        if (commitment_index >= commitment_count) return false;
    }

    auth_paths.reserve(commitment_indices.size());
    for (uint64_t commitment_index : commitment_indices) {
        std::vector<uint256> path;
        path.reserve(ORCHARD_MERKLE_DEPTH);
        uint64_t node_index{commitment_index};

        for (uint8_t level = 0; level < ORCHARD_MERKLE_DEPTH; ++level) {
            const uint64_t sibling_index = node_index ^ 1U;
            uint256 sibling;
            if (!m_db->ReadMerkleNodeOrEmpty(level, sibling_index, commitment_count, sibling)) {
                auth_paths.clear();
                return error("%s: missing Orchard Merkle sibling at level %u index %llu",
                             __func__, level, static_cast<unsigned long long>(sibling_index));
            }
            path.push_back(sibling);
            node_index >>= 1;
        }

        auth_paths.push_back(std::move(path));
    }

    return true;
}

OrchardIndex* GetOrchardIndex()
{
    return g_orchard_index.get();
}

bool InitOrchardIndex(std::function<std::unique_ptr<interfaces::Chain>()> make_chain, size_t n_cache_size, bool f_memory, bool f_wipe)
{
    if (g_orchard_index) return false;
    g_orchard_index = std::make_unique<OrchardIndex>(make_chain(), n_cache_size, f_memory, f_wipe);
    return true;
}

void DestroyOrchardIndex()
{
    g_orchard_index.reset();
}
