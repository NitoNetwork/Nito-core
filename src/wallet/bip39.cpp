// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/bip39.h>

#include <crypto/hmac_sha512.h>
#include <crypto/sha256.h>
#include <span.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <util/string.h>
#include <util/translation.h>

#if defined(_WIN32) && !defined(UTF8PROC_STATIC)
#define UTF8PROC_STATIC
#endif
#include <utf8proc.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace wallet {
namespace {

#include <wallet/bip39_english.inc>

constexpr size_t BIP39_ENTROPY_BYTES_12_WORDS{16};
constexpr size_t BIP39_ENTROPY_BYTES_24_WORDS{32};
constexpr size_t BIP39_METADATA_KEY_BYTES{32};
constexpr size_t BIP39_WORD_COUNT_12{12};
constexpr size_t BIP39_WORD_COUNT_24{24};
constexpr size_t BIP39_WORD_BITS{11};
constexpr unsigned int BIP39_PBKDF2_ROUNDS{2048};
constexpr std::array<unsigned char, 4> BIP39_METADATA_MAGIC{{0x4e, 0x49, 0x54, 0x4f}}; // NITO
constexpr size_t BIP39_METADATA_VERSION_OFFSET{4};
constexpr size_t BIP39_METADATA_WORD_COUNT_OFFSET{5};
constexpr size_t BIP39_METADATA_ENTROPY_OFFSET{6};
constexpr size_t BIP39_METADATA_CHECKSUM_OFFSET{22};
constexpr size_t BIP39_METADATA_CHECKSUM_BYTES{BIP39_METADATA_KEY_BYTES - BIP39_METADATA_CHECKSUM_OFFSET};
static_assert((BIP39_ENTROPY_BYTES_12_WORDS * 8 + BIP39_ENTROPY_BYTES_12_WORDS * 8 / 32) / BIP39_WORD_BITS == BIP39_WORD_COUNT_12);
static_assert((BIP39_ENTROPY_BYTES_24_WORDS * 8 + BIP39_ENTROPY_BYTES_24_WORDS * 8 / 32) / BIP39_WORD_BITS == BIP39_WORD_COUNT_24);

bool GetBit(Span<const unsigned char> data, size_t bit)
{
    return (data[bit / 8] >> (7 - (bit % 8))) & 1;
}

void SetBit(std::vector<unsigned char>& data, size_t bit, bool value)
{
    if (value) {
        data[bit / 8] |= static_cast<unsigned char>(1U << (7 - (bit % 8)));
    }
}

std::array<unsigned char, 32> Sha256(Span<const unsigned char> data)
{
    std::array<unsigned char, 32> hash{};
    CSHA256().Write(data.data(), data.size()).Finalize(hash.data());
    return hash;
}

std::string NormalizeMnemonicWord(std::string word)
{
    for (char& c : word) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return word;
}

std::vector<std::string> SplitMnemonic(const std::string& mnemonic)
{
    std::istringstream stream{mnemonic};
    std::vector<std::string> words;
    std::string word;
    while (stream >> word) {
        words.push_back(NormalizeMnemonicWord(word));
    }
    return words;
}

std::optional<uint16_t> LookupWord(const std::string& word)
{
    for (uint16_t i = 0; i < 2048; ++i) {
        if (word == BIP39_ENGLISH_WORDS[i]) return i;
    }
    return std::nullopt;
}

bool IsSupportedWordCount(size_t words)
{
    return words == BIP39_WORD_COUNT_12 || words == BIP39_WORD_COUNT_24;
}

size_t EntropyBytesForWordCount(size_t words)
{
    return words == BIP39_WORD_COUNT_12 ? BIP39_ENTROPY_BYTES_12_WORDS : BIP39_ENTROPY_BYTES_24_WORDS;
}

size_t ChecksumBitsForEntropyBytes(size_t entropy_bytes)
{
    return entropy_bytes * 8 / 32;
}

size_t WordCountForEntropyBytes(size_t entropy_bytes)
{
    return (entropy_bytes * 8 + ChecksumBitsForEntropyBytes(entropy_bytes)) / BIP39_WORD_BITS;
}

util::Result<std::vector<unsigned char>> DecodeBIP39Entropy(const std::string& mnemonic)
{
    const std::vector<std::string> words = SplitMnemonic(mnemonic);
    if (!IsSupportedWordCount(words.size())) {
        return util::Error{strprintf(_("Expected a BIP39 English mnemonic with 12 or 24 words, got %u words."), static_cast<unsigned>(words.size()))};
    }

    const size_t entropy_bytes = EntropyBytesForWordCount(words.size());
    const size_t entropy_bits = entropy_bytes * 8;
    const size_t checksum_bits = ChecksumBitsForEntropyBytes(entropy_bytes);
    std::vector<unsigned char> data(entropy_bytes + 1, 0);
    for (size_t i = 0; i < words.size(); ++i) {
        const auto index = LookupWord(words[i]);
        if (!index) {
            return util::Error{strprintf(_("Unknown BIP39 English mnemonic word: %s"), words[i])};
        }
        for (size_t j = 0; j < BIP39_WORD_BITS; ++j) {
            SetBit(data, i * BIP39_WORD_BITS + j, (*index >> (BIP39_WORD_BITS - 1 - j)) & 1);
        }
    }

    std::vector<unsigned char> entropy(entropy_bytes);
    std::copy_n(data.begin(), entropy.size(), entropy.begin());
    const auto checksum = Sha256(Span<const unsigned char>{entropy.data(), entropy.size()});
    const Span<const unsigned char> checksum_span{checksum.data(), checksum.size()};
    const Span<const unsigned char> data_span{data.data(), data.size()};
    for (size_t bit = 0; bit < checksum_bits; ++bit) {
        if (GetBit(data_span, entropy_bits + bit) != GetBit(checksum_span, bit)) {
            memory_cleanse(data.data(), data.size());
            memory_cleanse(entropy.data(), entropy.size());
            return util::Error{_("Invalid BIP39 mnemonic checksum.")};
        }
    }

    memory_cleanse(data.data(), data.size());
    return entropy;
}

util::Result<std::string> EncodeBIP39Entropy(Span<const unsigned char> entropy)
{
    if (entropy.size() != BIP39_ENTROPY_BYTES_12_WORDS && entropy.size() != BIP39_ENTROPY_BYTES_24_WORDS) {
        return util::Error{_("Nito.network mnemonic export requires 16-byte or 32-byte BIP39 entropy.")};
    }

    const auto checksum = Sha256(entropy);
    const Span<const unsigned char> checksum_span{checksum.data(), checksum.size()};
    const size_t word_count = WordCountForEntropyBytes(entropy.size());
    std::vector<std::string> words;
    words.reserve(word_count);

    for (size_t i = 0; i < word_count; ++i) {
        uint16_t index{0};
        for (size_t j = 0; j < BIP39_WORD_BITS; ++j) {
            const size_t bit = i * BIP39_WORD_BITS + j;
            const bool value = bit < entropy.size() * 8 ? GetBit(entropy, bit) : GetBit(checksum_span, bit - entropy.size() * 8);
            index = static_cast<uint16_t>((index << 1) | (value ? 1 : 0));
        }
        words.emplace_back(BIP39_ENGLISH_WORDS[index]);
    }

    return Join(words, " ");
}

util::Result<CKey> MakeBIP39EntropyKey(Span<const unsigned char> entropy)
{
    std::array<unsigned char, BIP39_METADATA_KEY_BYTES> key_bytes{};
    if (entropy.size() == BIP39_ENTROPY_BYTES_24_WORDS) {
        // Otherwise this 24-word phrase could be exported and derived as a
        // different 12-word phrase by DecodeBIP39EntropyKey.
        if (std::equal(BIP39_METADATA_MAGIC.begin(), BIP39_METADATA_MAGIC.end(), entropy.begin()) &&
            entropy[BIP39_METADATA_VERSION_OFFSET] == 1 &&
            entropy[BIP39_METADATA_WORD_COUNT_OFFSET] == BIP39_WORD_COUNT_12) {
            return util::Error{_("This 24-word phrase uses reserved Nito seed metadata and cannot be imported.")};
        }
        std::copy(entropy.begin(), entropy.end(), key_bytes.begin());
    } else if (entropy.size() == BIP39_ENTROPY_BYTES_12_WORDS) {
        std::copy(BIP39_METADATA_MAGIC.begin(), BIP39_METADATA_MAGIC.end(), key_bytes.begin());
        key_bytes[BIP39_METADATA_VERSION_OFFSET] = 1;
        key_bytes[BIP39_METADATA_WORD_COUNT_OFFSET] = static_cast<unsigned char>(BIP39_WORD_COUNT_12);
        std::copy(entropy.begin(), entropy.end(), key_bytes.begin() + BIP39_METADATA_ENTROPY_OFFSET);
        const auto metadata_checksum = Sha256(Span<const unsigned char>{key_bytes.data(), BIP39_METADATA_CHECKSUM_OFFSET});
        std::copy_n(metadata_checksum.begin(), BIP39_METADATA_CHECKSUM_BYTES, key_bytes.begin() + BIP39_METADATA_CHECKSUM_OFFSET);
    } else {
        return util::Error{_("Nito.network mnemonic metadata requires 12-word or 24-word BIP39 entropy.")};
    }

    CKey key;
    key.Set(key_bytes.begin(), key_bytes.end(), true);
    memory_cleanse(key_bytes.data(), key_bytes.size());
    if (!key.IsValid()) {
        return util::Error{_("BIP39 mnemonic entropy is not valid Nito HD seed key material.")};
    }
    return key;
}

util::Result<std::vector<unsigned char>> DecodeBIP39EntropyKey(const CKey& hd_seed)
{
    if (!hd_seed.IsValid()) {
        return util::Error{_("Cannot export an invalid HD seed as a mnemonic.")};
    }

    const auto seed_bytes = MakeUCharSpan(hd_seed);
    if (seed_bytes.size() != BIP39_METADATA_KEY_BYTES) {
        return util::Error{_("Nito.network mnemonic export requires a 32-byte HD seed metadata key.")};
    }

    const bool is_metadata_key = std::equal(BIP39_METADATA_MAGIC.begin(), BIP39_METADATA_MAGIC.end(), seed_bytes.begin()) &&
        seed_bytes[BIP39_METADATA_VERSION_OFFSET] == 1 &&
        seed_bytes[BIP39_METADATA_WORD_COUNT_OFFSET] == BIP39_WORD_COUNT_12;
    if (is_metadata_key) {
        const auto metadata_checksum = Sha256(Span<const unsigned char>{seed_bytes.data(), BIP39_METADATA_CHECKSUM_OFFSET});
        if (!std::equal(metadata_checksum.begin(), metadata_checksum.begin() + BIP39_METADATA_CHECKSUM_BYTES, seed_bytes.begin() + BIP39_METADATA_CHECKSUM_OFFSET)) {
            return util::Error{_("Nito.network mnemonic seed metadata checksum is invalid.")};
        }
        return std::vector<unsigned char>{
            seed_bytes.begin() + BIP39_METADATA_ENTROPY_OFFSET,
            seed_bytes.begin() + BIP39_METADATA_ENTROPY_OFFSET + BIP39_ENTROPY_BYTES_12_WORDS};
    }

    return std::vector<unsigned char>{seed_bytes.begin(), seed_bytes.end()};
}

BIP39Seed PBKDF2HMACSHA512(const std::string& password, const SecureString& normalized_passphrase)
{
    std::array<unsigned char, CHMAC_SHA512::OUTPUT_SIZE> u{};
    std::array<unsigned char, CHMAC_SHA512::OUTPUT_SIZE> t{};
    static constexpr std::string_view BIP39_SALT_PREFIX{"mnemonic"};
    std::vector<unsigned char, secure_allocator<unsigned char>> salt_block;
    salt_block.reserve(BIP39_SALT_PREFIX.size() + normalized_passphrase.size() + 4);
    salt_block.insert(salt_block.end(), BIP39_SALT_PREFIX.begin(), BIP39_SALT_PREFIX.end());
    salt_block.insert(salt_block.end(), normalized_passphrase.begin(), normalized_passphrase.end());
    salt_block.push_back(0x00);
    salt_block.push_back(0x00);
    salt_block.push_back(0x00);
    salt_block.push_back(0x01);

    const auto* password_data = reinterpret_cast<const unsigned char*>(password.data());
    CHMAC_SHA512(password_data, password.size()).Write(salt_block.data(), salt_block.size()).Finalize(u.data());
    t = u;

    for (unsigned int round = 1; round < BIP39_PBKDF2_ROUNDS; ++round) {
        CHMAC_SHA512(password_data, password.size()).Write(u.data(), u.size()).Finalize(u.data());
        for (size_t i = 0; i < t.size(); ++i) {
            t[i] ^= u[i];
        }
    }

    BIP39Seed seed{};
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] = std::byte{t[i]};
    }
    memory_cleanse(u.data(), u.size());
    memory_cleanse(t.data(), t.size());
    memory_cleanse(salt_block.data(), salt_block.size());
    return seed;
}

} // namespace

bool LooksLikeBIP39Mnemonic(const std::string& mnemonic)
{
    return IsSupportedWordCount(SplitMnemonic(mnemonic).size());
}

util::Result<CKey> DecodeBIP39Mnemonic(const std::string& mnemonic)
{
    auto entropy = DecodeBIP39Entropy(mnemonic);
    if (!entropy) {
        return util::Error{util::ErrorString(entropy)};
    }
    auto key = MakeBIP39EntropyKey(Span<const unsigned char>{entropy->data(), entropy->size()});
    memory_cleanse(entropy->data(), entropy->size());
    return key;
}

util::Result<std::string> EncodeBIP39Mnemonic(const CKey& hd_seed)
{
    auto entropy = DecodeBIP39EntropyKey(hd_seed);
    if (!entropy) {
        return util::Error{util::ErrorString(entropy)};
    }
    auto mnemonic = EncodeBIP39Entropy(Span<const unsigned char>{entropy->data(), entropy->size()});
    memory_cleanse(entropy->data(), entropy->size());
    return mnemonic;
}

util::Result<std::string> NormalizeBIP39Mnemonic(const std::string& mnemonic)
{
    auto key = DecodeBIP39Mnemonic(mnemonic);
    if (!key) {
        return util::Error{util::ErrorString(key)};
    }
    return EncodeBIP39Mnemonic(*key);
}

util::Result<SecureString> NormalizeBIP39Passphrase(const SecureString& passphrase)
{
    if (passphrase.size() > MAX_BIP39_PASSPHRASE_SIZE) {
        return util::Error{strprintf(_("BIP39 passphrase exceeds the maximum of %u UTF-8 bytes."), static_cast<unsigned>(MAX_BIP39_PASSPHRASE_SIZE))};
    }
    if (std::find(passphrase.begin(), passphrase.end(), '\0') != passphrase.end()) {
        return util::Error{_("BIP39 passphrase must not contain a NUL character.")};
    }
    if (passphrase.size() > static_cast<size_t>(std::numeric_limits<utf8proc_ssize_t>::max())) {
        return util::Error{_("BIP39 passphrase is too large to normalize.")};
    }

    utf8proc_uint8_t* normalized_raw{nullptr};
    const auto options = static_cast<utf8proc_option_t>(UTF8PROC_STABLE | UTF8PROC_COMPAT | UTF8PROC_DECOMPOSE);
    const utf8proc_ssize_t normalized_size = utf8proc_map(
        reinterpret_cast<const utf8proc_uint8_t*>(passphrase.data()),
        static_cast<utf8proc_ssize_t>(passphrase.size()),
        &normalized_raw,
        options);
    if (normalized_size < 0) {
        std::free(normalized_raw);
        return util::Error{_("BIP39 passphrase is not valid UTF-8.")};
    }

    auto clear_normalized = [&]() {
        if (normalized_raw != nullptr) {
            if (normalized_size > 0) memory_cleanse(normalized_raw, static_cast<size_t>(normalized_size));
            std::free(normalized_raw);
            normalized_raw = nullptr;
        }
    };
    if (static_cast<size_t>(normalized_size) > MAX_BIP39_PASSPHRASE_SIZE) {
        clear_normalized();
        return util::Error{strprintf(_("BIP39 passphrase exceeds the maximum of %u UTF-8 bytes after NFKD normalization."), static_cast<unsigned>(MAX_BIP39_PASSPHRASE_SIZE))};
    }

    SecureString normalized;
    try {
        normalized.assign(reinterpret_cast<const char*>(normalized_raw), static_cast<size_t>(normalized_size));
    } catch (...) {
        clear_normalized();
        throw;
    }
    clear_normalized();
    return normalized;
}

util::Result<BIP39Seed> DeriveBIP39SeedFromMnemonic(const std::string& mnemonic)
{
    const SecureString empty_passphrase;
    return DeriveBIP39SeedFromMnemonic(mnemonic, empty_passphrase);
}

util::Result<BIP39Seed> DeriveBIP39SeedFromMnemonic(const std::string& mnemonic, const SecureString& passphrase)
{
    auto normalized = NormalizeBIP39Mnemonic(mnemonic);
    if (!normalized) {
        return util::Error{util::ErrorString(normalized)};
    }
    auto normalized_passphrase = NormalizeBIP39Passphrase(passphrase);
    if (!normalized_passphrase) {
        memory_cleanse(normalized->data(), normalized->size());
        return util::Error{util::ErrorString(normalized_passphrase)};
    }
    BIP39Seed seed{PBKDF2HMACSHA512(*normalized, *normalized_passphrase)};
    memory_cleanse(normalized->data(), normalized->size());
    ClearBIP39Passphrase(*normalized_passphrase);
    return seed;
}

util::Result<BIP39Seed> DeriveBIP39SeedFromEntropyKey(const CKey& hd_seed)
{
    const SecureString empty_passphrase;
    return DeriveBIP39SeedFromEntropyKey(hd_seed, empty_passphrase);
}

util::Result<BIP39Seed> DeriveBIP39SeedFromEntropyKey(const CKey& hd_seed, const SecureString& passphrase)
{
    auto mnemonic = EncodeBIP39Mnemonic(hd_seed);
    if (!mnemonic) {
        return util::Error{util::ErrorString(mnemonic)};
    }
    auto seed = DeriveBIP39SeedFromMnemonic(*mnemonic, passphrase);
    memory_cleanse(mnemonic->data(), mnemonic->size());
    return seed;
}

CExtKey MakeBIP39MasterKey(const BIP39Seed& seed)
{
    CExtKey master_key;
    master_key.SetSeed(Span<const std::byte>{seed.data(), seed.size()});
    return master_key;
}

util::Result<CExtKey> MakeBIP39MasterKeyFromEntropyKey(const CKey& hd_seed)
{
    const SecureString empty_passphrase;
    return MakeBIP39MasterKeyFromEntropyKey(hd_seed, empty_passphrase);
}

util::Result<CExtKey> MakeBIP39MasterKeyFromEntropyKey(const CKey& hd_seed, const SecureString& passphrase)
{
    auto seed = DeriveBIP39SeedFromEntropyKey(hd_seed, passphrase);
    if (!seed) {
        return util::Error{util::ErrorString(seed)};
    }

    CExtKey master_key{MakeBIP39MasterKey(*seed)};
    ClearBIP39Seed(*seed);
    return master_key;
}

void ClearBIP39Seed(BIP39Seed& seed)
{
    memory_cleanse(seed.data(), seed.size());
}

BIP39SeedGuard::~BIP39SeedGuard()
{
    ClearBIP39Seed(m_seed);
}

void ClearBIP39Passphrase(SecureString& passphrase)
{
    if (!passphrase.empty()) memory_cleanse(passphrase.data(), passphrase.size());
    passphrase.clear();
}

} // namespace wallet
