// Copyright (c) 2019-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <clientversion.h>
#include <common/args.h>
#include <flatfile.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/fs_helpers.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(flatfile_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(flatfile_filename)
{
    const auto data_dir = m_args.GetDataDirBase();

    FlatFilePos pos(456, 789);

    FlatFileSeq seq1(data_dir, "a", 16 * 1024);
    BOOST_CHECK_EQUAL(seq1.FileName(pos), data_dir / "a00456.dat");

    FlatFileSeq seq2(data_dir / "a", "b", 16 * 1024);
    BOOST_CHECK_EQUAL(seq2.FileName(pos), data_dir / "a" / "b00456.dat");

    // Check default constructor IsNull
    assert(FlatFilePos{}.IsNull());
}

BOOST_AUTO_TEST_CASE(flatfile_open)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 16 * 1024);

    std::string line1("A purely peer-to-peer version of electronic cash would allow online "
                      "payments to be sent directly from one party to another without going "
                      "through a financial institution.");
    std::string line2("Digital signatures provide part of the solution, but the main benefits are "
                      "lost if a trusted third party is still required to prevent double-spending.");

    size_t pos1 = 0;
    size_t pos2 = pos1 + GetSerializeSize(line1);

    // Write first line to file.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos1))};
        file << LIMITED_STRING(line1, 256);
    }

    // Attempt to append to file opened in read-only mode.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos2), true)};
        BOOST_CHECK_THROW(file << LIMITED_STRING(line2, 256), std::ios_base::failure);
    }

    // Append second line to file.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos2))};
        file << LIMITED_STRING(line2, 256);
    }

    // Read text from file in read-only mode.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(0, pos1), true)};

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line1);

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line2);
    }

    // Read text from file with position offset.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(0, pos2))};

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line2);
    }

    // Ensure another file in the sequence has no data.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(1, pos2))};
        BOOST_CHECK_THROW(file >> LIMITED_STRING(text, 256), std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(flatfile_large_position)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "large", 16 * 1024);
    constexpr uint64_t large_pos = (uint64_t{1} << 32) + 123;

    AutoFile file{seq.Open(FlatFilePos{0, large_pos})};
    BOOST_REQUIRE(!file.IsNull());
    BOOST_CHECK_EQUAL(FileTell64(file.Get()), large_pos);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos{0, 0})), 0U);
}

BOOST_AUTO_TEST_CASE(flatfile_64bit_serialization)
{
    constexpr uint64_t large_pos = (uint64_t{1} << 32) + 123;

    const FlatFilePos original_pos{7, large_pos};
    DataStream pos_stream{};
    pos_stream << original_pos;
    FlatFilePos decoded_pos;
    pos_stream >> decoded_pos;
    BOOST_CHECK_EQUAL(decoded_pos.nFile, original_pos.nFile);
    BOOST_CHECK_EQUAL(decoded_pos.nPos, original_pos.nPos);

    CBlockFileInfo original_info;
    original_info.nBlocks = 2;
    original_info.nSize = large_pos;
    original_info.nUndoSize = large_pos + 456;
    original_info.nHeightFirst = 1;
    original_info.nHeightLast = 2;
    original_info.nTimeFirst = 3;
    original_info.nTimeLast = 4;

    DataStream info_stream{};
    info_stream << original_info;
    CBlockFileInfo decoded_info;
    info_stream >> decoded_info;
    BOOST_CHECK_EQUAL(decoded_info.nSize, original_info.nSize);
    BOOST_CHECK_EQUAL(decoded_info.nUndoSize, original_info.nUndoSize);

    CDiskBlockIndex original_index;
    original_index.nStatus = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
    original_index.nFile = 3;
    original_index.nDataPos = large_pos;
    original_index.nUndoPos = large_pos + 789;

    DataStream index_stream{};
    index_stream << original_index;
    CDiskBlockIndex decoded_index;
    index_stream >> decoded_index;
    BOOST_CHECK_EQUAL(decoded_index.nDataPos, original_index.nDataPos);
    BOOST_CHECK_EQUAL(decoded_index.nUndoPos, original_index.nUndoPos);
}

BOOST_AUTO_TEST_CASE(flatfile_position_serialization_compatibility)
{
    constexpr int file_number = 9;
    constexpr uint32_t legacy_pos = 123456789;

    DataStream widened_stream{};
    widened_stream << FlatFilePos{file_number, legacy_pos};

    DataStream legacy_stream{};
    int legacy_file_number = file_number;
    uint32_t legacy_position = legacy_pos;
    legacy_stream << VARINT_MODE(legacy_file_number, VarIntMode::NONNEGATIVE_SIGNED);
    legacy_stream << VARINT(legacy_position);

    BOOST_CHECK_EQUAL_COLLECTIONS(widened_stream.begin(), widened_stream.end(),
                                  legacy_stream.begin(), legacy_stream.end());
}

BOOST_AUTO_TEST_CASE(flatfile_allocate)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 100);

    bool out_of_space;

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 0), 1, out_of_space), 100U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 0))), 100U);
    BOOST_CHECK(!out_of_space);

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 99), 1, out_of_space), 0U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 99))), 100U);
    BOOST_CHECK(!out_of_space);

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 99), 2, out_of_space), 101U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 99))), 200U);
    BOOST_CHECK(!out_of_space);
}

BOOST_AUTO_TEST_CASE(flatfile_flush)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 100);

    bool out_of_space;
    seq.Allocate(FlatFilePos(0, 0), 1, out_of_space);

    // Flush without finalize should not truncate file.
    seq.Flush(FlatFilePos(0, 1));
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 1))), 100U);

    // Flush with finalize should truncate file.
    seq.Flush(FlatFilePos(0, 1), true);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 1))), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
