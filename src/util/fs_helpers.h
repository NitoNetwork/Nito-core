// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2023 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_FS_HELPERS_H
#define BITCOIN_UTIL_FS_HELPERS_H

#include <util/fs.h>

#include <cstdint>
#include <cstdio>
#include <iosfwd>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

/**
 * Ensure file contents are fully committed to disk, using a platform-specific
 * feature analogous to fsync().
 */
bool FileCommit(FILE* file);

/**
 * Sync directory contents. This is required on some environments to ensure that
 * newly created files are committed to disk.
 */
void DirectoryCommit(const fs::path& dirname);

bool TruncateFile(FILE* file, uint64_t length);

/**
 * Return whether a filesystem type is known to support files larger than
 * 4 GiB. Unknown filesystem types are accepted; FAT variants with a 4 GiB
 * per-file limit are rejected.
 */
bool FileSystemSupportsLargeFiles(std::string_view filesystem_type);

/**
 * Return the filesystem type when the directory is on a filesystem that is
 * known not to support files larger than 4 GiB. Detection failures and
 * supported filesystems return std::nullopt.
 */
std::optional<std::string> GetLargeFileIncompatibleFileSystem(const fs::path& directory);

/**
 * 64-bit-clean file positioning.
 *
 * These wrappers are necessary on Windows, where long remains 32 bits in
 * 64-bit builds.
 */
inline int FileSeek64(FILE* file, int64_t offset, int origin)
{
#if defined(WIN32)
    return _fseeki64(file, offset, origin);
#else
    return std::fseek(file, offset, origin);
#endif
}

inline int64_t FileTell64(FILE* file)
{
#if defined(WIN32)
    return _ftelli64(file);
#else
    return std::ftell(file);
#endif
}

int RaiseFileDescriptorLimit(int nMinFD);
void AllocateFileRange(FILE* file, uint64_t offset, unsigned int length);

/**
 * Rename src to dest.
 * @return true if the rename was successful.
 */
[[nodiscard]] bool RenameOver(fs::path src, fs::path dest);

namespace util {
enum class LockResult {
    Success,
    ErrorWrite,
    ErrorLock,
};
[[nodiscard]] LockResult LockDirectory(const fs::path& directory, const fs::path& lockfile_name, bool probe_only = false);
} // namespace util
void UnlockDirectory(const fs::path& directory, const fs::path& lockfile_name);
bool CheckDiskSpace(const fs::path& dir, uint64_t additional_bytes = 0);

/** Get the size of a file by scanning it.
 *
 * @param[in] path The file path
 * @param[in] max Stop seeking beyond this limit
 * @return The file size or max
 */
std::streampos GetFileSize(const char* path, std::streamsize max = std::numeric_limits<std::streamsize>::max());

/** Release all directory locks. This is used for unit testing only, at runtime
 * the global destructor will take care of the locks.
 */
void ReleaseDirectoryLocks();

bool TryCreateDirectories(const fs::path& p);
fs::path GetDefaultDataDir();

#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

#endif // BITCOIN_UTIL_FS_HELPERS_H
