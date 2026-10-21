#ifndef VOID_VAULT_STORAGE_HPP
#define VOID_VAULT_STORAGE_HPP

#include <cstddef>
#include <string>

// Cross-process RAII exclusive lock on "<target_path>.lock".
// Uses LockFileEx (LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY) on
// Windows and flock(LOCK_EX | LOCK_NB) on POSIX.
class FileLock {
public:
    explicit FileLock(const std::string& target_path);
    ~FileLock();

    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;

    bool isLocked() const noexcept { return locked_; }
    void unlock() noexcept;

private:
    std::string lock_path_;
    bool locked_ = false;
#ifdef _WIN32
    void* handle_ = reinterpret_cast<void*>(-1);
#else
    int fd_ = -1;
#endif
};

class Storage {
public:
    // Maximum allowed file size (16 MiB) to prevent memory-exhaustion DoS.
    static constexpr std::size_t MAX_FILE_SIZE = 16U * 1024U * 1024U;

    explicit Storage(const std::string& file_path);

    // Atomically replaces the file: data is written to "<path>.tmp" with
    // owner-only permissions, flushed to disk, then renamed over the target.
    // Refuses symlinks/reparse points and payloads exceeding MAX_FILE_SIZE.
    // A failed save never truncates the previously valid file.
    bool save(const std::string& data);

    // Reads the whole file. Refuses symlinks/reparse points and files
    // exceeding MAX_FILE_SIZE. On failure the output is left untouched.
    bool load(std::string& data);

    bool exists() const;
    const std::string& path() const;

    // Shared atomic-write primitive (also used by Authorizer).
    // allow_replace == false: fails if the target already exists (no overwrite).
    static bool atomicWrite(const std::string& path,
                            const std::string& data,
                            bool allow_replace);

    // Reads a whole file into `out` only on success.
    static bool readFile(const std::string& path, std::string& out);

    // Applies owner-only permissions (DACL restricted to current user SID on
    // Windows; chmod 0600 on POSIX).
    static bool restrictPermissions(const std::string& path);

    // Returns true if `path` is a symbolic link or Windows reparse point.
    static bool isSymlinkOrReparsePoint(const std::string& path);

private:
    std::string file_path;
};

#endif
