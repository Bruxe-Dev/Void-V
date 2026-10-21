#include "../include/storage.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <system_error>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace
{
#ifdef _WIN32
    std::wstring widen(const std::string &s)
    {
        return std::filesystem::path(s).wstring();
    }
#endif

    bool writeTemp(const std::string &tmp, const std::string &data)
    {
        if (Storage::isSymlinkOrReparsePoint(tmp))
        {
            return false;
        }
#ifdef _WIN32
        const std::wstring wtmp = widen(tmp);
        HANDLE h = CreateFileW(
            wtmp.c_str(),
            GENERIC_WRITE,
            0, // exclusive access while writing temp file
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (h == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        std::size_t total = 0;
        while (total < data.size())
        {
            const std::size_t remaining = data.size() - total;
            const DWORD chunk = remaining > 0x40000000UL
                                    ? 0x40000000UL
                                    : static_cast<DWORD>(remaining);
            DWORD written = 0;
            if (!WriteFile(h, data.data() + total, chunk, &written, nullptr) ||
                written != chunk)
            {
                CloseHandle(h);
                return false;
            }
            total += static_cast<std::size_t>(written);
        }

        const bool flushed = FlushFileBuffers(h) != 0;
        const bool closed = CloseHandle(h) != 0;
        if (!flushed || !closed)
        {
            return false;
        }
        (void)Storage::restrictPermissions(tmp);
        return true;
#else
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
        if (fd < 0)
        {
            return false;
        }
        (void)::fchmod(fd, S_IRUSR | S_IWUSR);
        std::size_t written = 0;
        while (written < data.size())
        {
            const ssize_t n = ::write(fd, data.data() + written, data.size() - written);
            if (n <= 0)
            {
                ::close(fd);
                return false;
            }
            written += static_cast<std::size_t>(n);
        }
        const bool synced = ::fsync(fd) == 0;
        return (::close(fd) == 0) && synced;
#endif
    }

    bool commit(const std::string &tmp, const std::string &target, bool allow_replace)
    {
#ifdef _WIN32
        DWORD flags = MOVEFILE_WRITE_THROUGH;
        if (allow_replace)
        {
            flags |= MOVEFILE_REPLACE_EXISTING;
        }
        if (MoveFileExW(widen(tmp).c_str(), widen(target).c_str(), flags) == 0)
        {
            return false;
        }
        (void)Storage::restrictPermissions(target);
        return true;
#else
        if (allow_replace)
        {
            if (::rename(tmp.c_str(), target.c_str()) != 0)
            {
                return false;
            }
            (void)Storage::restrictPermissions(target);
            return true;
        }
        // link() fails with EEXIST if the target exists: no overwrite.
        if (::link(tmp.c_str(), target.c_str()) != 0)
        {
            return false;
        }
        ::unlink(tmp.c_str());
        (void)Storage::restrictPermissions(target);
        return true;
#endif
    }
}

FileLock::FileLock(const std::string &target_path)
    : lock_path_(target_path.empty() ? std::string() : target_path + ".lock")
{
    if (lock_path_.empty() || Storage::isSymlinkOrReparsePoint(lock_path_))
    {
        return;
    }
#ifdef _WIN32
    const std::wstring wpath = widen(lock_path_);
    HANDLE h = CreateFileW(
        wpath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        return;
    }
    OVERLAPPED ov{};
    if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, MAXDWORD, MAXDWORD, &ov))
    {
        CloseHandle(h);
        return;
    }
    handle_ = h;
    locked_ = true;
#else
    const int fd = ::open(lock_path_.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (fd < 0)
    {
        return;
    }
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0)
    {
        ::close(fd);
        return;
    }
    fd_ = fd;
    locked_ = true;
#endif
}

FileLock::~FileLock()
{
    unlock();
}

void FileLock::unlock() noexcept
{
    if (!locked_)
    {
        return;
    }
#ifdef _WIN32
    HANDLE h = static_cast<HANDLE>(handle_);
    if (h != INVALID_HANDLE_VALUE)
    {
        OVERLAPPED ov{};
        (void)UnlockFileEx(h, 0, MAXDWORD, MAXDWORD, &ov);
        CloseHandle(h);
        handle_ = INVALID_HANDLE_VALUE;
    }
#else
    if (fd_ >= 0)
    {
        (void)::flock(fd_, LOCK_UN);
        ::close(fd_);
        fd_ = -1;
    }
#endif
    locked_ = false;
}

Storage::Storage(const std::string &path)
    : file_path(path)
{
}

const std::string &Storage::path() const
{
    return file_path;
}

bool Storage::exists() const
{
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::path(file_path), ec) && !ec;
}

bool Storage::isSymlinkOrReparsePoint(const std::string &path)
{
    if (path.empty())
    {
        return false;
    }
    std::error_code ec;
    const std::filesystem::path p(path);
    const auto st = std::filesystem::symlink_status(p, ec);
    if (!ec && std::filesystem::is_symlink(st))
    {
        return true;
    }
#ifdef _WIN32
    const DWORD attrs = GetFileAttributesW(widen(path).c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    {
        return true;
    }
#endif
    return false;
}

bool Storage::restrictPermissions(const std::string &path)
{
    if (path.empty() || isSymlinkOrReparsePoint(path))
    {
        return false;
    }
#ifdef _WIN32
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        return false;
    }
    DWORD needed = 0;
    (void)GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0)
    {
        CloseHandle(token);
        return false;
    }
    std::vector<unsigned char> buf(needed);
    if (!GetTokenInformation(token, TokenUser, buf.data(), needed, &needed))
    {
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);

    auto *tu = reinterpret_cast<TOKEN_USER *>(buf.data());
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = static_cast<LPWSTR>(tu->User.Sid);

    PACL dacl = nullptr;
    if (SetEntriesInAclW(1, &ea, nullptr, &dacl) != ERROR_SUCCESS || dacl == nullptr)
    {
        return false;
    }
    std::wstring wpath = widen(path);
    const DWORD rc = SetNamedSecurityInfoW(
        wpath.data(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        dacl,
        nullptr);
    LocalFree(dacl);
    return rc == ERROR_SUCCESS;
#else
    return ::chmod(path.c_str(), S_IRUSR | S_IWUSR) == 0;
#endif
}

bool Storage::atomicWrite(const std::string &path, const std::string &data, bool allow_replace)
{
    if (path.empty() || data.size() > MAX_FILE_SIZE)
    {
        return false;
    }
    if (isSymlinkOrReparsePoint(path))
    {
        return false;
    }
    if (!allow_replace)
    {
        std::error_code ec;
        if (std::filesystem::exists(std::filesystem::path(path), ec) || ec)
        {
            return false;
        }
    }

    const std::string tmp = path + ".tmp";
    if (isSymlinkOrReparsePoint(tmp))
    {
        return false;
    }
    if (!writeTemp(tmp, data) || !commit(tmp, path, allow_replace))
    {
        std::error_code ec;
        std::filesystem::remove(std::filesystem::path(tmp), ec);
        return false;
    }
    return true;
}

bool Storage::readFile(const std::string &path, std::string &out)
{
    if (path.empty() || isSymlinkOrReparsePoint(path))
    {
        return false;
    }
    std::error_code ec;
    const std::filesystem::path fspath(path);
    const auto st = std::filesystem::status(fspath, ec);
    if (ec || !std::filesystem::is_regular_file(st))
    {
        return false;
    }
    const auto file_size = std::filesystem::file_size(fspath, ec);
    if (ec || file_size > MAX_FILE_SIZE)
    {
        return false;
    }

    std::ifstream file(fspath, std::ios::binary);
    if (!file.is_open())
    {
        return false;
    }
    std::string buffer;
    buffer.resize(static_cast<std::size_t>(file_size));
    if (file_size > 0)
    {
        file.read(buffer.data(), static_cast<std::streamsize>(file_size));
        if (file.bad() || file.fail() ||
            static_cast<std::size_t>(file.gcount()) != static_cast<std::size_t>(file_size))
        {
            return false;
        }
    }
    out = std::move(buffer);
    return true;
}

bool Storage::save(const std::string &data)
{
    FileLock lock(file_path);
    if (!lock.isLocked())
    {
        return false;
    }
    return atomicWrite(file_path, data, true);
}

bool Storage::load(std::string &data)
{
    return readFile(file_path, data);
}
