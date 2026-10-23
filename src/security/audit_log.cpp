#include "audit_log.hpp"

#include "../../include/storage.hpp"

#include <sodium.h>

#include <chrono>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace
{
    constexpr char AUDIT_MAGIC[] = "VVAUDIT1";
    constexpr char GENESIS_PREV_HASH[] =
        "0000000000000000000000000000000000000000000000000000000000000000";

    std::uint64_t currentUnixTime() noexcept
    {
        const auto now = std::chrono::system_clock::now();
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        return secs > 0 ? static_cast<std::uint64_t>(secs) : 0ULL;
    }

    std::string sanitizeField(std::string_view field)
    {
        std::string out;
        out.reserve(field.size());
        for (char c : field)
        {
            const auto uc = static_cast<unsigned char>(c);
            if (c == '|' || c == '\n' || c == '\r' || uc < 0x20U || uc >= 0x7FU)
            {
                out.push_back('_');
            }
            else
            {
                out.push_back(c);
            }
        }
        return out.empty() ? std::string("-") : out;
    }

    std::string computeEntryHash(std::string_view canonical_prefix)
    {
        unsigned char digest[crypto_generichash_BYTES]{}; // 32 bytes (256-bit BLAKE2b)
        crypto_generichash(
            digest,
            sizeof(digest),
            reinterpret_cast<const unsigned char *>(canonical_prefix.data()),
            canonical_prefix.size(),
            nullptr,
            0);
        std::string hex(sizeof(digest) * 2 + 1, '\0');
        sodium_bin2hex(hex.data(), hex.size(), digest, sizeof(digest));
        hex.resize(sizeof(digest) * 2);
        sodium_memzero(digest, sizeof(digest));
        return hex;
    }

    std::vector<std::string> splitPipe(const std::string &line)
    {
        std::vector<std::string> parts;
        std::size_t start = 0;
        while (true)
        {
            const std::size_t pos = line.find('|', start);
            if (pos == std::string::npos)
            {
                parts.push_back(line.substr(start));
                break;
            }
            parts.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }
        return parts;
    }
}

AuditLog::AuditLog(const std::string &log_file_path)
    : log_file_path_(log_file_path)
{
    if (sodium_init() < 0)
    {
        throw std::runtime_error("Libsodium initialization failed");
    }
}

bool AuditLog::append(
    std::string_view event,
    std::string_view actor,
    std::string_view target,
    std::uint64_t now_unix)
{
    if (log_file_path_.empty() || Storage::isSymlinkOrReparsePoint(log_file_path_))
    {
        return false;
    }

    FileLock lock(log_file_path_);
    if (!lock.isLocked())
    {
        return false;
    }

    std::string existing;
    std::uint64_t next_seq = 1;
    std::string prev_hash = GENESIS_PREV_HASH;

    std::error_code ec;
    if (std::filesystem::exists(std::filesystem::path(log_file_path_), ec) && !ec)
    {
        if (!Storage::readFile(log_file_path_, existing))
        {
            return false;
        }
        if (!existing.empty())
        {
            std::istringstream in(existing);
            std::string line, last_non_empty;
            std::uint64_t count = 0;
            while (std::getline(in, line))
            {
                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }
                if (!line.empty())
                {
                    last_non_empty = line;
                    ++count;
                }
            }
            if (count > 0)
            {
                const auto parts = splitPipe(last_non_empty);
                if (parts.size() != 8 || parts[0] != AUDIT_MAGIC || parts[7].size() != 64)
                {
                    return false; // Refuse to append to a corrupted audit chain
                }
                next_seq = count + 1;
                prev_hash = parts[7];
            }
        }
    }

    const std::uint64_t ts = now_unix != 0 ? now_unix : currentUnixTime();
    const std::string clean_event = sanitizeField(event);
    const std::string clean_actor = sanitizeField(actor);
    const std::string clean_target = sanitizeField(target);

    std::string prefix;
    prefix.reserve(160);
    prefix += AUDIT_MAGIC;
    prefix += '|';
    prefix += std::to_string(next_seq);
    prefix += '|';
    prefix += std::to_string(ts);
    prefix += '|';
    prefix += clean_event;
    prefix += '|';
    prefix += clean_actor;
    prefix += '|';
    prefix += clean_target;
    prefix += '|';
    prefix += prev_hash;

    const std::string entry_hash = computeEntryHash(prefix);

    std::string updated = std::move(existing);
    updated += prefix;
    updated += '|';
    updated += entry_hash;
    updated += '\n';

    return Storage::atomicWrite(log_file_path_, updated, true);
}

bool AuditLog::verify(std::size_t *out_entry_count, std::size_t *out_failed_line) const
{
    if (out_entry_count != nullptr)
    {
        *out_entry_count = 0;
    }
    if (out_failed_line != nullptr)
    {
        *out_failed_line = 0;
    }
    if (log_file_path_.empty() || Storage::isSymlinkOrReparsePoint(log_file_path_))
    {
        return false;
    }

    std::error_code ec;
    if (!std::filesystem::exists(std::filesystem::path(log_file_path_), ec))
    {
        return !ec;
    }

    std::string content;
    if (!Storage::readFile(log_file_path_, content))
    {
        if (out_failed_line != nullptr)
        {
            *out_failed_line = 1;
        }
        return false;
    }

    std::istringstream in(content);
    std::string line;
    std::string expected_prev = GENESIS_PREV_HASH;
    std::size_t line_no = 0;

    while (std::getline(in, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        if (line.empty())
        {
            continue;
        }
        ++line_no;
        const auto parts = splitPipe(line);
        if (parts.size() != 8 || parts[0] != AUDIT_MAGIC)
        {
            if (out_failed_line != nullptr)
            {
                *out_failed_line = line_no;
            }
            return false;
        }

        if (parts[1] != std::to_string(line_no) || parts[6] != expected_prev)
        {
            if (out_failed_line != nullptr)
            {
                *out_failed_line = line_no;
            }
            return false;
        }

        const std::size_t last_pipe = line.rfind('|');
        const std::string prefix = line.substr(0, last_pipe);
        const std::string actual_hash = line.substr(last_pipe + 1);
        const std::string computed_hash = computeEntryHash(prefix);

        if (actual_hash.size() != 64 ||
            sodium_memcmp(actual_hash.data(), computed_hash.data(), 64) != 0)
        {
            if (out_failed_line != nullptr)
            {
                *out_failed_line = line_no;
            }
            return false;
        }

        expected_prev = actual_hash;
    }

    if (out_entry_count != nullptr)
    {
        *out_entry_count = line_no;
    }
    return true;
}
