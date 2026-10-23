#ifndef VOID_VAULT_AUDIT_LOG_HPP
#define VOID_VAULT_AUDIT_LOG_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

// Tamper-evident, cryptographically hash-chained security audit log ("VVAUDIT1").
//
// Each line in the log file has the format:
//   VVAUDIT1|<seq>|<unix_ts>|<event>|<actor>|<target>|<prev_hash_hex>|<entry_hash_hex>
// where:
//   entry_hash = BLAKE2b-256("VVAUDIT1|" || seq || "|" || unix_ts || "|" ||
//                            event || "|" || actor || "|" || target || "|" || prev_hash_hex)
//
// Never pass secret values or passwords into `actor` or `target`.
// Deleting, inserting, reordering, or modifying any line breaks the hash chain
// and is detected by `AuditLog::verify()`.
class AuditLog {
public:
    explicit AuditLog(const std::string& log_file_path);

    const std::string& path() const noexcept { return log_file_path_; }

    // Appends a new hash-chained event atomically under a cross-process FileLock.
    bool append(
        std::string_view event,
        std::string_view actor,
        std::string_view target,
        std::uint64_t now_unix = 0);

    // Verifies the entire hash chain from genesis (seq=1) to the last entry.
    // Returns true if the file is absent (0 entries) or if every entry's hash
    // and sequence link is valid. On failure, sets `out_failed_line` (1-indexed).
    bool verify(std::size_t* out_entry_count = nullptr, std::size_t* out_failed_line = nullptr) const;

private:
    std::string log_file_path_;
};

#endif
