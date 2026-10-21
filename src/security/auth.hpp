#ifndef VOID_VAULT_AUTH_HPP
#define VOID_VAULT_AUTH_HPP

#include <cstddef>
#include <string>
#include <string_view>

// Password gate for the vault.
//
// Persistent mode (file path constructor) stores, atomically:
//     VVAUTH1
//     <argon2id hash string>
//     failed=<n>
// The plaintext password is never written. The failed-attempt counter is
// persisted BEFORE each verification, so lockout survives restarts and cannot
// be bypassed by killing the process mid-check. Legacy single-line hash files
// are accepted and upgraded on the next write.
//
// Missing file  -> uninitialized (first-time setup allowed).
// Any unreadable / malformed / corrupted existing file -> storage error
// (fail closed: no setup, no verification). A corrupted record never becomes
// a new account.
//
// NOTE: this is an online gate only. Confidentiality of stored data comes from
// password-derived encryption; an attacker with file access can bypass this
// class and attack the data file offline (bounded by Argon2id cost).
class Authorizer {
public:
    static constexpr int MAX_FAILED_ATTEMPTS = 5;
    static constexpr std::size_t MIN_PASSWORD_LENGTH = 12;
    static constexpr std::size_t MAX_PASSWORD_LENGTH = 1024;

    Authorizer();  // in-memory only; lockout is session-only

    explicit Authorizer(const std::string& hash_file_path);
    ~Authorizer();

    Authorizer(const Authorizer&) = delete;
    Authorizer& operator=(const Authorizer&) = delete;

    // Validates password length, printable characters, and non-trivial entropy
    // (rejects control characters, all-whitespace, or repeated single character).
    static bool isPasswordAcceptable(std::string_view candidate) noexcept;

    bool setPassword(std::string_view new_password);
    bool verifyPassword(std::string_view attempted_password);
    bool changePassword(std::string_view current_password, std::string_view new_password);

    bool isAuthorized() const;
    void revokeAuthorization();
    bool isLockedOut() const;
    bool isInitialized() const;
    bool hasStorageError() const;
    int failedAttempts() const;

private:
    bool loadPasswordHash();
    bool persist(const std::string& hash, int failed, bool allow_replace);

    bool authorized;
    std::string password_hash;
    int failed_attempts;
    bool locked_out;
    bool password_initialized;

    std::string hash_file_path;
    bool persistent_storage;
    bool storage_error;
};

#endif
