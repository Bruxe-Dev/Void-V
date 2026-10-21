#include "auth.hpp"

#include "../../include/storage.hpp"

#include <sodium.h>

#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>

namespace
{
    constexpr char FORMAT_HEADER[] = "VVAUTH1";
    constexpr char ARGON_PREFIX[] = "$argon2id$";

    bool validHash(const std::string &hash)
    {
        if (hash.empty() || hash.size() >= crypto_pwhash_STRBYTES ||
            hash.rfind(ARGON_PREFIX, 0) != 0)
        {
            return false;
        }
        // -1 means the string is not a valid hash for this algorithm.
        return crypto_pwhash_str_needs_rehash(
                   hash.c_str(),
                   crypto_pwhash_OPSLIMIT_INTERACTIVE,
                   crypto_pwhash_MEMLIMIT_INTERACTIVE) != -1;
    }

    bool parseCounter(const std::string &line, int &out)
    {
        constexpr char KEY[] = "failed=";
        if (line.rfind(KEY, 0) != 0)
        {
            return false;
        }
        const std::string digits = line.substr(sizeof(KEY) - 1);
        if (digits.empty() || digits.size() > 6)
        {
            return false;
        }
        int value = 0;
        for (char c : digits)
        {
            if (c < '0' || c > '9')
            {
                return false;
            }
            value = value * 10 + (c - '0');
        }
        out = value;
        return true;
    }

    bool hashPassword(std::string_view password, std::string &out_hash)
    {
        char generated_hash[crypto_pwhash_STRBYTES] = {};
        if (crypto_pwhash_str(
                generated_hash,
                password.data(),
                static_cast<unsigned long long>(password.size()),
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
        {
            sodium_memzero(generated_hash, sizeof(generated_hash));
            return false;
        }
        out_hash.assign(generated_hash);
        sodium_memzero(generated_hash, sizeof(generated_hash));
        return true;
    }
}

Authorizer::Authorizer()
    : authorized(false),
      failed_attempts(0),
      locked_out(false),
      password_initialized(false),
      persistent_storage(false),
      storage_error(false)
{
    if (sodium_init() < 0) {
        storage_error = true;
    }
}

Authorizer::Authorizer(const std::string& file_path)
    : authorized(false),
      failed_attempts(0),
      locked_out(false),
      password_initialized(false),
      hash_file_path(file_path),
      persistent_storage(true),
      storage_error(false)
{
    if (sodium_init() < 0) {
        storage_error = true;
        return;
    }

    if (!loadPasswordHash()) {
        storage_error = true;
        if (!password_hash.empty()) {
            sodium_memzero(password_hash.data(), password_hash.size());
            password_hash.clear();
        }
    }
}

Authorizer::~Authorizer() {
    authorized = false;
    if (!password_hash.empty()) {
        sodium_memzero(password_hash.data(), password_hash.size());
        password_hash.clear();
    }
}

bool Authorizer::isPasswordAcceptable(std::string_view candidate) noexcept {
    if (candidate.size() < MIN_PASSWORD_LENGTH ||
        candidate.size() > MAX_PASSWORD_LENGTH) {
        return false;
    }
    bool has_non_space = false;
    bool has_distinct_char = false;
    const char first = candidate.front();
    for (char c : candidate) {
        const auto uc = static_cast<unsigned char>(c);
        // Reject ASCII control characters (NUL..US and DEL).
        if (uc < 0x20U || uc == 0x7FU) {
            return false;
        }
        if (c != ' ') {
            has_non_space = true;
        }
        if (c != first) {
            has_distinct_char = true;
        }
    }
    return has_non_space && has_distinct_char;
}

bool Authorizer::loadPasswordHash() {
    if (hash_file_path.empty() || Storage::isSymlinkOrReparsePoint(hash_file_path)) {
        return false;
    }
    std::error_code ec;
    const std::filesystem::path p(hash_file_path);
    const bool present = std::filesystem::exists(p, ec);
    if (ec) {
        return false;                    // cannot determine -> fail closed
    }
    if (!present) {
        password_initialized = false;    // genuinely new account
        return true;
    }

    // From here on an account record exists: any problem is an error,
    // never a silent re-initialization.
    password_initialized = true;

    std::string content;
    if (!Storage::readFile(hash_file_path, content) || content.empty()) {
        return false;
    }

    std::istringstream in(content);
    std::string first;
    if (!std::getline(in, first)) {
        return false;
    }
    if (!first.empty() && first.back() == '\r') {
        first.pop_back();
    }

    if (first == FORMAT_HEADER) {
        std::string hash, counter, extra;
        if (!std::getline(in, hash) || !std::getline(in, counter)) {
            return false;
        }
        if (!hash.empty() && hash.back() == '\r') {
            hash.pop_back();
        }
        if (!counter.empty() && counter.back() == '\r') {
            counter.pop_back();
        }
        if (std::getline(in, extra) && !extra.empty()) {
            return false;
        }
        int failed = 0;
        if (!validHash(hash) || !parseCounter(counter, failed)) {
            return false;
        }
        password_hash = hash;
        failed_attempts = failed;
    } else {
        // Legacy format: exactly one line containing the hash.
        std::string extra;
        if (std::getline(in, extra) && !extra.empty()) {
            return false;
        }
        if (!validHash(first)) {
            return false;
        }
        password_hash = first;
        failed_attempts = 0;
    }

    locked_out = failed_attempts >= MAX_FAILED_ATTEMPTS;
    return true;
}

bool Authorizer::persist(const std::string& hash, int failed, bool allow_replace) {
    if (!persistent_storage) {
        return true;
    }
    FileLock lock(hash_file_path);
    if (!lock.isLocked()) {
        return false;
    }
    std::string record;
    record.reserve(hash.size() + 32);
    record += FORMAT_HEADER;
    record += '\n';
    record += hash;
    record += "\nfailed=";
    record += std::to_string(failed);
    record += '\n';
    return Storage::atomicWrite(hash_file_path, record, allow_replace);
}

bool Authorizer::setPassword(std::string_view new_password) {
    if (storage_error ||
        password_initialized ||
        !isPasswordAcceptable(new_password)) {
        return false;
    }

    std::string candidate_hash;
    if (!hashPassword(new_password, candidate_hash)) {
        return false;
    }

    // allow_replace = false: never overwrite an account created meanwhile.
    if (!persist(candidate_hash, 0, false)) {
        return false;
    }

    password_hash = std::move(candidate_hash);
    password_initialized = true;
    failed_attempts = 0;
    locked_out = false;

    return true;
}

bool Authorizer::verifyPassword(std::string_view attempted_password) {
    authorized = false;

    if (storage_error ||
        locked_out ||
        !password_initialized ||
        password_hash.empty() ||
        attempted_password.size() > MAX_PASSWORD_LENGTH) {
        return false;
    }

    // Count the attempt BEFORE verifying (fail closed if it cannot be recorded).
    const int pending = failed_attempts + 1;
    if (!persist(password_hash, pending, true)) {
        locked_out = true;
        return false;
    }
    failed_attempts = pending;

    if (crypto_pwhash_str_verify(
            password_hash.c_str(),
            attempted_password.data(),
            static_cast<unsigned long long>(attempted_password.size())
        ) == 0) {
        authorized = true;
        failed_attempts = 0;
        // If this write fails the on-disk counter is merely more restrictive.
        persist(password_hash, 0, true);
        return true;
    }

    if (failed_attempts >= MAX_FAILED_ATTEMPTS) {
        locked_out = true;
    }

    return false;
}

bool Authorizer::changePassword(std::string_view current_password, std::string_view new_password) {
    if (!isPasswordAcceptable(new_password)) {
        return false;
    }
    if (!verifyPassword(current_password)) {
        return false;
    }

    std::string candidate_hash;
    if (!hashPassword(new_password, candidate_hash)) {
        return false;
    }

    if (!persist(candidate_hash, 0, true)) {
        return false;
    }

    if (!password_hash.empty()) {
        sodium_memzero(password_hash.data(), password_hash.size());
    }
    password_hash = std::move(candidate_hash);
    failed_attempts = 0;
    locked_out = false;
    authorized = true;
    return true;
}

bool Authorizer::isAuthorized() const {
    return authorized;
}

void Authorizer::revokeAuthorization() {
    authorized = false;
}

bool Authorizer::isLockedOut() const {
    return locked_out;
}

bool Authorizer::isInitialized() const {
    return password_initialized && !storage_error;
}

bool Authorizer::hasStorageError() const {
    return storage_error;
}

int Authorizer::failedAttempts() const {
    return failed_attempts;
}
