#include "vault.hpp"

#include <sodium.h>
#include <chrono>
#include <filesystem>
#include <utility>

namespace
{
    std::uint64_t currentUnixTime() noexcept
    {
        const auto now = std::chrono::system_clock::now();
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        return secs > 0 ? static_cast<std::uint64_t>(secs) : 0ULL;
    }

    std::string makeFormattedRecoveryKey()
    {
        unsigned char raw[16]{}; // 128 bits = 32 hex characters
        randombytes_buf(raw, sizeof(raw));
        char hex[33]{};
        sodium_bin2hex(hex, sizeof(hex), raw, sizeof(raw));
        sodium_memzero(raw, sizeof(raw));

        // Upper-case grouped format: VVREC-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
        std::string formatted = "VVREC";
        for (std::size_t i = 0; i < 32; ++i)
        {
            if ((i % 4) == 0)
            {
                formatted.push_back('-');
            }
            char c = hex[i];
            if (c >= 'a' && c <= 'z')
            {
                c = static_cast<char>(c - 'a' + 'A');
            }
            formatted.push_back(c);
        }
        sodium_memzero(hex, sizeof(hex));
        return formatted;
    }
}

const char* vaultErrorMessage(VaultError error) {
    switch (error) {
    case VaultError::None: return "no error";
    case VaultError::Locked: return "vault is locked; authenticate and unlock first";
    case VaultError::NoData: return "no stored data yet";
    case VaultError::DecryptFailed: return "decryption failed (wrong password, or data file corrupted/tampered)";
    case VaultError::StorageError: return "data file could not be read or written";
    case VaultError::EncryptFailed: return "encryption failed";
    case VaultError::ForeignDataExists:
        return "existing data file cannot be decrypted with this password; refusing to overwrite it";
    case VaultError::WeakPassword:
        return "password does not meet minimum length (12+ chars) or complexity requirements";
    case VaultError::WrongCurrentPassword:
        return "current password is incorrect (password was NOT changed)";
    case VaultError::InvalidRecoveryKey:
        return "emergency recovery key is invalid or no recovery slot is configured";
    }
    return "unknown error";
}

Vault::Vault(Authorizer& authorizer_ref, Storage& storage_ref)
    : authorizer(authorizer_ref),
      storage(storage_ref),
      is_unlocked(false),
      last_error(VaultError::None)
{
}

Vault::~Vault() {
    lock();
}

void Vault::recordAudit(std::string_view event, std::string_view actor, std::string_view target) {
    if (audit_log != nullptr) {
        (void)audit_log->append(event, actor, target);
    }
}

void Vault::touchActivity(std::uint64_t now_unix) noexcept {
    last_activity_unix = now_unix != 0 ? now_unix : currentUnixTime();
}

bool Vault::checkIdleTimeout(std::uint64_t now_unix) {
    if (!is_unlocked || idle_timeout_seconds == 0 || last_activity_unix == 0) {
        return false;
    }
    const std::uint64_t now = now_unix != 0 ? now_unix : currentUnixTime();
    if (now > last_activity_unix && (now - last_activity_unix) >= idle_timeout_seconds) {
        lock();
        last_error = VaultError::Locked;
        recordAudit("AUTO_LOCK_IDLE", "system", "vault");
        return true;
    }
    return false;
}

bool Vault::isUnlocked() const {
    return is_unlocked;
}

VaultError Vault::lastError() const {
    return last_error;
}

std::string Vault::recoveryFilePath() const {
    return storage.path().empty() ? std::string() : storage.path() + ".recovery";
}

bool Vault::hasRecoveryKey() const {
    const std::string rpath = recoveryFilePath();
    if (rpath.empty()) {
        return false;
    }
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::path(rpath), ec) && !ec;
}

bool Vault::authenticate(std::string_view attempted_password) {
    lock();

    if (!authorizer.verifyPassword(attempted_password)) {
        last_error = VaultError::Locked;
        recordAudit(
            authorizer.isLockedOut() ? "AUTH_LOCKOUT" : "AUTH_FAILED",
            "owner",
            "vault");
        return false;
    }

    session_password.assign(attempted_password);
    touchActivity();
    last_error = VaultError::None;
    return true;
}

bool Vault::unlock() {
    if (!authorizer.isAuthorized() || session_password.empty()) {
        is_unlocked = false;
        last_error = VaultError::Locked;
        return false;
    }

    is_unlocked = true;
    touchActivity();
    last_error = VaultError::None;
    recordAudit("VAULT_UNLOCKED", "owner", "vault");
    return true;
}

void Vault::lock() {
    const bool was_unlocked = is_unlocked;
    is_unlocked = false;
    authorizer.revokeAuthorization();
    session_password.clear();
    if (was_unlocked) {
        recordAudit("VAULT_LOCKED", "owner", "vault");
    }
}

bool Vault::canDecryptExistingData(std::string_view candidate_password) {
    if (!storage.exists()) {
        return true;
    }
    std::string existing;
    if (!storage.load(existing)) {
        last_error = VaultError::StorageError;
        return false;
    }
    if (existing.empty()) {
        return true;
    }
    std::string probe;
    const bool ok = encryption.decrypt(existing, candidate_password, probe);
    if (!probe.empty()) {
        sodium_memzero(probe.data(), probe.size());
    }
    if (!ok) {
        last_error = VaultError::ForeignDataExists;
    }
    return ok;
}

bool Vault::saveData(std::string_view data) {
    (void)checkIdleTimeout();
    if (!is_unlocked || session_password.empty()) {
        last_error = VaultError::Locked;
        return false;
    }
    touchActivity();

    // Do not destroy existing data that this password cannot decrypt
    // (e.g. after an accidental re-initialization with a different password).
    if (!canDecryptExistingData(session_password.view())) {
        return false;
    }

    std::string encrypted_data;

    // Encrypt before writing anything to disk.
    if (!encryption.encrypt(data, session_password.view(), encrypted_data)) {
        last_error = VaultError::EncryptFailed;
        return false;
    }

    if (!storage.save(encrypted_data)) {
        last_error = VaultError::StorageError;
        return false;
    }
    last_error = VaultError::None;
    return true;
}

bool Vault::loadData(std::string& data) {
    (void)checkIdleTimeout();
    if (!is_unlocked || session_password.empty()) {
        last_error = VaultError::Locked;
        return false;
    }
    touchActivity();

    if (!storage.exists()) {
        last_error = VaultError::NoData;
        return false;
    }

    std::string encrypted_data;

    if (!storage.load(encrypted_data)) {
        last_error = VaultError::StorageError;
        return false;
    }

    std::string decrypted_data;

    if (!encryption.decrypt(
            encrypted_data,
            session_password.view(),
            decrypted_data
        )) {
        last_error = VaultError::DecryptFailed;
        return false;
    }

    data = std::move(decrypted_data);
    last_error = VaultError::None;
    return true;
}

bool Vault::changePassword(std::string_view current_password, std::string_view new_password) {
    (void)checkIdleTimeout();
    if (!is_unlocked || session_password.empty()) {
        last_error = VaultError::Locked;
        return false;
    }

    if (!session_password.constantTimeEquals(current_password)) {
        // Count the failed attempt in the authorizer and lock the vault.
        (void)authorizer.verifyPassword(current_password);
        lock();
        last_error = VaultError::WrongCurrentPassword;
        recordAudit("PASSWORD_ROTATE_FAILED", "owner", "wrong_current_password");
        return false;
    }

    if (!Authorizer::isPasswordAcceptable(new_password)) {
        last_error = VaultError::WeakPassword;
        return false;
    }

    const bool has_data = storage.exists();
    std::string old_encrypted;
    std::string plaintext;
    std::string new_encrypted;

    if (has_data) {
        if (!storage.load(old_encrypted)) {
            last_error = VaultError::StorageError;
            return false;
        }
        if (!old_encrypted.empty()) {
            if (!encryption.decrypt(old_encrypted, current_password, plaintext)) {
                last_error = VaultError::DecryptFailed;
                return false;
            }
            const bool enc_ok = encryption.encrypt(plaintext, new_password, new_encrypted);
            if (!plaintext.empty()) {
                sodium_memzero(plaintext.data(), plaintext.size());
            }
            if (!enc_ok) {
                last_error = VaultError::EncryptFailed;
                return false;
            }
        }
    }

    // Re-encrypt data file first, then update auth file (with rollback on failure).
    if (has_data && !old_encrypted.empty()) {
        if (!storage.save(new_encrypted)) {
            last_error = VaultError::StorageError;
            return false;
        }
    }

    if (!authorizer.changePassword(current_password, new_password)) {
        if (has_data && !old_encrypted.empty()) {
            (void)storage.save(old_encrypted); // Roll back data file to old key
        }
        last_error = VaultError::StorageError;
        return false;
    }

    // Invalidate any old recovery key envelope because the master password rotated.
    if (hasRecoveryKey()) {
        std::error_code ec;
        std::filesystem::remove(std::filesystem::path(recoveryFilePath()), ec);
    }

    session_password.assign(new_password);
    is_unlocked = true;
    touchActivity();
    last_error = VaultError::None;
    recordAudit("PASSWORD_ROTATED", "owner", "vault");
    return true;
}

bool Vault::generateRecoveryKey(std::string& out_recovery_key) {
    (void)checkIdleTimeout();
    if (!is_unlocked || session_password.empty()) {
        last_error = VaultError::Locked;
        return false;
    }
    const std::string rpath = recoveryFilePath();
    if (rpath.empty()) {
        last_error = VaultError::StorageError;
        return false;
    }

    std::string candidate_key = makeFormattedRecoveryKey();
    std::string encrypted_envelope;
    if (!encryption.encrypt(session_password.view(), candidate_key, encrypted_envelope)) {
        sodium_memzero(candidate_key.data(), candidate_key.size());
        last_error = VaultError::EncryptFailed;
        return false;
    }

    FileLock lock_guard(rpath);
    if (!lock_guard.isLocked() || !Storage::atomicWrite(rpath, encrypted_envelope, true)) {
        sodium_memzero(candidate_key.data(), candidate_key.size());
        last_error = VaultError::StorageError;
        return false;
    }

    out_recovery_key = std::move(candidate_key);
    touchActivity();
    last_error = VaultError::None;
    recordAudit("RECOVERY_KEY_GENERATED", "owner", "vault");
    return true;
}

bool Vault::recoverWithEmergencyKey(std::string_view recovery_key, std::string_view new_password) {
    lock();

    if (!Authorizer::isPasswordAcceptable(new_password)) {
        last_error = VaultError::WeakPassword;
        return false;
    }
    if (recovery_key.empty() || !hasRecoveryKey()) {
        last_error = VaultError::InvalidRecoveryKey;
        return false;
    }

    const std::string rpath = recoveryFilePath();
    std::string envelope;
    if (!Storage::readFile(rpath, envelope) || envelope.empty()) {
        last_error = VaultError::InvalidRecoveryKey;
        return false;
    }

    std::string recovered_old_pw;
    if (!encryption.decrypt(envelope, recovery_key, recovered_old_pw) || recovered_old_pw.empty()) {
        last_error = VaultError::InvalidRecoveryKey;
        recordAudit("RECOVERY_KEY_FAILED", "owner", "vault");
        return false;
    }

    // Re-encrypt vault_data.dat (if present) from recovered_old_pw -> new_password
    const bool has_data = storage.exists();
    std::string old_encrypted;
    std::string plaintext;
    std::string new_encrypted;

    if (has_data) {
        if (!storage.load(old_encrypted)) {
            sodium_memzero(recovered_old_pw.data(), recovered_old_pw.size());
            last_error = VaultError::StorageError;
            return false;
        }
        if (!old_encrypted.empty()) {
            if (!encryption.decrypt(old_encrypted, recovered_old_pw, plaintext)) {
                sodium_memzero(recovered_old_pw.data(), recovered_old_pw.size());
                last_error = VaultError::DecryptFailed;
                return false;
            }
            const bool enc_ok = encryption.encrypt(plaintext, new_password, new_encrypted);
            if (!plaintext.empty()) {
                sodium_memzero(plaintext.data(), plaintext.size());
            }
            if (!enc_ok) {
                sodium_memzero(recovered_old_pw.data(), recovered_old_pw.size());
                last_error = VaultError::EncryptFailed;
                return false;
            }
        }
    }
    sodium_memzero(recovered_old_pw.data(), recovered_old_pw.size());

    if (has_data && !old_encrypted.empty()) {
        if (!storage.save(new_encrypted)) {
            last_error = VaultError::StorageError;
            return false;
        }
    }

    if (!authorizer.forceResetPassword(new_password)) {
        if (has_data && !old_encrypted.empty()) {
            (void)storage.save(old_encrypted);
        }
        last_error = VaultError::StorageError;
        return false;
    }

    // Consume (remove) the used one-time recovery envelope.
    std::error_code ec;
    std::filesystem::remove(std::filesystem::path(rpath), ec);

    session_password.assign(new_password);
    is_unlocked = true;
    touchActivity();
    last_error = VaultError::None;
    recordAudit("EMERGENCY_RECOVERY_COMPLETED", "owner", "vault");
    return true;
}
