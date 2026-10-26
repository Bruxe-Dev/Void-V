#ifndef VOID_VAULT_VAULT_HPP
#define VOID_VAULT_VAULT_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "../security/audit_log.hpp"
#include "../security/auth.hpp"
#include "../security/encryption.hpp"
#include "../security/secure_buffer.hpp"
#include "../../include/storage.hpp"

enum class VaultError {
    None,
    Locked,               // not authenticated / not unlocked (or auto-locked due to idle timeout)
    NoData,               // no data file yet
    DecryptFailed,        // wrong password or corrupted / tampered data file
    StorageError,         // file could not be read or written
    EncryptFailed,
    ForeignDataExists,    // existing data cannot be decrypted with this password; refusing to overwrite
    WeakPassword,         // new password fails length / entropy policy
    WrongCurrentPassword, // current password verification failed during password rotation
    InvalidRecoveryKey    // recovery key missing, invalid, or already consumed
};

const char* vaultErrorMessage(VaultError error);

class Vault {
public:
    Vault(Authorizer& authorizer, Storage& storage);
    ~Vault();

    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    void setKdfProfile(KdfProfile profile) noexcept { encryption.setKdfProfile(profile); }
    KdfProfile kdfProfile() const noexcept { return encryption.kdfProfile(); }

    // Optional tamper-evident AuditLog attachment.
    void setAuditLog(AuditLog* log) noexcept { audit_log = log; }
    AuditLog* auditLog() const noexcept { return audit_log; }
    void setLockCallback(std::function<void()> callback);

    // Configures automatic inactivity lock timeout (0 = disabled).
    void setIdleTimeoutSeconds(std::uint64_t seconds) noexcept { idle_timeout_seconds = seconds; }
    std::uint64_t idleTimeoutSeconds() const noexcept { return idle_timeout_seconds; }
    bool checkIdleTimeout(std::uint64_t now_unix = 0);

    bool isUnlocked() const;
    bool authenticate(std::string_view attempted_password);
    bool unlock();
    void lock();

    bool saveData(std::string_view data);
    bool loadData(std::string& data);

    // Checks whether `candidate_password` can decrypt the existing data file on disk
    // (returns true if no data file exists yet or if decryption succeeds).
    bool canDecryptExistingData(std::string_view candidate_password);

    // Atomically rotates the account password and re-encrypts any stored data
    // record under the new password. Requires the vault to be unlocked.
    bool changePassword(std::string_view current_password, std::string_view new_password);

    // Generates a one-time 256-bit Emergency Recovery Key ("VVREC-XXXX-...") and
    // writes an AEAD-encrypted recovery envelope ("<data_path>.recovery") so the
    // vault can be recovered even if the master password is forgotten or locked out.
    bool generateRecoveryKey(std::string& out_recovery_key);

    // Recovers a locked-out or forgotten-password vault using the Emergency
    // Recovery Key, re-encrypting stored data under `new_password`, resetting the
    // lockout counter, and consuming the one-time recovery envelope.
    bool recoverWithEmergencyKey(std::string_view recovery_key, std::string_view new_password);

    bool hasRecoveryKey() const;
    std::string recoveryFilePath() const;

    VaultError lastError() const;

private:
    void recordAudit(std::string_view event, std::string_view actor, std::string_view target);
    void touchActivity(std::uint64_t now_unix = 0) noexcept;

    Authorizer& authorizer;
    Storage& storage;
    Encryption encryption;
    SecureBuffer session_password;
    AuditLog* audit_log = nullptr;
    std::function<void()> lock_callback;
    std::uint64_t idle_timeout_seconds = 0;
    std::uint64_t last_activity_unix = 0;
    bool is_unlocked;
    VaultError last_error;
};

#endif
