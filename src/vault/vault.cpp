#include "vault.hpp"

#include <sodium.h>
#include <utility>

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

bool Vault::isUnlocked() const {
    return is_unlocked;
}

VaultError Vault::lastError() const {
    return last_error;
}

bool Vault::authenticate(std::string_view attempted_password) {
    lock();

    if (!authorizer.verifyPassword(attempted_password)) {
        last_error = VaultError::Locked;
        return false;
    }

    session_password.assign(attempted_password);
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
    last_error = VaultError::None;
    return true;
}

void Vault::lock() {
    is_unlocked = false;
    authorizer.revokeAuthorization();
    session_password.clear();
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
    if (!is_unlocked || session_password.empty()) {
        last_error = VaultError::Locked;
        return false;
    }

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
    if (!is_unlocked || session_password.empty()) {
        last_error = VaultError::Locked;
        return false;
    }

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
    if (!is_unlocked || session_password.empty()) {
        last_error = VaultError::Locked;
        return false;
    }

    if (!session_password.constantTimeEquals(current_password)) {
        // Count the failed attempt in the authorizer and lock the vault.
        (void)authorizer.verifyPassword(current_password);
        lock();
        last_error = VaultError::WrongCurrentPassword;
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

    session_password.assign(new_password);
    is_unlocked = true;
    last_error = VaultError::None;
    return true;
}
