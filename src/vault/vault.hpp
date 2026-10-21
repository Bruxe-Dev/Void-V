#ifndef VOID_VAULT_VAULT_HPP
#define VOID_VAULT_VAULT_HPP

#include <string>
#include <string_view>

#include "../security/auth.hpp"
#include "../security/encryption.hpp"
#include "../security/secure_buffer.hpp"
#include "../../include/storage.hpp"

enum class VaultError {
    None,
    Locked,               // not authenticated / not unlocked
    NoData,               // no data file yet
    DecryptFailed,        // wrong password or corrupted / tampered data file
    StorageError,         // file could not be read or written
    EncryptFailed,
    ForeignDataExists,    // existing data cannot be decrypted with this password; refusing to overwrite
    WeakPassword,         // new password fails length / entropy policy
    WrongCurrentPassword  // current password verification failed during password rotation
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

    VaultError lastError() const;

private:
    Authorizer& authorizer;
    Storage& storage;
    Encryption encryption;
    SecureBuffer session_password;
    bool is_unlocked;
    VaultError last_error;
};

#endif
