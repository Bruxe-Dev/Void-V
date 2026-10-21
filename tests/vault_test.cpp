#include "vault/vault.hpp"

#include <cstdio>
#include <string>

#include "test_util.hpp"

using tu::check;

int main()
{
    std::cout << "=== Vault Integration Tests ===\n";
    tu::TempDir dir("vault");
    const std::string test_file = dir.file("vault_test_data.dat");
    const std::string auth_file = dir.file("vault_test_auth.dat");
    const std::string password = "VaultTestPassword123!";
    const std::string original = "Confidential Void Vault test data";

    std::string disk_data;
    {
        Authorizer authorizer(auth_file);
        Storage storage(test_file);
        Vault vault(authorizer, storage);

        check(authorizer.setPassword(password), "Password setup");

        check(!vault.isUnlocked(), "Vault starts locked");
        check(!vault.unlock(), "Unlock without authentication rejected");
        check(!vault.saveData(original), "Saving while locked is rejected");
        check(vault.lastError() == VaultError::Locked, "Locked error reported");

        std::string loaded;
        check(!vault.loadData(loaded), "Loading while locked is rejected");

        check(!vault.authenticate("WrongPassword123!"), "Wrong password fails");
        check(!vault.unlock() && !vault.isUnlocked(), "Failed authentication leaves vault locked");

        check(vault.authenticate(password), "Correct password authenticates");
        check(vault.unlock(), "Authenticated vault unlocks");
        check(vault.isUnlocked(), "Vault reports unlocked");

        check(!vault.loadData(loaded) && vault.lastError() == VaultError::NoData, "NoData before first save");

        check(vault.saveData(original), "Saving encrypted data succeeds");

        disk_data = tu::readAll(test_file);
        check(!disk_data.empty(), "Encrypted file is not empty");
        check(disk_data.find(original) == std::string::npos, "Plaintext is absent from encrypted file");

        check(vault.loadData(loaded) && loaded == original, "Loaded data matches original");

        vault.lock();
        vault.lock();
        check(!vault.isUnlocked() && !authorizer.isAuthorized(), "Lock is idempotent and revokes authorization");
        check(!vault.saveData(original), "Saving after locking is rejected");
        check(!vault.loadData(loaded), "Loading after locking is rejected");

        check(vault.authenticate(password), "Re-authentication succeeds");
        check(vault.unlock(), "Vault unlocks again");
        check(vault.saveData(""), "Saving empty data succeeds");
        check(vault.loadData(loaded) && loaded.empty(), "Empty data loads");
        check(vault.saveData(original), "Restore original data");
        disk_data = tu::readAll(test_file);

        // Corruption
        std::string corrupted = disk_data;
        corrupted.back() = static_cast<char>(corrupted.back() ^ 1);
        tu::writeAll(test_file, corrupted);

        const std::string previous_loaded = loaded;
        check(!vault.loadData(loaded), "Corrupted ciphertext is rejected");
        check(vault.lastError() == VaultError::DecryptFailed, "DecryptFailed reported");
        check(loaded == previous_loaded, "Failed decryption does not overwrite output data");
        check(!vault.saveData("new data"), "Refuses to overwrite undecryptable data");
        check(vault.lastError() == VaultError::ForeignDataExists, "ForeignDataExists reported");
        check(tu::readAll(test_file) == corrupted, "Undecryptable data file preserved");

        tu::writeAll(test_file, disk_data);
        vault.lock();
    }

    // Restart: new objects, same files.
    {
        Authorizer authorizer(auth_file);
        Storage storage(test_file);
        Vault vault(authorizer, storage);
        std::string loaded;
        check(vault.authenticate(password) && vault.unlock(), "Unlock after restart");
        check(vault.loadData(loaded) && loaded == original, "Data persists across restart");
    }

    // Foreign data: another account with a different password must not overwrite.
    {
        const std::string other_auth = dir.file("other_auth.dat");
        Authorizer other(other_auth);
        Storage storage(test_file);
        Vault vault(other, storage);
        check(other.setPassword("DifferentPassword456!"), "Second account setup");
        check(vault.authenticate("DifferentPassword456!") && vault.unlock(), "Second account unlocks");
        std::string loaded = "keep";
        check(!vault.loadData(loaded) && loaded == "keep", "Other password cannot read data");
        check(!vault.saveData("overwrite attempt"), "Other password cannot overwrite data");
        check(tu::readAll(test_file) == disk_data, "Original data intact");
    }

    // Atomic password rotation re-encrypts stored data seamlessly.
    const std::string rotated_pw = "RotatedVaultPass789!";
    {
        Authorizer authorizer(auth_file);
        Storage storage(test_file);
        Vault vault(authorizer, storage);
        check(!vault.changePassword(password, rotated_pw) && vault.lastError() == VaultError::Locked,
              "changePassword while locked is rejected");
        check(vault.authenticate(password) && vault.unlock(), "Unlock before rotation");
        check(!vault.changePassword(password, "short") && vault.lastError() == VaultError::WeakPassword,
              "changePassword rejects weak new password");
        check(!vault.changePassword("WrongCurrentPass!", rotated_pw) && !vault.isUnlocked(),
              "changePassword with wrong current password locks vault");
        check(vault.authenticate(password) && vault.unlock(), "Re-unlock after failed rotation");
        check(vault.changePassword(password, rotated_pw), "changePassword succeeds and re-encrypts data");
        std::string loaded;
        check(vault.loadData(loaded) && loaded == original, "Data readable immediately after rotation");
    }
    {
        Authorizer authorizer(auth_file);
        Storage storage(test_file);
        Vault vault(authorizer, storage);
        check(!vault.authenticate(password), "Old password rejected after rotation");
        check(vault.authenticate(rotated_pw) && vault.unlock(), "New password unlocks after restart");
        std::string loaded;
        check(vault.loadData(loaded) && loaded == original, "Re-encrypted data persists across restart");
    }

    return tu::finish("vault");
}