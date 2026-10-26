#include "vault/broker.hpp"
#include "void_vault_c.h"

#include <cstring>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "test_util.hpp"

using tu::check;

int main()
{
    std::cout << "=== VaultBroker & Delegated Capability Token Tests ===\n";
    tu::TempDir dir("broker");
    const std::string data_file = dir.file("broker_data.dat");
    const std::string auth_file = dir.file("broker_auth.dat");
    const std::string password = "BrokerMasterPassword123!";

    // --- 1. Multi-secret encrypted key-value store ---
    {
        Authorizer auth(auth_file);
        Storage storage(data_file);
        Vault vault(auth, storage);
        VaultBroker broker(vault);

        check(auth.setPassword(password), "Master password setup");
        check(!broker.setSecret("trader.mt5_password", "secret1"), "setSecret rejected while vault is locked");

        check(vault.authenticate(password) && vault.unlock(), "Vault unlocked");
        check(broker.setSecret("trader.mt5_login", "100200300"), "Save trader.mt5_login");
        check(broker.setSecret("trader.mt5_password", "MyBrokerSecret!99"), "Save trader.mt5_password");
        check(broker.setSecret("medical.patient_id", "PAT-88421"), "Save medical.patient_id");
        check(!broker.setSecret("__vv_reserved", "bad"), "Reserved prefix __vv_ rejected");
        check(!broker.setSecret("invalid key with spaces", "bad"), "Key with whitespace rejected");

        // Verify neither keys nor values appear in plaintext on disk
        const std::string disk_cipher = tu::readAll(data_file);
        check(disk_cipher.find("trader.mt5_password") == std::string::npos,
              "Key names are hidden inside AEAD ciphertext on disk");
        check(disk_cipher.find("MyBrokerSecret!99") == std::string::npos,
              "Secret values are hidden inside AEAD ciphertext on disk");

        std::vector<std::string> keys;
        check(broker.listKeys(keys) && keys.size() == 3, "listKeys returns 3 user keys (internal broker key hidden)");

        std::string val;
        check(broker.getSecret("trader.mt5_password", val) && val == "MyBrokerSecret!99", "getSecret retrieves exact value");
        check(broker.setSecret("trader.mt5_password", "UpdatedBrokerSecret!00"), "Overwrite existing key");
        check(broker.getSecret("trader.mt5_password", val) && val == "UpdatedBrokerSecret!00", "Updated value retrieved");

        check(broker.setEphemeralSecret("session.temporary", "short-lived", 1),
              "Save in-memory ephemeral secret");
        check(broker.getEphemeralSecret("session.temporary", val) && val == "short-lived",
              "Read ephemeral secret before expiry");
        check(!broker.setEphemeralSecret("session.zero_ttl", "invalid", 0),
              "Reject zero ephemeral TTL");
        check(!broker.setEphemeralSecret(
                  "session.long_ttl",
                  "invalid",
                  VaultBroker::MAX_EPHEMERAL_TTL_SECONDS + 1),
              "Reject ephemeral TTL above limit");
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        check(!broker.getEphemeralSecret("session.temporary", val),
              "Reject ephemeral secret after expiry");

        check(broker.setEphemeralSecret("session.delete", "remove-me", 30),
              "Save another ephemeral secret");
        check(broker.deleteEphemeralSecret("session.delete"),
              "Delete ephemeral secret before expiry");
        check(!broker.getEphemeralSecret("session.delete", val),
              "Deleted ephemeral secret is no longer readable");

        vault.lock();
        check(!broker.getEphemeralSecret("session.temporary", val),
              "Ephemeral reads rejected while vault is locked");
        check(vault.authenticate(password) && vault.unlock(),
              "Vault unlocked after ephemeral tests");
    }

    // --- 2. "Sign in with Void Vault" Scoped Capability Tokens & App Isolation ---
    {
        Authorizer auth(auth_file);
        Storage storage(data_file);
        Vault vault(auth, storage);
        VaultBroker broker(vault);

        check(vault.authenticate(password) && vault.unlock(), "Unlock after restart");

        std::string trader_read_token;
        check(broker.issueToken("void-trader", "read:trader.*", 300, trader_read_token, 1000),
              "Issue read:trader.* token for void-trader");

        CapabilityClaims claims;
        check(broker.verifyToken(trader_read_token, "void-trader", claims, 1100) &&
                  claims.scope == "read:trader.*" && claims.expires_at == 1300,
              "verifyToken succeeds within TTL for matching app_id");
        check(!broker.verifyToken(trader_read_token, "other-app", claims, 1100),
              "verifyToken rejects token presented by wrong app_id");
        check(!broker.verifyToken(trader_read_token, "void-trader", claims, 1301),
              "verifyToken rejects expired token");

        // Tamper with token MAC
        std::string tampered = trader_read_token;
        if (!tampered.empty())
        {
            tampered.back() = (tampered.back() == 'a') ? 'b' : 'a';
        }
        check(!broker.verifyToken(tampered, "void-trader", claims, 1100),
              "Tampered token rejected by HMAC-SHA512256");

        // Scope enforcement: void-trader with read:trader.* can read trader.* but NOT medical.* and CANNOT write
        std::string secret_out;
        check(broker.getSecretWithToken(trader_read_token, "void-trader", "trader.mt5_password", secret_out, 1100) &&
                  secret_out == "UpdatedBrokerSecret!00",
              "Scoped token reads permitted key (trader.mt5_password)");
        check(!broker.getSecretWithToken(trader_read_token, "void-trader", "medical.patient_id", secret_out, 1100),
              "Scoped token blocked from reading another namespace (medical.patient_id)");
        check(!broker.setSecretWithToken(trader_read_token, "void-trader", "trader.mt5_password", "hacked", 1100),
              "Read-only token blocked from modifying secrets");

        // Issue write:trader.* token and verify write succeeds only in trader.* namespace
        std::string trader_write_token;
        check(broker.issueToken("void-trader", "write:trader.*", 300, trader_write_token, 1000),
              "Issue write:trader.* token");
        check(broker.setSecretWithToken(trader_write_token, "void-trader", "trader.api_token", "tok-xyz", 1100),
              "write:trader.* token can write trader.api_token");
        check(!broker.setSecretWithToken(trader_write_token, "void-trader", "medical.patient_id", "hacked", 1100),
              "write:trader.* token blocked from writing medical.patient_id");

        // --- 3. Zero-Knowledge App Subkey Derivation (BLAKE2b KDF) ---
        std::string key_trader_1, key_trader_1_again, key_trader_2;
        check(broker.deriveAppKey(trader_read_token, "void-trader", 1, key_trader_1, 1100) &&
                  key_trader_1.size() == 64,
              "deriveAppKey produces 256-bit (64 hex char) key");
        check(broker.deriveAppKey(trader_read_token, "void-trader", 1, key_trader_1_again, 1100) &&
                  key_trader_1 == key_trader_1_again,
              "deriveAppKey is deterministic for same app_id and subkey_id");
        check(broker.deriveAppKey(trader_read_token, "void-trader", 2, key_trader_2, 1100) &&
                  key_trader_1 != key_trader_2,
              "Different subkey_id produces distinct cryptographic subkey");

        std::string med_token, key_med_1;
        check(broker.issueToken("medical-app", "auth:only", 300, med_token, 1000),
              "Issue auth:only token for medical-app");
        check(broker.deriveAppKey(med_token, "medical-app", 1, key_med_1, 1100) &&
                  key_med_1 != key_trader_1,
              "Different app_id derives completely isolated subkey");

        // --- 4. Per-App & Global Token Revocation ---
        check(broker.revokeAppTokens("void-trader"), "revokeAppTokens(void-trader) succeeds");
        check(!broker.verifyToken(trader_read_token, "void-trader", claims, 1100),
              "void-trader token is immediately invalidated after revokeAppTokens(void-trader)");
        check(broker.verifyToken(med_token, "medical-app", claims, 1100),
              "medical-app token remains valid when only void-trader is revoked");

        check(broker.revokeAllTokens(), "revokeAllTokens rotates internal broker key");
        check(!broker.verifyToken(med_token, "medical-app", claims, 1100),
              "All remaining tokens invalidated after revokeAllTokens");
    }

    // --- 5. Universal C ABI v2 (void_vault_c.h) test ---
    {
        const std::string c_auth = dir.file("c_abi_auth.dat");
        const std::string c_data = dir.file("c_abi_data.dat");
        const std::string c_audit = c_data + ".audit.log";
        VoidVaultHandle *h = vv_open(c_auth.c_str(), c_data.c_str());
        check(h != nullptr, "vv_open creates handle");
        check(vv_is_initialized(h) == 0, "vv_is_initialized returns 0 initially");
        check(vv_setup_password(h, password.c_str()) == 1, "vv_setup_password succeeds");
        check(vv_unlock(h, password.c_str()) == 1 && vv_is_unlocked(h) == 1, "vv_unlock unlocks vault");
        check(vv_set_secret(h, "app.secret", "c-abi-payload") == 1, "vv_set_secret stores secret");

        char token_buf[512]{};
        check(vv_issue_token(h, "c-client", "read:app.*", 300, token_buf, sizeof(token_buf)) == 1,
              "vv_issue_token issues token via C ABI");
        check(vv_verify_token(h, token_buf, "c-client") == 1, "vv_verify_token validates token via C ABI");

        char secret_buf[128]{};
        check(vv_get_secret_with_token(h, token_buf, "c-client", "app.secret", secret_buf, sizeof(secret_buf)) == 1 &&
                  std::strcmp(secret_buf, "c-abi-payload") == 0,
              "vv_get_secret_with_token retrieves secret via C ABI");

        char app_key_hex[65]{};
        check(vv_derive_app_key(h, token_buf, "c-client", 1, app_key_hex, sizeof(app_key_hex)) == 1 &&
                  std::strlen(app_key_hex) == 64,
              "vv_derive_app_key derives 64-hex-char subkey via C ABI");

        check(vv_revoke_app_tokens(h, "c-client") == 1, "vv_revoke_app_tokens succeeds via C ABI");
        check(vv_verify_token(h, token_buf, "c-client") == 0, "Revoked app token rejected via C ABI");

        char rec_key_buf[64]{};
        check(vv_generate_recovery_key(h, rec_key_buf, sizeof(rec_key_buf)) == 1 &&
                  std::strncmp(rec_key_buf, "VVREC-", 6) == 0,
              "vv_generate_recovery_key generates VVREC- key via C ABI");

        vv_lock(h);
        check(vv_is_unlocked(h) == 0, "vv_lock locks vault");
        check(vv_recover_with_emergency_key(h, rec_key_buf, "NewCAbiMasterPass99!") == 1 &&
                  vv_is_unlocked(h) == 1,
              "vv_recover_with_emergency_key recovers and unlocks vault via C ABI");

        std::size_t audit_count = 0;
        std::size_t failed_line = 0;
        check(vv_verify_audit_log(c_audit.c_str(), &audit_count, &failed_line) == 1 && audit_count >= 5,
              "vv_verify_audit_log verifies BLAKE2b hash chain via C ABI");

        vv_close(h);
    }

    return tu::finish("broker");
}
