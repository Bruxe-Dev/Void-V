#ifndef VOID_VAULT_BROKER_HPP
#define VOID_VAULT_BROKER_HPP

#include <cstdint>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "vault.hpp"
#include "../security/secure_buffer.hpp"
#include "operation_engine.hpp"
#include "pki_engine.hpp"
#include "transit_engine.hpp"

// Represents a parsed and verified "Sign in with Void Vault" capability token.
// Format on the wire:
//   VVTOK1.<hex(payload)>.<hex(hmac_sha512256)>
// where payload encodes:
//   issued_at (uint64) | expires_at (uint64) | app_id | scope
//
// Scopes supported:
//   "*"                 -> full access to all named secrets
//   "read:*"            -> read-only access to all named secrets
//   "read:<prefix>*"    -> read-only access to keys starting with <prefix>
//   "write:<prefix>*"   -> read + write access to keys starting with <prefix>
//   "key:<exact_key>"   -> read + write access to a single exact key
//   "read_key:<key>"    -> read-only access to a single exact key
//   "auth:only"         -> identity/sign-in verification & subkey derivation only (no secret read/write)
struct CapabilityClaims
{
    std::uint64_t issued_at = 0;
    std::uint64_t expires_at = 0;
    std::string app_id;
    std::string scope;
};

// Embeddable Zero-Knowledge Key-Value Secret Store & Local OAuth-Style
// Capability Broker ("Sign in / Authorize with Void Vault") built on top of Vault.
//
// Persistent named secrets and internal broker signing/KDF keys are serialized
// inside the encrypted "VVKV1" payload. Ephemeral secrets remain in protected
// process memory only and are wiped on expiry or broker destruction.
class VaultBroker : public OperationEngine
{
public:
    static constexpr std::size_t MAX_EPHEMERAL_SECRETS = 1024;
    static constexpr std::uint64_t MAX_EPHEMERAL_TTL_SECONDS = 86400;
    static constexpr std::size_t MAX_EPHEMERAL_VALUE_SIZE = 4096;
    static constexpr std::uint64_t DEFAULT_TOKEN_TTL_SECONDS = 300; // 5 minutes
    static constexpr std::uint64_t MAX_TOKEN_TTL_SECONDS = 86400;   // 24 hours
    static constexpr std::size_t MAX_KEY_LENGTH = 256;

    explicit VaultBroker(Vault &vault);
    ~VaultBroker();

    VaultBroker(const VaultBroker &) = delete;
    VaultBroker &operator=(const VaultBroker &) = delete;

    // --- Direct Unlocked Key-Value Operations (for Vault Owner) ---
    bool setSecret(std::string_view key, std::string_view value);
    bool getSecret(std::string_view key, std::string &out_value);
    bool deleteSecret(std::string_view key);
    bool listKeys(std::vector<std::string> &out_keys);
    bool setEphemeralSecret(
        std::string_view key,
        std::string_view value,
        std::uint64_t ttl_seconds);

    bool getEphemeralSecret(std::string_view key, std::string &out_value);
    bool deleteEphemeralSecret(std::string_view key);

    bool transitEncrypt(
        std::string_view token,
        std::string_view app_id,
        std::string_view key_id,
        std::string_view plaintext,
        std::string& out_ciphertext,
        std::uint64_t now_unix = 0);

    bool transitDecrypt(
        std::string_view token,
        std::string_view app_id,
        std::string_view key_id,
        std::string_view ciphertext,
        std::string& out_plaintext,
        std::uint64_t now_unix = 0);

    bool createPkiAuthority(
        std::string_view authority_id,
        std::string_view common_name,
        std::string& out_certificate);
    bool issuePkiCertificate(
        std::string_view authority_id,
        std::string_view common_name,
        std::uint64_t validity_days,
        std::string& out_certificate);

    EngineKind kind() const noexcept override { return EngineKind::KeyValue; }
    bool supportsOperation(std::string_view operation) const noexcept override;
    OperationEngine& transitEngine() noexcept { return transit_engine_; }
    OperationEngine& pkiEngine() noexcept { return pki_engine_; }

    // --- "Sign in with Void Vault" Delegated App Authorization ---
    // Issues a cryptographically signed (HMAC-SHA512256), time-bounded
    // capability token for `app_id` with `scope`. Never exposes the user's
    // master password to the calling module.
    bool issueToken(
        std::string_view app_id,
        std::string_view scope,
        std::uint64_t ttl_seconds,
        std::string &out_token,
        std::uint64_t now_unix = 0);

    // Verifies a token's cryptographic MAC, expiration timestamp, and app_id
    // in constant time. Populates `out_claims` on success.
    bool verifyToken(
        std::string_view token,
        std::string_view expected_app_id,
        CapabilityClaims &out_claims,
        std::uint64_t now_unix = 0);

    // Revokes all tokens issued specifically for `app_id` without invalidating
    // tokens belonging to other applications.
    bool revokeAppTokens(std::string_view app_id);

    // Revokes all previously issued tokens across all apps immediately by
    // rotating the internal 256-bit broker signing key inside the encrypted vault.
    bool revokeAllTokens();

    // --- Scoped Secret Access for External Modules Using a Token ---
    bool getSecretWithToken(
        std::string_view token,
        std::string_view app_id,
        std::string_view key,
        std::string &out_value,
        std::uint64_t now_unix = 0);

    bool setSecretWithToken(
        std::string_view token,
        std::string_view app_id,
        std::string_view key,
        std::string_view value,
        std::uint64_t now_unix = 0);

    // --- Zero-Knowledge App Subkey Derivation (BLAKE2b KDF) ---
    // Derives an isolated 32-byte (64-hex-char) cryptographic subkey for
    // `app_id` + `subkey_id` using libsodium's crypto_kdf_derive_from_key so an
    // external application can encrypt its own local database without ever
    // seeing the user's master password or other apps' keys.
    bool deriveAppKey(
        std::string_view token,
        std::string_view app_id,
        std::uint64_t subkey_id,
        std::string &out_key_hex,
        std::uint64_t now_unix = 0);

    static bool isValidKeyName(std::string_view key) noexcept;
    static bool scopeAllowsRead(std::string_view scope, std::string_view key) noexcept;
    static bool scopeAllowsWrite(std::string_view scope, std::string_view key) noexcept;

private:
    struct KeyValue {
        std::string key;
        std::string value;
    };

    using Clock = std::chrono::steady_clock;

    struct EphemeralSecret {
        SecureBuffer value;
        Clock::time_point expires_at;
    };

    void purgeExpiredEphemeralSecrets(Clock::time_point now);
    void clearEphemeralSecrets();
    void runExpiryWorker();

    void recordAudit(std::string_view event, std::string_view actor, std::string_view target);
    bool loadStore(std::vector<KeyValue>& entries, unsigned char master_key[32], bool& has_master_key);
    bool saveStore(const std::vector<KeyValue>& entries, const unsigned char master_key[32]);
    bool ensureBrokerKey(std::vector<KeyValue>& entries, unsigned char master_key[32]);
    bool ensureTransitKey(unsigned char transit_key[32]);
    bool storeInternalSecret(std::string_view key, std::string_view value);
    bool loadInternalSecret(std::string_view key, std::string& out_value);

    Vault& vault_;
    std::unordered_map<std::string, EphemeralSecret> ephemeral_secrets_;
    std::mutex ephemeral_mutex_;
    std::condition_variable ephemeral_cv_;
    std::thread expiry_thread_;
    bool stop_expiry_thread_ = false;
    TransitEngine transit_engine_;
    PkiEngine pki_engine_;

};

#endif
