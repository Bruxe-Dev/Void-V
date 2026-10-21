#ifndef VOID_VAULT_ENCRYPTION_HPP
#define VOID_VAULT_ENCRYPTION_HPP

#include <string>
#include <string_view>

// Configurable Argon2id work factors for key derivation.
// The active profile is encoded in the 4-byte record magic ("VV02" = Interactive,
// "VV2M" = Moderate, "VV2S" = Sensitive) and authenticated as Additional
// Authenticated Data (AAD) so an attacker cannot downgrade the KDF parameters.
enum class KdfProfile
{
    Interactive, // Argon2id INTERACTIVE (64 MiB, 2 ops) - fast interactive/test default
    Moderate,    // Argon2id MODERATE    (256 MiB, 3 ops) - hardened workstation default
    Sensitive    // Argon2id SENSITIVE   (1 GiB, 4 ops)   - maximum offline resistance
};

// Record formats (both have 4 + 16 + 24 + 16 = 60 bytes overhead):
//   v2 (current):
//     magic ("VV02" | "VV2M" | "VV2S", 4 B)
//     | salt  (crypto_pwhash_SALTBYTES = 16 B)
//     | nonce (crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24 B)
//     | XChaCha20-Poly1305-IETF(plaintext, AAD = magic || salt || nonce)
//   v1 (legacy backward-compatible read support):
//     "VV01" (4 B) | salt (16 B) | nonce (24 B) | XSalsa20-Poly1305(plaintext)
class Encryption
{
public:
    explicit Encryption(KdfProfile profile = KdfProfile::Interactive);

    void setKdfProfile(KdfProfile profile) noexcept { profile_ = profile; }
    KdfProfile kdfProfile() const noexcept { return profile_; }

    // On failure, encrypted_data is left unchanged.
    bool encrypt(
        std::string_view plaintext,
        std::string_view password,
        std::string &encrypted_data);

    // Legacy v1 ("VV01") encoder retained for backward-compatibility testing.
    bool encryptLegacyV1(
        std::string_view plaintext,
        std::string_view password,
        std::string &encrypted_data);

    // Transparently decrypts both v2 AEAD ("VV02"/"VV2M"/"VV2S") and legacy
    // v1 ("VV01") records. On failure (wrong password, tampering, truncation,
    // bad magic) plaintext is left unchanged and no partial plaintext is exposed.
    bool decrypt(
        std::string_view encrypted_data,
        std::string_view password,
        std::string &plaintext);

private:
    KdfProfile profile_;
};

#endif
