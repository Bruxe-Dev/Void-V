#include "encryption.hpp"

#include <sodium.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

namespace
{
    constexpr char MAGIC_V1[] = "VV01";
    constexpr char MAGIC_V2_INTERACTIVE[] = "VV02";
    constexpr char MAGIC_V2_MODERATE[] = "VV2M";
    constexpr char MAGIC_V2_SENSITIVE[] = "VV2S";

    constexpr std::size_t MAGIC_SIZE = 4;
    constexpr std::size_t SALT_SIZE = crypto_pwhash_SALTBYTES; // 16
    constexpr std::size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    constexpr std::size_t MAC_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16
    constexpr std::size_t KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32
    constexpr std::size_t HEADER_SIZE = MAGIC_SIZE + SALT_SIZE + NONCE_SIZE; // 44

    static_assert(NONCE_SIZE == crypto_secretbox_NONCEBYTES, "Nonce size mismatch");
    static_assert(MAC_SIZE == crypto_secretbox_MACBYTES, "MAC size mismatch");
    static_assert(KEY_SIZE == crypto_secretbox_KEYBYTES, "Key size mismatch");

    const char *magicForProfile(KdfProfile profile) noexcept
    {
        switch (profile)
        {
        case KdfProfile::Interactive:
            return MAGIC_V2_INTERACTIVE;
        case KdfProfile::Moderate:
            return MAGIC_V2_MODERATE;
        case KdfProfile::Sensitive:
            return MAGIC_V2_SENSITIVE;
        }
        return MAGIC_V2_INTERACTIVE;
    }

    void kdfParams(KdfProfile profile, unsigned long long &opslimit, std::size_t &memlimit) noexcept
    {
        switch (profile)
        {
        case KdfProfile::Interactive:
            opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
            memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
            return;
        case KdfProfile::Moderate:
            opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
            memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
            return;
        case KdfProfile::Sensitive:
            opslimit = crypto_pwhash_OPSLIMIT_SENSITIVE;
            memlimit = crypto_pwhash_MEMLIMIT_SENSITIVE;
            return;
        }
        opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
        memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    }

    bool deriveKey(
        unsigned char *key,
        std::string_view password,
        const unsigned char *salt,
        KdfProfile profile)
    {
        unsigned long long opslimit = 0;
        std::size_t memlimit = 0;
        kdfParams(profile, opslimit, memlimit);

        return crypto_pwhash(
                   key,
                   KEY_SIZE,
                   password.data(),
                   password.size(),
                   salt,
                   opslimit,
                   memlimit,
                   crypto_pwhash_ALG_ARGON2ID13) == 0;
    }

    // RAII guard that mlocks a 32-byte key buffer and zeroes + munlocks on exit.
    struct LockedKey
    {
        unsigned char bytes[KEY_SIZE]{};
        LockedKey() noexcept { (void)sodium_mlock(bytes, sizeof(bytes)); }
        ~LockedKey() noexcept { (void)sodium_munlock(bytes, sizeof(bytes)); }
        LockedKey(const LockedKey &) = delete;
        LockedKey &operator=(const LockedKey &) = delete;
    };
}

Encryption::Encryption(KdfProfile profile)
    : profile_(profile)
{
    if (sodium_init() < 0)
    {
        throw std::runtime_error("Libsodium initialization failed");
    }
}

bool Encryption::encrypt(
    std::string_view plaintext,
    std::string_view password,
    std::string &encrypted_data)
{
    if (password.empty() ||
        plaintext.size() > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX)
    {
        return false;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    LockedKey key;

    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);

    if (!deriveKey(key.bytes, password, salt, profile_))
    {
        return false;
    }

    std::string record(HEADER_SIZE + MAC_SIZE + plaintext.size(), '\0');
    auto *out = reinterpret_cast<unsigned char *>(record.data());
    const char *magic = magicForProfile(profile_);
    std::memcpy(out, magic, MAGIC_SIZE);
    std::memcpy(out + MAGIC_SIZE, salt, SALT_SIZE);
    std::memcpy(out + MAGIC_SIZE + SALT_SIZE, nonce, NONCE_SIZE);

    unsigned long long ciphertext_len = 0;
    const int status = crypto_aead_xchacha20poly1305_ietf_encrypt(
        out + HEADER_SIZE,
        &ciphertext_len,
        reinterpret_cast<const unsigned char *>(plaintext.data()),
        static_cast<unsigned long long>(plaintext.size()),
        out, // Authenticate the entire 44-byte header (magic || salt || nonce) as AAD
        HEADER_SIZE,
        nullptr,
        nonce,
        key.bytes);

    if (status != 0 || ciphertext_len != MAC_SIZE + plaintext.size())
    {
        sodium_memzero(record.data(), record.size());
        return false;
    }

    encrypted_data = std::move(record);
    return true;
}

bool Encryption::encryptLegacyV1(
    std::string_view plaintext,
    std::string_view password,
    std::string &encrypted_data)
{
    if (password.empty() ||
        plaintext.size() > crypto_secretbox_MESSAGEBYTES_MAX - crypto_secretbox_MACBYTES)
    {
        return false;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    LockedKey key;

    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);

    if (!deriveKey(key.bytes, password, salt, KdfProfile::Interactive))
    {
        return false;
    }

    std::string record(HEADER_SIZE + MAC_SIZE + plaintext.size(), '\0');
    auto *out = reinterpret_cast<unsigned char *>(record.data());
    std::memcpy(out, MAGIC_V1, MAGIC_SIZE);
    std::memcpy(out + MAGIC_SIZE, salt, SALT_SIZE);
    std::memcpy(out + MAGIC_SIZE + SALT_SIZE, nonce, NONCE_SIZE);

    const int status = crypto_secretbox_easy(
        out + HEADER_SIZE,
        reinterpret_cast<const unsigned char *>(plaintext.data()),
        plaintext.size(),
        nonce,
        key.bytes);

    if (status != 0)
    {
        sodium_memzero(record.data(), record.size());
        return false;
    }

    encrypted_data = std::move(record);
    return true;
}

bool Encryption::decrypt(
    std::string_view encrypted_data,
    std::string_view password,
    std::string &plaintext)
{
    if (password.empty() || encrypted_data.size() < HEADER_SIZE + MAC_SIZE)
    {
        return false;
    }

    bool is_v1 = false;
    KdfProfile record_profile = KdfProfile::Interactive;
    if (encrypted_data.compare(0, MAGIC_SIZE, MAGIC_V2_INTERACTIVE) == 0)
    {
        record_profile = KdfProfile::Interactive;
    }
    else if (encrypted_data.compare(0, MAGIC_SIZE, MAGIC_V2_MODERATE) == 0)
    {
        record_profile = KdfProfile::Moderate;
    }
    else if (encrypted_data.compare(0, MAGIC_SIZE, MAGIC_V2_SENSITIVE) == 0)
    {
        record_profile = KdfProfile::Sensitive;
    }
    else if (encrypted_data.compare(0, MAGIC_SIZE, MAGIC_V1) == 0)
    {
        is_v1 = true;
        record_profile = KdfProfile::Interactive;
    }
    else
    {
        return false;
    }

    const auto *bytes =
        reinterpret_cast<const unsigned char *>(encrypted_data.data());
    const unsigned char *salt = bytes + MAGIC_SIZE;
    const unsigned char *nonce = salt + SALT_SIZE;
    const unsigned char *ciphertext = nonce + NONCE_SIZE;
    const std::size_t ciphertext_size = encrypted_data.size() - HEADER_SIZE;

    LockedKey key;
    if (!deriveKey(key.bytes, password, salt, record_profile))
    {
        return false;
    }

    std::string result(ciphertext_size - MAC_SIZE, '\0');
    int status = -1;

    if (is_v1)
    {
        status = crypto_secretbox_open_easy(
            reinterpret_cast<unsigned char *>(result.data()),
            ciphertext,
            ciphertext_size,
            nonce,
            key.bytes);
    }
    else
    {
        unsigned long long decrypted_len = 0;
        status = crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char *>(result.data()),
            &decrypted_len,
            nullptr,
            ciphertext,
            static_cast<unsigned long long>(ciphertext_size),
            bytes, // Verify the 44-byte header (magic || salt || nonce) AAD
            HEADER_SIZE,
            nonce,
            key.bytes);
        if (status == 0 && decrypted_len != result.size())
        {
            status = -1;
        }
    }

    if (status != 0)
    {
        sodium_memzero(result.data(), result.size());
        return false;
    }

    // Wipe the previous plaintext held by the caller before replacing it.
    if (!plaintext.empty())
    {
        sodium_memzero(plaintext.data(), plaintext.size());
    }
    plaintext = std::move(result);
    return true;
}
