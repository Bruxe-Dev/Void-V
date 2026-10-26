#include "transit_engine.hpp"

#include <sodium.h>

#include <cstring>

namespace
{
    constexpr char MAGIC[] = "VVTX1";
    constexpr std::size_t MAGIC_SIZE = sizeof(MAGIC) - 1;
    constexpr std::size_t NONCE_SIZE =
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    constexpr std::size_t TAG_SIZE =
        crypto_aead_xchacha20poly1305_ietf_ABYTES;

    bool validKeyId(std::string_view key_id) noexcept
    {
        if (key_id.empty() || key_id.size() > 64)
        {
            return false;
        }
        for (const char c : key_id)
        {
            const auto uc = static_cast<unsigned char>(c);
            if (!((uc >= 'a' && uc <= 'z') ||
                  (uc >= 'A' && uc <= 'Z') ||
                  (uc >= '0' && uc <= '9') ||
                  c == '_' || c == '-' || c == '.'))
            {
                return false;
            }
        }
        return true;
    }

    std::string makeAad(std::string_view key_id)
    {
        std::string aad(MAGIC, MAGIC_SIZE);
        aad.push_back('\0');
        aad.append(key_id);
        return aad;
    }

    bool deriveTransitKey(
        const unsigned char root_key[32],
        std::string_view key_id,
        unsigned char out_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES])
    {
        constexpr std::string_view DOMAIN = "Void Vault Transit key v1:";
        std::string context(DOMAIN);
        context.append(key_id);
        crypto_auth_hmacsha512256(
            out_key,
            reinterpret_cast<const unsigned char*>(context.data()),
            context.size(),
            root_key);
        sodium_memzero(context.data(), context.size());
        return true;
    }
}

bool TransitEngine::supportsOperation(std::string_view operation) const noexcept
{
    return operation == "TRANSIT_ENCRYPT" ||
           operation == "TRANSIT_DECRYPT";
}

bool TransitEngine::encrypt(
    const unsigned char root_key[32],
    std::string_view key_id,
    std::string_view plaintext,
    std::string& out_ciphertext) const
{
    if (root_key == nullptr || !validKeyId(key_id) ||
        plaintext.size() > MAX_MESSAGE_SIZE ||
        sodium_init() < 0)
    {
        return false;
    }

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]{};
    unsigned char nonce[NONCE_SIZE]{};
    randombytes_buf(nonce, sizeof(nonce));
    if (!deriveTransitKey(root_key, key_id, key))
    {
        sodium_memzero(nonce, sizeof(nonce));
        return false;
    }

    std::string aad = makeAad(key_id);
    std::string result(MAGIC, MAGIC_SIZE);
    result.append(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    const std::size_t cipher_offset = result.size();
    result.resize(cipher_offset + plaintext.size() + TAG_SIZE, '\0');

    unsigned long long cipher_size = 0;
    const int status = crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(result.data() + cipher_offset),
        &cipher_size,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        static_cast<unsigned long long>(plaintext.size()),
        reinterpret_cast<const unsigned char*>(aad.data()),
        static_cast<unsigned long long>(aad.size()),
        nullptr,
        nonce,
        key);

    sodium_memzero(key, sizeof(key));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(aad.data(), aad.size());
    if (status != 0 || cipher_size != plaintext.size() + TAG_SIZE)
    {
        sodium_memzero(result.data(), result.size());
        return false;
    }

    out_ciphertext = std::move(result);
    return true;
}

bool TransitEngine::decrypt(
    const unsigned char root_key[32],
    std::string_view key_id,
    std::string_view ciphertext,
    std::string& out_plaintext) const
{
    if (root_key == nullptr || !validKeyId(key_id) ||
        ciphertext.size() < MAGIC_SIZE + NONCE_SIZE + TAG_SIZE ||
        ciphertext.size() > MAGIC_SIZE + NONCE_SIZE + MAX_MESSAGE_SIZE + TAG_SIZE ||
        ciphertext.compare(0, MAGIC_SIZE, MAGIC) != 0 ||
        sodium_init() < 0)
    {
        return false;
    }

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]{};
    if (!deriveTransitKey(root_key, key_id, key))
    {
        return false;
    }

    const auto* nonce = reinterpret_cast<const unsigned char*>(
        ciphertext.data() + MAGIC_SIZE);
    const auto* encrypted = reinterpret_cast<const unsigned char*>(
        ciphertext.data() + MAGIC_SIZE + NONCE_SIZE);
    const std::size_t encrypted_size =
        ciphertext.size() - MAGIC_SIZE - NONCE_SIZE;
    std::string aad = makeAad(key_id);
    std::string plaintext(encrypted_size - TAG_SIZE, '\0');
    unsigned long long plaintext_size = 0;
    const int status = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(plaintext.data()),
        &plaintext_size,
        nullptr,
        encrypted,
        static_cast<unsigned long long>(encrypted_size),
        reinterpret_cast<const unsigned char*>(aad.data()),
        static_cast<unsigned long long>(aad.size()),
        nonce,
        key);

    sodium_memzero(key, sizeof(key));
    sodium_memzero(aad.data(), aad.size());
    if (status != 0 || plaintext_size != plaintext.size())
    {
        if (!plaintext.empty())
        {
            sodium_memzero(plaintext.data(), plaintext.size());
        }
        return false;
    }

    out_plaintext = std::move(plaintext);
    return true;
}
