#include "auto_unseal.hpp"

#include <sodium.h>

#include <array>
#include <string>

#include "../../include/storage.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#else
#include <cerrno>
#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace
{
    constexpr char KEY_DESCRIPTION_PREFIX[] = "void-vault-autounseal-";

    std::string keyDescription(const std::string& vault_path)
    {
        std::array<unsigned char, crypto_generichash_BYTES> digest{};
        const std::string context = "Void Vault OS auto-unseal v1:" + vault_path;
        crypto_generichash(
            digest.data(),
            digest.size(),
            reinterpret_cast<const unsigned char*>(context.data()),
            context.size(),
            nullptr,
            0);

        std::array<char, crypto_generichash_BYTES * 2 + 1> hex{};
        sodium_bin2hex(hex.data(), hex.size(), digest.data(), digest.size());
        sodium_memzero(digest.data(), digest.size());
        return std::string(KEY_DESCRIPTION_PREFIX) + hex.data();
    }

#ifndef _WIN32
    long addKey(
        const char* type,
        const char* description,
        const void* payload,
        std::size_t payload_size)
    {
        return syscall(
            SYS_add_key,
            type,
            description,
            payload,
            payload_size,
            KEY_SPEC_USER_KEYRING);
    }

    long searchKey(const char* description)
    {
        return syscall(
            SYS_keyctl,
            KEYCTL_SEARCH,
            KEY_SPEC_USER_KEYRING,
            "user",
            description,
            0);
    }

    long readKey(long serial, void* buffer, std::size_t size)
    {
        return syscall(SYS_keyctl, KEYCTL_READ, serial, buffer, size);
    }

    bool unlinkKey(long serial)
    {
        return syscall(
                   SYS_keyctl,
                   KEYCTL_UNLINK,
                   serial,
                   KEY_SPEC_USER_KEYRING)
            >= 0;
    }
#endif
}

bool AutoUnsealStore::protectFragment(
    const std::string& vault_path,
    std::string_view fragment)
{
    if (vault_path.empty() || fragment.size() != 32 ||
        sodium_init() < 0)
    {
        return false;
    }

#ifdef _WIN32
    const std::wstring path = std::filesystem::path(vault_path + ".oskey").wstring();
    if (Storage::isSymlinkOrReparsePoint(vault_path + ".oskey"))
    {
        return false;
    }

    DATA_BLOB input{};
    input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(fragment.data()));
    input.cbData = static_cast<DWORD>(fragment.size());
    DATA_BLOB entropy{};
    std::array<unsigned char, crypto_generichash_BYTES> digest{};
    const std::string context = "Void Vault OS auto-unseal v1:" + vault_path;
    crypto_generichash(
        digest.data(),
        digest.size(),
        reinterpret_cast<const unsigned char*>(context.data()),
        context.size(),
        nullptr,
        0);
    entropy.pbData = digest.data();
    entropy.cbData = static_cast<DWORD>(digest.size());

    DATA_BLOB encrypted{};
    const BOOL protected_ok = CryptProtectData(
        &input,
        L"Void Vault auto-unseal fragment",
        &entropy,
        nullptr,
        nullptr,
        CRYPTPROTECT_UI_FORBIDDEN,
        &encrypted);
    sodium_memzero(digest.data(), digest.size());
    if (!protected_ok)
    {
        return false;
    }

    const std::string blob(
        reinterpret_cast<const char*>(encrypted.pbData),
        encrypted.cbData);
    const bool saved = Storage::atomicWrite(vault_path + ".oskey", blob, true);
    sodium_memzero(encrypted.pbData, encrypted.cbData);
    LocalFree(encrypted.pbData);
    return saved;
#elif defined(__linux__)
    const std::string description = keyDescription(vault_path);
    const long serial = addKey(
        "user",
        description.c_str(),
        fragment.data(),
        fragment.size());
    return serial >= 0;
#else
    (void)fragment;
    return false;
#endif
}

bool AutoUnsealStore::unprotectFragment(
    const std::string& vault_path,
    std::string& fragment)
{
    if (vault_path.empty() || sodium_init() < 0)
    {
        return false;
    }

#ifdef _WIN32
    std::string blob;
    if (!Storage::readFile(vault_path + ".oskey", blob) || blob.empty() ||
        blob.size() > 65536)
    {
        return false;
    }

    DATA_BLOB input{};
    input.pbData = reinterpret_cast<BYTE*>(blob.data());
    input.cbData = static_cast<DWORD>(blob.size());
    DATA_BLOB entropy{};
    std::array<unsigned char, crypto_generichash_BYTES> digest{};
    const std::string context = "Void Vault OS auto-unseal v1:" + vault_path;
    crypto_generichash(
        digest.data(),
        digest.size(),
        reinterpret_cast<const unsigned char*>(context.data()),
        context.size(),
        nullptr,
        0);
    entropy.pbData = digest.data();
    entropy.cbData = static_cast<DWORD>(digest.size());

    DATA_BLOB decrypted{};
    const BOOL decrypted_ok = CryptUnprotectData(
        &input,
        nullptr,
        &entropy,
        nullptr,
        nullptr,
        CRYPTPROTECT_UI_FORBIDDEN,
        &decrypted);
    sodium_memzero(digest.data(), digest.size());
    sodium_memzero(blob.data(), blob.size());
    if (!decrypted_ok)
    {
        return false;
    }

    const bool valid = decrypted.cbData == 32;
    if (valid)
    {
        fragment.assign(
            reinterpret_cast<const char*>(decrypted.pbData),
            decrypted.cbData);
    }
    sodium_memzero(decrypted.pbData, decrypted.cbData);
    LocalFree(decrypted.pbData);
    return valid;
#elif defined(__linux__)
    const std::string description = keyDescription(vault_path);
    const long serial = searchKey(description.c_str());
    if (serial < 0)
    {
        return false;
    }
    std::array<char, 32> bytes{};
    const long read_size = readKey(serial, bytes.data(), bytes.size());
    if (read_size != static_cast<long>(bytes.size()))
    {
        sodium_memzero(bytes.data(), bytes.size());
        return false;
    }
    fragment.assign(bytes.data(), bytes.size());
    sodium_memzero(bytes.data(), bytes.size());
    return true;
#else
    (void)fragment;
    return false;
#endif
}

bool AutoUnsealStore::removeFragment(const std::string& vault_path)
{
    if (vault_path.empty())
    {
        return false;
    }

#ifdef _WIN32
    const std::string path = vault_path + ".oskey";
    if (Storage::isSymlinkOrReparsePoint(path))
    {
        return false;
    }
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
    {
        return !ec;
    }
    return std::filesystem::remove(path, ec) && !ec;
#elif defined(__linux__)
    const std::string description = keyDescription(vault_path);
    const long serial = searchKey(description.c_str());
    if (serial < 0)
    {
        return errno == ENOKEY;
    }
    return unlinkKey(serial);
#else
    return false;
#endif
}
