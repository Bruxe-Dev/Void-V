#include "../../include/void_vault_c.h"

#include <sodium.h>

#include <cstring>
#include <memory>
#include <new>
#include <string>

#include "../../include/storage.hpp"
#include "../security/auth.hpp"
#include "broker.hpp"
#include "vault.hpp"

struct VoidVaultHandle {
    Authorizer authorizer;
    Storage storage;
    Vault vault;
    VaultBroker broker;

    VoidVaultHandle(const std::string& auth_path, const std::string& data_path)
        : authorizer(auth_path),
          storage(data_path),
          vault(authorizer, storage),
          broker(vault)
    {
    }
};

namespace
{
    int copyOutString(std::string &src, char *out_buf, std::size_t out_buf_size) noexcept
    {
        if (out_buf == nullptr || out_buf_size <= src.size())
        {
            if (!src.empty())
            {
                sodium_memzero(src.data(), src.size());
            }
            return 0;
        }
        std::memcpy(out_buf, src.data(), src.size());
        out_buf[src.size()] = '\0';
        if (!src.empty())
        {
            sodium_memzero(src.data(), src.size());
        }
        return 1;
    }
}

extern "C" {

VoidVaultHandle* vv_open(const char* auth_file_path, const char* data_file_path)
{
    if (auth_file_path == nullptr || data_file_path == nullptr)
    {
        return nullptr;
    }
    try
    {
        return new VoidVaultHandle(auth_file_path, data_file_path);
    }
    catch (...)
    {
        return nullptr;
    }
}

void vv_close(VoidVaultHandle* handle)
{
    delete handle;
}

int vv_is_initialized(const VoidVaultHandle* handle)
{
    if (handle == nullptr)
    {
        return 0;
    }
    return handle->authorizer.isInitialized() ? 1 : 0;
}

int vv_is_unlocked(const VoidVaultHandle* handle)
{
    if (handle == nullptr)
    {
        return 0;
    }
    return handle->vault.isUnlocked() ? 1 : 0;
}

int vv_setup_password(VoidVaultHandle* handle, const char* new_password)
{
    if (handle == nullptr || new_password == nullptr)
    {
        return 0;
    }
    return handle->authorizer.setPassword(new_password) ? 1 : 0;
}

int vv_unlock(VoidVaultHandle* handle, const char* password)
{
    if (handle == nullptr || password == nullptr)
    {
        return 0;
    }
    if (!handle->vault.authenticate(password))
    {
        return 0;
    }
    return handle->vault.unlock() ? 1 : 0;
}

void vv_lock(VoidVaultHandle* handle)
{
    if (handle != nullptr)
    {
        handle->vault.lock();
    }
}

int vv_set_secret(VoidVaultHandle* handle, const char* key, const char* value)
{
    if (handle == nullptr || key == nullptr || value == nullptr)
    {
        return 0;
    }
    return handle->broker.setSecret(key, value) ? 1 : 0;
}

int vv_get_secret(
    VoidVaultHandle* handle,
    const char* key,
    char* out_buf,
    size_t out_buf_size)
{
    if (handle == nullptr || key == nullptr)
    {
        return 0;
    }
    std::string val;
    if (!handle->broker.getSecret(key, val))
    {
        return 0;
    }
    return copyOutString(val, out_buf, out_buf_size);
}

int vv_issue_token(
    VoidVaultHandle* handle,
    const char* app_id,
    const char* scope,
    uint64_t ttl_seconds,
    char* out_token_buf,
    size_t out_token_buf_size)
{
    if (handle == nullptr || app_id == nullptr || scope == nullptr)
    {
        return 0;
    }
    std::string token;
    if (!handle->broker.issueToken(app_id, scope, ttl_seconds, token))
    {
        return 0;
    }
    return copyOutString(token, out_token_buf, out_token_buf_size);
}

int vv_verify_token(
    VoidVaultHandle* handle,
    const char* token,
    const char* expected_app_id)
{
    if (handle == nullptr || token == nullptr || expected_app_id == nullptr)
    {
        return 0;
    }
    CapabilityClaims claims;
    return handle->broker.verifyToken(token, expected_app_id, claims) ? 1 : 0;
}

int vv_get_secret_with_token(
    VoidVaultHandle* handle,
    const char* token,
    const char* app_id,
    const char* key,
    char* out_buf,
    size_t out_buf_size)
{
    if (handle == nullptr || token == nullptr || app_id == nullptr || key == nullptr)
    {
        return 0;
    }
    std::string val;
    if (!handle->broker.getSecretWithToken(token, app_id, key, val))
    {
        return 0;
    }
    return copyOutString(val, out_buf, out_buf_size);
}

int vv_set_secret_with_token(
    VoidVaultHandle* handle,
    const char* token,
    const char* app_id,
    const char* key,
    const char* value)
{
    if (handle == nullptr || token == nullptr || app_id == nullptr || key == nullptr || value == nullptr)
    {
        return 0;
    }
    return handle->broker.setSecretWithToken(token, app_id, key, value) ? 1 : 0;
}

int vv_derive_app_key(
    VoidVaultHandle* handle,
    const char* token,
    const char* app_id,
    uint64_t subkey_id,
    char* out_hex_buf,
    size_t out_hex_buf_size)
{
    if (handle == nullptr || token == nullptr || app_id == nullptr)
    {
        return 0;
    }
    std::string hex;
    if (!handle->broker.deriveAppKey(token, app_id, subkey_id, hex))
    {
        return 0;
    }
    return copyOutString(hex, out_hex_buf, out_hex_buf_size);
}

} // extern "C"
