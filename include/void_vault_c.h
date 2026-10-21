#ifndef VOID_VAULT_C_H
#define VOID_VAULT_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle representing an embedded Void Vault + VaultBroker instance.
typedef struct VoidVaultHandle VoidVaultHandle;

// Opens a Void Vault instance bound to `auth_file_path` and `data_file_path`.
// Returns NULL on allocation failure.
VoidVaultHandle* vv_open(const char* auth_file_path, const char* data_file_path);

// Locks the vault, wipes all in-memory secrets, and frees the handle.
void vv_close(VoidVaultHandle* handle);

// Returns 1 if the account is initialized on disk, 0 otherwise.
int vv_is_initialized(const VoidVaultHandle* handle);

// Returns 1 if the vault is currently unlocked, 0 otherwise.
int vv_is_unlocked(const VoidVaultHandle* handle);

// First-time account setup. Returns 1 on success, 0 on failure.
int vv_setup_password(VoidVaultHandle* handle, const char* new_password);

// Authenticates and unlocks the vault. Returns 1 on success, 0 on failure.
int vv_unlock(VoidVaultHandle* handle, const char* password);

// Immediately locks the vault and wipes the in-memory session password.
void vv_lock(VoidVaultHandle* handle);

// Stores a named secret (requires unlocked vault). Returns 1 on success, 0 on failure.
int vv_set_secret(VoidVaultHandle* handle, const char* key, const char* value);

// Retrieves a named secret into `out_buf` (null-terminated).
// Returns 1 on success, 0 if not found, locked, or `out_buf_size` is too small.
int vv_get_secret(
    VoidVaultHandle* handle,
    const char* key,
    char* out_buf,
    size_t out_buf_size);

// Issues a "Sign in with Void Vault" scoped capability token (`VVTOK1...`).
// Returns 1 on success, 0 on failure.
int vv_issue_token(
    VoidVaultHandle* handle,
    const char* app_id,
    const char* scope,
    uint64_t ttl_seconds,
    char* out_token_buf,
    size_t out_token_buf_size);

// Verifies a capability token for `expected_app_id`. Returns 1 if valid, 0 if invalid/expired.
int vv_verify_token(
    VoidVaultHandle* handle,
    const char* token,
    const char* expected_app_id);

// Reads a scoped secret using a capability token (`VVTOK1...`).
// Returns 1 on success, 0 if token is invalid/expired or scope denies access.
int vv_get_secret_with_token(
    VoidVaultHandle* handle,
    const char* token,
    const char* app_id,
    const char* key,
    char* out_buf,
    size_t out_buf_size);

// Writes a scoped secret using a capability token (`VVTOK1...`).
// Returns 1 on success, 0 if token is invalid/expired or scope denies access.
int vv_set_secret_with_token(
    VoidVaultHandle* handle,
    const char* token,
    const char* app_id,
    const char* key,
    const char* value);

// Derives an isolated 32-byte (64-hex-char) app subkey using a capability token.
// `out_hex_buf_size` must be at least 65 bytes. Returns 1 on success, 0 on failure.
int vv_derive_app_key(
    VoidVaultHandle* handle,
    const char* token,
    const char* app_id,
    uint64_t subkey_id,
    char* out_hex_buf,
    size_t out_hex_buf_size);

#ifdef __cplusplus
}
#endif

#endif
