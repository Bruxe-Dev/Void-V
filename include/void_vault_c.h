#ifndef VOID_VAULT_C_H
#define VOID_VAULT_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(VOID_VAULT_BUILD_SHARED)
#define VV_API __declspec(dllexport)
#else
#define VV_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle representing an embedded Void Vault + VaultBroker instance.
typedef struct VoidVaultHandle VoidVaultHandle;

// Opens a Void Vault instance bound to `auth_file_path` and `data_file_path`.
// Automatically attaches a hash-chained audit log at `<data_file_path>.audit.log`.
VV_API VoidVaultHandle* vv_open(const char* auth_file_path, const char* data_file_path);

// Opens a Void Vault instance with an explicit `audit_log_path` (or NULL to disable).
VV_API VoidVaultHandle* vv_open_with_audit(
    const char* auth_file_path,
    const char* data_file_path,
    const char* audit_log_path);

// Locks the vault, wipes all in-memory secrets, and frees the handle.
VV_API void vv_close(VoidVaultHandle* handle);

// Returns 1 if the account is initialized on disk, 0 otherwise.
VV_API int vv_is_initialized(const VoidVaultHandle* handle);

// Returns 1 if the vault is currently unlocked, 0 otherwise.
VV_API int vv_is_unlocked(const VoidVaultHandle* handle);

// First-time account setup. Returns 1 on success, 0 on failure.
VV_API int vv_setup_password(VoidVaultHandle* handle, const char* new_password);

// Authenticates and unlocks the vault. Returns 1 on success, 0 on failure.
VV_API int vv_unlock(VoidVaultHandle* handle, const char* password);

// Immediately locks the vault and wipes the in-memory session password.
VV_API void vv_lock(VoidVaultHandle* handle);

// Stores a named secret (requires unlocked vault). Returns 1 on success, 0 on failure.
VV_API int vv_set_secret(VoidVaultHandle* handle, const char* key, const char* value);

// Retrieves a named secret into `out_buf` (null-terminated).
// Returns 1 on success, 0 if not found, locked, or `out_buf_size` is too small.
VV_API int vv_get_secret(
    VoidVaultHandle* handle,
    const char* key,
    char* out_buf,
    size_t out_buf_size);

// Deletes a named secret. Returns 1 on success, 0 if not found or locked.
VV_API int vv_delete_secret(VoidVaultHandle* handle, const char* key);

// Writes comma-separated stored key names into `out_csv_buf`. Returns 1 on success.
VV_API int vv_list_keys(
    VoidVaultHandle* handle,
    char* out_csv_buf,
    size_t out_buf_size);

// Issues a "Sign in with Void Vault" scoped capability token (`VVTOK1...`).
// Returns 1 on success, 0 on failure.
VV_API int vv_issue_token(
    VoidVaultHandle* handle,
    const char* app_id,
    const char* scope,
    uint64_t ttl_seconds,
    char* out_token_buf,
    size_t out_token_buf_size);

// Verifies a capability token for `expected_app_id`. Returns 1 if valid, 0 if invalid/expired.
VV_API int vv_verify_token(
    VoidVaultHandle* handle,
    const char* token,
    const char* expected_app_id);

// Revokes all tokens issued for a specific `app_id` without affecting other apps.
VV_API int vv_revoke_app_tokens(VoidVaultHandle* handle, const char* app_id);

// Revokes all issued tokens across all applications immediately.
VV_API int vv_revoke_all_tokens(VoidVaultHandle* handle);

// Reads a scoped secret using a capability token (`VVTOK1...`).
// Returns 1 on success, 0 if token is invalid/expired or scope denies access.
VV_API int vv_get_secret_with_token(
    VoidVaultHandle* handle,
    const char* token,
    const char* app_id,
    const char* key,
    char* out_buf,
    size_t out_buf_size);

// Writes a scoped secret using a capability token (`VVTOK1...`).
// Returns 1 on success, 0 if token is invalid/expired or scope denies access.
VV_API int vv_set_secret_with_token(
    VoidVaultHandle* handle,
    const char* token,
    const char* app_id,
    const char* key,
    const char* value);

// Derives an isolated 32-byte (64-hex-char) app subkey using a capability token.
// `out_hex_buf_size` must be at least 65 bytes. Returns 1 on success, 0 on failure.
VV_API int vv_derive_app_key(
    VoidVaultHandle* handle,
    const char* token,
    const char* app_id,
    uint64_t subkey_id,
    char* out_hex_buf,
    size_t out_hex_buf_size);

// Generates a one-time Emergency Recovery Key ("VVREC-XXXX-...").
// `out_key_buf_size` must be at least 46 bytes. Returns 1 on success, 0 on failure.
VV_API int vv_generate_recovery_key(
    VoidVaultHandle* handle,
    char* out_key_buf,
    size_t out_key_buf_size);

// Recovers the vault using an Emergency Recovery Key and sets `new_password`.
// Returns 1 on success, 0 on failure.
VV_API int vv_recover_with_emergency_key(
    VoidVaultHandle* handle,
    const char* recovery_key,
    const char* new_password);

// Verifies the BLAKE2b hash chain of an audit log file.
// Returns 1 if intact, 0 if tampered.
VV_API int vv_verify_audit_log(
    const char* audit_log_path,
    size_t* out_entry_count,
    size_t* out_failed_line);

#ifdef __cplusplus
}
#endif

#endif
