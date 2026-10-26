# Void Vault v2.0 — Developer & Integration Guide

This guide explains how software developers can embed **Void Vault v2.0** into their own applications (fintech/banking systems, desktop apps, trading platforms, AI agents, CLI tools, healthcare systems, and microservices) so that:

1. **Users own their sensitive credentials and PII locally** inside an Argon2id + XChaCha20-Poly1305 AEAD container (`vault_data.dat`).
2. **Developers integrate in 3 lines of code** using the high-level **`VaultApp` Developer Abstraction Layer** — without ever managing pipes, hex encoding, file paths, or manual vault locking.
3. **Your application modules never need to store or handle the user's master password**, using **"Sign in with Void Vault"** scoped capability tokens (`VVTOK1`) and zero-knowledge derived app subkeys.
4. **Every security operation is recorded in a tamper-evident BLAKE2b-256 hash-chained audit log (`VVAUDIT1`)**, and locked-out or forgotten-password accounts can be recovered without data loss via **One-Time Emergency Recovery Keys (`VVREC-...`)**.

---

## Table of Contents

1. [Fastest Integration: High-Level Developer Abstraction (`VaultApp`)](#1-fastest-integration-high-level-developer-abstraction-vaultapp)
2. [Core Architecture: How "Sign in with Void Vault" Works](#2-core-architecture-how-sign-in-with-void-vault-works)
3. [Capability Token Scopes Reference](#3-capability-token-scopes-reference)
4. [Emergency Recovery Keys & Tamper-Evident Audit Logs](#4-emergency-recovery-keys--tamper-evident-audit-logs)
5. [Low-Level Option A: Native In-Memory DLL Bridge (`VoidVaultNativeClient`)](#5-low-level-option-a-native-in-memory-dll-bridge-voidvaultnativeclient)
6. [Low-Level Option B: Language-Agnostic `--broker` IPC Protocol (Node.js, Go, Rust, C#)](#6-low-level-option-b-language-agnostic---broker-ipc-protocol-nodejs-go-rust-c)
7. [Transit Encryption, PKI, and Auto-Unseal](#7-transit-encryption-pki-and-auto-unseal)
8. [Low-Level Option C: Universal C ABI v2 (`include/void_vault_c.h` & `void_vault.dll`)](#8-low-level-option-c-universal-c-abi-v2-includevoid_vault_ch--void_vaultdll)
9. [Low-Level Option D: Native C++20 Library (`VaultBroker`)](#9-low-level-option-d-native-c20-library-vaultbroker)

---

## 1. Fastest Integration: High-Level Developer Abstraction (`VaultApp`)

With **Void Vault v2.0**, you do **not** need to spawn subprocesses, hex-encode strings, check if an account is initialized, or remember to lock the vault on exceptions.

Drop `void_vault.dll` (or `void_vault.exe`) and `sdk/python/void_vault.py` into your project (or run `pip install ./sdk/python`), and use `VaultApp`:

### 3-Line Banking / Fintech Integration Example

```python
from void_vault import VaultApp, ScopedSession

# 1. Define your application identity and default capability scope once
vault = VaultApp(app_id="acme-banking", scope="*", vault_root="./user_vaults")

# 2. Open a context-managed session for any user (auto-initializes on first use,
#    unlocks in sodium_malloc RAM, and issues a short-lived VVTOK1 token)
with vault.session(user_id="customer_1042", passphrase=user_pin) as secrets:
    # Dictionary-style encrypted read/write
    secrets["card.pan"] = "4532-0151-9982-8891"
    secrets["card.expiry"] = "08/29"

    # Optional prefix namespacing: card["pan"] -> "card.pan"
    card = secrets.namespace("card.")
    print("Masked PAN:", f"****-****-****-{card['pan'][-4:]}")

    # Zero-knowledge 256-bit (32-byte) key derivation for your app's own local DB
    user_db_key: bytes = secrets.derive_key(subkey_id=1)

# 3. The instant the `with` block exits (even if an exception occurs),
#    Void Vault automatically locks the vault and wipes the key in RAM!
```

### Enforcing Least-Privilege Scopes with `@VaultApp.require_scope`

```python
@VaultApp.require_scope("read:card.*")
def charge_customer_card(session: ScopedSession, amount_usd: float) -> None:
    pan = session["card.pan"]
    # Process payment in memory without ever persisting `pan` to your database...
```

---

## 2. Core Architecture: How "Sign in with Void Vault" Works

```mermaid
sequenceDiagram
    participant User as End User
    participant App as Developer's App (VaultApp SDK)
    participant Vault as Void Vault Core (void_vault.dll / --broker)

    User->>App: 1. Enters Passphrase / PIN at Checkout or Login
    App->>Vault: 2. with vault.session(user_id, passphrase)
    Note over Vault: Passphrase verified via Argon2id & held only in sodium_malloc RAM
    Vault-->>App: 3. Issues HMAC-SHA512256 Token (VVTOK1.<payload>.<mac>)
    App->>Vault: 4. secrets["card.pan"] / secrets.derive_key(1)
    Note over Vault: Verifies token MAC, TTL, app_id & scope; appends to VVAUDIT1 hash chain
    Vault-->>App: 5. Returns decrypted secret / 256-bit derived key
    App->>Vault: 6. Exiting `with` block -> automatic lock & sodium_memzero wipe
```

- **Encrypted Multi-Secret Container (`VVKV1`):** All named secrets (`key -> value`) are packed together and encrypted as a single XChaCha20-Poly1305 AEAD ciphertext. Key names and secret counts are never visible on disk.
- **Scoped Capability Tokens (`VVTOK1`):** Signed with a vault-internal 256-bit key via `HMAC-SHA512256`. Bound to a specific `app_id`, `scope`, per-app generation counter, and expiration timestamp (`expires_at`).
- **Per-App Token Revocation (`revoke_app_tokens`):** Revoke all tokens issued to a single `app_id` immediately without invalidating tokens belonging to other apps.
- **Zero-Knowledge App Subkeys (`derive_key`):** Uses `libsodium`'s BLAKE2b KDF (`crypto_kdf_derive_from_key`) to derive deterministic 256-bit keys isolated per `app_id` and `subkey_id`.

---

## 3. Capability Token Scopes Reference

| Scope String | Read Permission | Write Permission | Typical Use Case |
|---|---|---|---|
| `auth:only` | None | None | Identity verification ("Sign in") + `derive_key` only |
| `read_key:<exact_key>` | Only `<exact_key>` | None | Module only needs to read a single credential (e.g. `read_key:card.pan`) |
| `key:<exact_key>` | Only `<exact_key>` | Only `<exact_key>` | Module manages a single secret (e.g. `key:oauth.refresh_token`) |
| `read:<prefix>*` | Keys starting with `<prefix>` | None | Read-only access to an app's namespace (e.g. `read:card.*`) |
| `write:<prefix>*` | Keys starting with `<prefix>` | Keys starting with `<prefix>` | Full read/write access within an app's namespace (e.g. `write:card.*`) |
| `read:*` | All keys | None | Backup / audit reader |
| `*` | All keys | All keys | Full administrative session |

---

## 4. Emergency Recovery Keys & Tamper-Evident Audit Logs

### One-Time Emergency Recovery Key (`VVREC-...`)
If a user forgets their master passphrase or triggers the 5-attempt brute-force lockout, they can recover their vault without losing any encrypted data using a pre-generated 256-bit **Emergency Recovery Key**:

```python
# Generate a one-time recovery key while the vault is unlocked (show once to user):
with vault.session(user_id="customer_1042", passphrase=current_pin) as secrets:
    recovery_key = secrets.generate_recovery_key()
    # Example format: VVREC-8F3A-91C0-44B2-7E1D-09A5-C3E8-55B1-2D90

# Recover a locked-out or forgotten-passphrase vault and re-encrypt under a new PIN:
vault.recover_account(
    recovery_key=recovery_key,
    new_passphrase=new_pin,
    user_id="customer_1042",
)
```

### Tamper-Evident Hash-Chained Audit Log (`VVAUDIT1`)
Every authentication attempt, unlock, lock, secret read/write, token issuance, token revocation, and password rotation is appended to `vault_audit.log` using a **BLAKE2b-256 cryptographic hash chain**:
- Each entry's hash commits to the previous entry's 256-bit hash (`prev_hash_hex`), sequence number, timestamp, event type, actor, and target key.
- Deleting, modifying, inserting, or reordering any line breaks the chain.
- Verify via Python (`vault.verify_audit_log(user_id=...)`) or via CLI (`void_vault.exe --data-dir <dir> --verify-audit`).

---

## 5. Low-Level Option A: Native In-Memory DLL Bridge (`VoidVaultNativeClient`)

When `void_vault.dll` (Windows) or `libvoid_vault.so` (Linux) is present, `VaultApp` automatically uses `VoidVaultNativeClient` (`ctypes`) for zero-subprocess, in-memory execution. You can also use `VoidVaultNativeClient` directly:

```python
from void_vault import VoidVaultNativeClient

with VoidVaultNativeClient("void_vault.dll", data_dir="./vault_data") as client:
    if not client.is_initialized():
        client.setup_account("MasterPassphrase#2026!")
    client.unlock("MasterPassphrase#2026!")
    client.set_secret("api.secret", "super-secret-value")
    token = client.issue_token("my-service", "read:api.*", ttl_seconds=300)
    print(client.get_secret_with_token(token, "my-service", "api.secret"))
    print("Audit entries verified:", client.verify_audit())
```

---

## 6. Low-Level Option B: Language-Agnostic `--broker` IPC Protocol (Node.js, Go, Rust, C#)

Any language that can spawn a child process can integrate with Void Vault by launching:

```bash
void_vault --data-dir <path> --kdf interactive --idle-timeout 300 --broker
```

### Wire Protocol Specification (Line-Delimited Stdin / Stdout)

All secret values and passwords on the wire are **lowercase hex-encoded** so binary payloads and special characters never break line framing.

| Request Line Sent to `stdin` | Success Response on `stdout` | Description |
|---|---|---|
| `SETUP <password_hex>` | `OK initialized` | First-time account setup |
| `UNLOCK <password_hex>` | `OK unlocked` | Authenticates and unlocks the vault in RAM |
| `LOCK` | `OK locked` | Wipes the session password in RAM and locks the vault |
| `SET_SECRET <key> <value_hex>` | `OK saved` | Stores or updates `<key>` inside the encrypted `VVKV1` container |
| `GET_SECRET <key>` | `OK <value_hex>` | Retrieves and hex-encodes the value of `<key>` |
| `DELETE_SECRET <key>` | `OK deleted` | Removes `<key>` from the encrypted container |
| `SET_EPHEMERAL_SECRET <key> <ttl_sec> <value_hex>` | `OK saved` | Stores a value in broker memory only; maximum TTL is 24 hours |
| `GET_EPHEMERAL_SECRET <key>` | `OK <value_hex>` | Reads the value only while the vault is unlocked and before its TTL expires |
| `DELETE_EPHEMERAL_SECRET <key>` | `OK deleted` | Wipes and removes an in-memory-only value |
| `TRANSIT_ENCRYPT <token> <app_id> <key_id> <plaintext_hex>` | `OK <ciphertext_hex>` | Encrypts bytes inside the broker; token scope must allow `transit:encrypt` |
| `TRANSIT_DECRYPT <token> <app_id> <key_id> <ciphertext_hex>` | `OK <plaintext_hex>` | Decrypts bytes inside the broker; token scope must allow `transit:decrypt` |
| `PKI_CREATE_CA <authority_id> <common_name_hex>` | `OK <certificate_hex>` | Creates a self-signed Ed25519 CA; private material is kept in encrypted vault storage |
| `PKI_ISSUE_CERTIFICATE <authority_id> <validity_days> <common_name_hex>` | `OK <certificate_hex>` | Issues a leaf certificate using the selected CA |
| `LIST_KEYS` | `OK key1,key2,...` | Lists all user key names |
| `ISSUE_TOKEN <app_id> <scope> <ttl_sec>` | `OK VVTOK1.<payload>.<mac>` | Issues a signed capability token |
| `VERIFY_TOKEN <token> <app_id>` | `OK <scope> <expires_unix>` | Verifies token HMAC, TTL, and `app_id` |
| `TOKEN_GET_SECRET <token> <app_id> <key>` | `OK <value_hex>` | Reads `<key>` if `<token>` is valid and scope permits read |
| `TOKEN_SET_SECRET <token> <app_id> <key> <val_hex>` | `OK saved` | Writes `<key>` if `<token>` is valid and scope permits write |
| `DERIVE_APP_KEY <token> <app_id> <subkey_id>` | `OK <64_char_hex_key>` | Derives an isolated 32-byte key for `<app_id>` + `<subkey_id>` |
| `REVOKE_APP_TOKENS <app_id>` | `OK revoked_app` | Invalidates all tokens for `<app_id>` immediately |
| `REVOKE_TOKENS` | `OK revoked` | Rotates the internal signing key, invalidating all tokens |
| `GENERATE_RECOVERY_KEY` | `OK VVREC-...` | Generates a one-time Emergency Recovery Key |
| `RECOVER_WITH_KEY <rec_hex> <new_pw_hex>` | `OK recovered` | Recovers vault using Emergency Recovery Key and sets new password |
| `VERIFY_AUDIT` | `OK <entry_count>` | Verifies the BLAKE2b-256 hash chain of `vault_audit.log` |
| `QUIT` | `OK bye` | Locks the vault, wipes memory, and exits `0` |

Ephemeral values are not included in `VVKV1`, are wiped when the vault locks or the
broker process exits, and are purged after expiry. A read rejects an expired value
even if the background cleanup has not run yet. A value returned to a caller is
copied into caller memory; the broker cannot wipe that copy later.

---

## 7. Transit Encryption, PKI, and Auto-Unseal

### Transit mode

Transit operations require a running `--broker` process. The payload and
ciphertext are sent over its standard-input/output IPC channel; the caller
does not load the Transit master key. Transit keys are separate from the token
signing key, and each ciphertext is bound to its `key_id`. Issue narrowly scoped
tokens such as `transit:encrypt` or `transit:decrypt` rather than `*`.

For the Python high-level API, select the broker explicitly because the default
native DLL backend is in-process:

```python
from void_vault import VaultApp

vault = VaultApp(
    app_id="payments-worker",
    scope="transit:encrypt",
    vault_root="./user_vaults",
    prefer_native_dll=False,
)
with vault.session(user_id="customer-1042", passphrase=passphrase) as session:
    ciphertext = session.transit_encrypt("payments-v1", b"payload")
```

The IPC and C ABI Transit interface accepts byte strings and returns
ciphertext/plaintext bytes. Payloads are limited to 16 KiB. Ciphertext is
authenticated; decryption fails if it is modified or presented with a
different `key_id`. The broker cannot prevent a caller from copying plaintext
or keys it receives back through other APIs.

### PKI mode

The broker can create self-signed Ed25519 certificate authorities and issue
leaf certificates. The CA private key bundle is stored in encrypted `VVKV1`
storage, not returned by the API. The CA validity is fixed at 10 years, and
leaf certificate validity is limited to 825 days. The C++ operation engine and
Python `VoidVaultClient` expose the PKI operations; the current C ABI exports
daemon Transit operations but does not yet expose PKI calls.

### OS-backed auto-unseal

Auto-unseal is opt-in and should only be enabled for a trusted, local,
single-user background service. `ENABLE_AUTO_UNSEAL` creates a random fragment
protected by the current OS user and stores an authenticated encrypted password
envelope beside the vault data file. Start the broker with `--auto-unseal` to
attempt an unlock at startup. The Windows implementation uses current-user
DPAPI; Linux uses the current user's kernel keyring. Other operating systems
currently report that auto-unseal is unavailable.

This feature is a convenience, not a defense against malware, an administrator,
or another process running as the same OS user: that user context can generally
access the protected fragment and the vault files. Keep the vault directory
private, and do not enable auto-unseal for a shared or remotely accessible
account. Disable it with `DISABLE_AUTO_UNSEAL` before moving a vault or
transferring it to another machine/user.

---

## 8. Low-Level Option C: Universal C ABI v2 (`include/void_vault_c.h` & `void_vault.dll`)

For C, Rust (`bindgen`), Go (`cgo`), C# (`P/Invoke`), or Python (`ctypes`), link against `void_vault.dll` / `libvoid_vault_core.a` and include [`include/void_vault_c.h`](include/void_vault_c.h):

```c
#include "void_vault_c.h"
#include <stdio.h>

int main(void) {
    VoidVaultHandle* v = vv_open("vault_auth.dat", "vault_data.dat");
    if (!vv_is_initialized(v)) {
        vv_setup_password(v, "MyMasterPassword123!");
    }
    if (vv_unlock(v, "MyMasterPassword123!")) {
        vv_set_secret(v, "app.api_key", "sk-live-998877");

        char token[512];
        if (vv_issue_token(v, "my-c-app", "read:app.*", 300, token, sizeof(token))) {
            char secret[256];
            if (vv_get_secret_with_token(v, token, "my-c-app", "app.api_key", secret, sizeof(secret))) {
                printf("Retrieved scoped secret successfully!\n");
            }
        }
        vv_lock(v);
    }
    vv_close(v);
    return 0;
}
```

---

For Transit calls that must keep the master key out of the caller process, use
the separate-process API in the same header: `vv_daemon_client_open`,
`vv_daemon_client_issue_token`, `vv_daemon_transit_encrypt`, and
`vv_daemon_transit_decrypt`. Do not use `VoidVaultHandle`/`vv_open` for that
trust boundary because those embedded APIs run the vault core inside the
calling process. The daemon C API accepts raw byte payloads, uses the local
`void_vault --broker` process, and returns ciphertext/plaintext through caller
buffers.

## 9. Low-Level Option D: Native C++20 Library (`VaultBroker`)

In CMake projects, link against `void_vault_core` and include `src/vault/broker.hpp`:

```cpp
#include "security/audit_log.hpp"
#include "security/auth.hpp"
#include "storage.hpp"
#include "vault/vault.hpp"
#include "vault/broker.hpp"

Authorizer auth("vault_auth.dat");
Storage storage("vault_data.dat");
AuditLog audit("vault_audit.log");
Vault vault(auth, storage);
vault.setAuditLog(&audit);
VaultBroker broker(vault);
```
