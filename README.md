# Void Vault v2.0

**Void Vault** is a hardened, production-grade C++20 encrypted local secret vault, capability broker, and developer SDK powered by **libsodium**.

It provides defense-in-depth local secret protection with **Argon2id (v1.3)** key derivation, **XChaCha20-Poly1305 IETF AEAD** encryption with header authentication (AAD), **BLAKE2b-256 hash-chained tamper-evident audit logs (`VVAUDIT1`)**, **One-Time Emergency Recovery Keys (`VVREC-...`)**, persistent fail-closed lockout protection, `sodium_malloc`-guarded memory handling, OS-level owner-only ACLs, and a **3-line Developer Abstraction SDK (`VaultApp`)**.

---

## Key Security & Production Features (v2.0)

- **3-Line Developer Abstraction SDK (`VaultApp` & `ScopedSession`)**
  - Embed zero-knowledge user vaults into any Python application in 3 lines of code with `with vault.session(user_id=..., passphrase=...) as secrets:`.
  - Automatically discovers `void_vault.dll` (zero-subprocess `ctypes` C-ABI mode) or `void_vault.exe` (`--broker` IPC mode), isolates per-user directories, mints short-lived capability tokens (`VVTOK1`), and **automatically locks & wipes RAM** the instant the `with` block exits.
- **Tamper-Evident Cryptographic Audit Log (`VVAUDIT1` — BLAKE2b-256)**
  - Every authentication attempt, unlock, lock, secret access, token issuance/revocation, and recovery event is recorded in `vault_audit.log` using a cryptographic BLAKE2b-256 hash chain.
  - Modifying, deleting, or reordering any log line breaks the hash chain and is immediately detected by `void_vault --verify-audit` or `vault.verify_audit_log()`.
- **One-Time Emergency Recovery Key (`VVREC-XXXX-...`)**
  - Generates a 256-bit offline recovery key (`VVREC-...`) stored in an AEAD-encrypted recovery capsule (`vault_data.dat.recovery`).
  - Allows recovering from both a 5-attempt lockout **and** a forgotten master password while preserving and re-encrypting all stored secrets, then atomically consumes the one-time capsule.
- **Per-App Capability Token Revocation & Inactivity Auto-Lock**
  - Issue scoped `HMAC-SHA512256` tokens (`VVTOK1`) bound to a specific `app_id`, `scope`, and TTL.
  - Revoke tokens for a single compromised application (`revokeAppTokens(app_id)`) without disrupting other applications, or revoke all tokens globally (`revokeAllTokens()`).
  - Configurable inactivity auto-lock (`--idle-timeout <seconds>`).
- **In-Memory Ephemeral Secrets**
  - Store separate TTL-bound values in broker memory without writing them to `VVKV1`; reads reject expired values and a cleanup worker wipes expired entries.
  - Ephemeral values disappear when the broker exits. Callers that read a value receive their own copy, which the broker cannot erase.
- **Modular Broker Engines**
  - A shared operation-engine interface routes key-value, Transit, and PKI operations to separate implementations.
- **Daemon-Backed Transit Encryption**
  - A separate-process C ABI client sends plaintext bytes to `void_vault --broker` and receives ciphertext without loading the Transit master key into caller memory.
  - Transit operations use scoped `transit:encrypt` / `transit:decrypt` tokens and a dedicated cryptographic key.
- **PKI Certificate Authority**
  - Creates Ed25519 authorities and issues leaf certificates; private CA material remains in encrypted vault storage.
- **Opt-In OS-Backed Auto-Unseal**
  - Protects a local unseal fragment using current-user Windows DPAPI or the Linux user keyring, enabling a trusted local broker to attempt unlock at startup.
  - This is a local convenience and does not protect against another process running as the same OS user.
- **XChaCha20-Poly1305 IETF Authenticated Encryption (`VV02` / `VV2M` / `VV2S`)**
  - Derives a 256-bit key from the user's passphrase and a fresh 128-bit random salt per save using `crypto_pwhash` (`Argon2id v1.3`).
  - Encrypts with a fresh 192-bit (24-byte) random nonce and authenticates the entire 44-byte header (`magic || salt || nonce`) as Additional Authenticated Data (AAD).
- **Zero `std::cin` / `std::string` Secret Buffering (`SecureBuffer`)**
  - Reads interactive passwords (with `*` visual feedback on Windows consoles) and secret lines byte-by-byte directly from the OS input handle into `sodium_malloc`-backed memory.
- **Hardened Filesystem & Process Isolation**
  - Atomic write-temp-flush-rename (`MoveFileExW` / `fsync` + `rename`), Windows current-user SID DACLs (`0600` on POSIX), symlink/junction rejection, cross-process `FileLock`, and crash-dump suppression (`hardenProcess`).

---

## Repository Structure

```text
void-vault/
├── CMakeLists.txt                  # Root CMake config (builds void_vault.exe, void_vault.dll, and tests)
├── include/
│   ├── storage.hpp                 # Storage & cross-process FileLock interface
│   └── void_vault_c.h              # Universal C ABI v2 header (DLL export / FFI / ctypes / Rust / Go / C#)
├── src/
│   ├── main.cpp                    # Hardened interactive CLI & --broker IPC server
│   ├── security/
│   │   ├── audit_log.hpp / .cpp    # Tamper-evident BLAKE2b-256 hash-chained audit log (VVAUDIT1)
│   │   ├── auth.hpp / auth.cpp     # Authorizer (VVAUTH1 persistence, lockout, password quality & rotation)
│   │   ├── encryption.hpp / .cpp   # Encryption (Argon2id + XChaCha20-Poly1305 AEAD + VV01 compatibility)
│   │   ├── process_hardening.hpp   # OS crash-dump / core-dump / ptrace mitigations
│   │   ├── auto_unseal.cpp         # Windows DPAPI / Linux user-keyring fragment protection
│   │   └── secure_buffer.hpp       # sodium_malloc RAII buffer with constant-time comparison
│   ├── storage/
│   │   └── storage.cpp             # Atomic writes, owner-only ACLs, symlink checks, FileLock
│   └── vault/
│       ├── vault.hpp / vault.cpp   # Vault state machine, password rotation & Emergency Recovery Keys
│       ├── broker.hpp / broker.cpp # VVKV1 store, ephemeral TTL secrets & capability broker
│       ├── operation_engine.hpp    # Common engine interface and operation router
│       ├── transit_engine.cpp      # Transit authenticated encryption
│       ├── pki_engine.cpp          # Ed25519 CA and leaf-certificate operations
│       └── void_vault_c.cpp        # Universal C ABI v2 implementation (void_vault.dll)
├── sdk/
│   └── python/
│       ├── void_vault.py           # VaultApp 3-line abstraction + Native ctypes DLL & IPC clients
│       └── pyproject.toml          # Standard pip packaging metadata
├── tests/
│   ├── CMakeLists.txt              # CTest target definitions
│   ├── storage_test.cpp            # Atomic I/O, FileLock, ACLs, and size-limit tests
│   ├── auth_test.cpp               # Persistence, lockout, corruption, quality, and rotation tests
│   ├── encryption_test.cpp         # AEAD tamper/downgrade, KDF profile, VV01, and SecureBuffer tests
│   ├── vault_test.cpp              # Vault lifecycle, AuditLog tamper detection, IdleTimeout & Recovery Key tests
│   ├── broker_test.cpp             # VVKV1 store, VVTOK1 scopes, per-app revocation & C ABI v2 tests
│   └── app_e2e_test.cmake          # Multi-process CLI integration test
├── scripts/
│   ├── build.ps1                   # Windows MSYS2 UCRT64 build & CTest automation script
│   └── package_release.ps1         # Separate release bundler (Full Release zip + Developer SDK zip + SHA256SUMS)
├── DEVELOPER_GUIDE.md              # Step-by-step developer integration & VaultApp abstraction guide
├── SECURITY.md                     # Threat model, cryptographic design & disclosure policy
└── LICENSE                         # MIT License
```

---

## 3-Line Developer Quickstart (`VaultApp`)

```python
from void_vault import VaultApp

vault = VaultApp(app_id="acme-banking", scope="*", vault_root="./user_vaults")

with vault.session(user_id="customer_1042", passphrase=user_pin) as secrets:
    secrets["card.pan"] = "4532-0151-9982-8891"
    print("Masked Card:", f"****-****-****-{secrets['card.pan'][-4:]}")
    app_db_key: bytes = secrets.derive_key(subkey_id=1)
# Automatically locked & wiped in RAM when exiting the `with` block!
```

See [**DEVELOPER_GUIDE.md**](DEVELOPER_GUIDE.md) for `VaultApp`, capability scopes, daemon-backed Transit, PKI operations, auto-unseal, the C ABI, and the `--broker` IPC protocol.

---

## Building & Running Tests

```powershell
# Release build + full CTest suite
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -BuildType Release -BuildDir build

# Debug build + full CTest suite
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -BuildType Debug -BuildDir build-debug

# Package separate v2.0.0 release archives in dist/
powershell -ExecutionPolicy Bypass -File scripts\package_release.ps1 -Version 2.0.0
```

---

## Running Void Vault CLI

```powershell
# Interactive console with 5-minute inactivity auto-lock
.\build\void_vault.exe --idle-timeout 300

# Verify tamper-evident BLAKE2b-256 audit log chain
.\build\void_vault.exe --verify-audit
```

### Interactive Menu Options (`1` – `10`)

1. **`[1] Unlock Vault`**: Authenticates your password (masked with `*`) and unlocks the session.
2. **`[2] Save Quick Text Note`**: Encrypts and saves a text note.
3. **`[3] View All Stored Data`**: Decrypts and displays stored secrets.
4. **`[4] Lock Vault`**: Immediately wipes the in-memory session password and locks the vault.
5. **`[5] Check Vault Status`**: Displays lock state, failed attempts (`n/5`), data file status, and live audit log integrity.
6. **`[6] Quit (Lock & Exit)`**: Wipes session secrets and exits cleanly (`0`).
7. **`[7] Change Master Password`**: Atomically rotates the master password and re-encrypts `vault_data.dat`.
8. **`[8] Manage Named Secrets (Key-Value)`**: Create, view, list, or delete named secrets inside the encrypted `VVKV1` store.
9. **`[9] Generate / Revoke App Tokens`**: Issue scoped `VVTOK1` tokens for applications or revoke tokens per-app / globally.
10. **`[10] Emergency Recovery & Audit Log`**: Generate a One-Time Emergency Recovery Key (`VVREC-...`), recover a locked/forgotten account, or verify the `vault_audit.log` hash chain.

---

## License

Released under the [MIT License](LICENSE). See [SECURITY.md](SECURITY.md) for the full threat model and vulnerability reporting instructions.
