# Void Vault

**Void Vault** is a hardened, open-source C++20 encrypted local storage and credential-protection utility powered by **libsodium**.

It provides defense-in-depth local secret protection with **Argon2id (v1.3)** key derivation, **XChaCha20-Poly1305 IETF AEAD** encryption with header authentication (AAD), persistent fail-closed lockout protection, `sodium_malloc`-guarded memory handling, OS-level owner-only ACLs, and cross-process file locking.

---

## Key Security Features

- **XChaCha20-Poly1305 IETF Authenticated Encryption (`VV02` / `VV2M` / `VV2S`)**
  - Derives a 256-bit key from the user's passphrase and a fresh 128-bit random salt per save using `crypto_pwhash` (`Argon2id v1.3`).
  - Encrypts with a fresh 192-bit (24-byte) random nonce and authenticates the entire 44-byte header (`magic || salt || nonce`) as Additional Authenticated Data (AAD), preventing header tampering and KDF downgrade attacks.
  - Maintains transparent backward-compatible decryption for legacy `VV01` (`XSalsa20-Poly1305`) records.
- **Configurable Argon2id KDF Work Factors (`--kdf`)**
  - `interactive` (`VV02`, default): 64 MiB RAM, 2 iterations.
  - `moderate` (`VV2M`): 256 MiB RAM, 3 iterations.
  - `sensitive` (`VV2S`): 1 GiB RAM, 4 iterations.
- **Persistent Pre-Verification Lockout (`VVAUTH1`)**
  - Stores only the Argon2id hash string and a failure counter (`failed=<n>`) in `vault_auth.dat`.
  - Persists the incremented failure counter to disk **before** verifying each password attempt, so terminating the process mid-check cannot bypass the 5-attempt limit.
  - Fails closed on any missing, empty, or malformed authentication record—a corrupted `vault_auth.dat` never silently resets into a new account.
- **Zero `std::cin` / `std::string` Secret Buffering (`SecureBuffer`)**
  - Reads interactive passwords and secret lines byte-by-byte directly from the OS input handle (`ReadFile` / `read`) into `sodium_malloc`-backed memory (guard pages, `VirtualLock`/`mlock`, automatic `sodium_memzero` on release).
  - Locks derived 256-bit encryption keys with `sodium_mlock` and compares secrets in constant time with `sodium_memcmp`.
- **Atomic Password Rotation (`changePassword`)**
  - Verifies the current password in constant time, enforces password quality rules (minimum 12 printable characters, non-repeating entropy, no control bytes), re-encrypts `vault_data.dat` under the new key, and atomically updates `vault_auth.dat` with automatic rollback on I/O failure.
- **Hardened Filesystem & Process Isolation**
  - **Atomic Writes:** Writes to `<file>.tmp`, flushes hardware buffers (`FlushFileBuffers` / `fsync`), and commits atomically (`MoveFileExW` with `MOVEFILE_WRITE_THROUGH` / `rename`).
  - **Owner-Only Permissions:** Restricts file DACLs to the current user SID on Windows (`SetNamedSecurityInfoW` with `PROTECTED_DACL_SECURITY_INFORMATION`) and `0600` on POSIX.
  - **Symlink & Reparse-Point Rejection:** Rejects symbolic links and Windows junctions/reparse points on all read, write, and lock paths.
  - **Cross-Process Exclusive Locks (`FileLock`):** Prevents concurrent `void_vault` processes from racing on the same `--data-dir` or corrupting files.
  - **Process Crash-Dump Suppression (`hardenProcess`):** Suppresses Windows Error Reporting crash dumps and POSIX core dumps (`RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0`) at startup.

---

## Repository Structure

```text
void-vault/
├── CMakeLists.txt                  # Root CMake configuration (C++20, static runtime option, hardening flags)
├── include/
│   └── storage.hpp                 # Storage & cross-process FileLock interface
├── src/
│   ├── main.cpp                    # Hardened interactive CLI entry point
│   ├── security/
│   │   ├── auth.hpp / auth.cpp     # Authorizer (VVAUTH1 persistence, lockout, password quality & rotation)
│   │   ├── encryption.hpp / .cpp   # Encryption (Argon2id + XChaCha20-Poly1305 AEAD + VV01 compatibility)
│   │   ├── process_hardening.hpp   # OS crash-dump / core-dump / ptrace mitigations
│   │   └── secure_buffer.hpp       # sodium_malloc RAII buffer with constant-time comparison
│   ├── storage/
│   │   └── storage.cpp             # Atomic writes, owner-only ACLs, symlink checks, FileLock
│   └── vault/
│       └── vault.hpp / vault.cpp   # High-level Vault state machine & atomic password rotation
├── tests/
│   ├── CMakeLists.txt              # CTest target definitions
│   ├── test_util.hpp               # Assertion-free test runner & RAII TempDir
│   ├── storage_test.cpp            # Atomic I/O, FileLock, ACLs, and size-limit tests
│   ├── auth_test.cpp               # Persistence, lockout, corruption, quality, and rotation tests
│   ├── encryption_test.cpp         # AEAD tamper/downgrade, KDF profile, VV01, and SecureBuffer tests
│   ├── vault_test.cpp              # End-to-end Vault lifecycle, foreign-data guard, and rotation tests
│   └── app_e2e_test.cmake          # Multi-process CLI integration test
├── scripts/
│   ├── build.ps1                   # Windows MSYS2 UCRT64 build & CTest automation script
│   └── package_release.ps1         # Release bundler (.zip + SHA256SUMS.txt)
├── include/
│   └── void_vault_c.h              # Universal C ABI for C/Rust/Go/C#/MQL5 embedding
├── sdk/
│   └── python/void_vault.py        # Zero-dependency Python SDK & Capability Broker client
├── DEVELOPER_GUIDE.md              # Step-by-step developer integration & token guide
├── SECURITY.md                     # Threat model, cryptographic design & disclosure policy
├── CONTRIBUTING.md                 # Contribution & security review guidelines
└── LICENSE                         # MIT License
```

---

## Prerequisites & Installation

### Windows (MSYS2 UCRT64)

Install the MSYS2 UCRT64 toolchain and `libsodium`:

```powershell
C:\msys64\usr\bin\pacman.exe -S --needed `
  mingw-w64-ucrt-x86_64-gcc `
  mingw-w64-ucrt-x86_64-cmake `
  mingw-w64-ucrt-x86_64-make `
  mingw-w64-ucrt-x86_64-pkgconf `
  mingw-w64-ucrt-x86_64-libsodium
```

> **Windows PATH Note:** If Anaconda or another MinGW distribution is on your `PATH`, its older `libstdc++-6.dll` or `libsodium.dll` can shadow MSYS2 UCRT64. `CMakeLists.txt` defaults `VOID_VAULT_STATIC_RUNTIME=ON` on MinGW so `libstdc++`, `libsodium`, and `winpthread` are linked statically into `void_vault.exe`. Always build via `scripts\build.ps1` or prepend `C:\msys64\ucrt64\bin` to `$env:PATH`.

### Linux (Ubuntu / Debian)

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libsodium-dev
```

---

## Building & Running Tests

### Quick Build & Test on Windows (Recommended)

```powershell
# Release build + full CTest suite
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -BuildType Release -BuildDir build

# Debug build + full CTest suite
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -BuildType Debug -BuildDir build-debug
```

### Manual CMake & CTest Commands

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;" + $env:PATH
& "C:\Program Files\CMake\bin\cmake.exe" -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
& "C:\Program Files\CMake\bin\cmake.exe" --build build -j 4
& "C:\Program Files\CMake\bin\ctest.exe" --test-dir build --output-on-failure
```

Run a single test target:

```powershell
& "C:\Program Files\CMake\bin\ctest.exe" --test-dir build -R encryption_test --output-on-failure
```

---

## Running Void Vault

```powershell
# Default data directory (current working directory) and interactive KDF profile
.\build\void_vault.exe

# Custom data directory with Sensitive (1 GiB Argon2id) KDF profile
.\build\void_vault.exe --data-dir D:\secure\vault --kdf sensitive

# CLI help
.\build\void_vault.exe --help
```

### Interactive Menu Workflow

1. **First-time setup:** If `vault_auth.dat` does not exist in `--data-dir`, you are prompted to enter and confirm a password (minimum 12 printable characters, non-repeating).
2. **`1) unlock`**: Authenticates your password against `vault_auth.dat` and unlocks the session.
3. **`2) save text`**: Encrypts and atomically saves confidential text to `vault_data.dat`.
4. **`3) show data`**: Decrypts and displays the stored record from `vault_data.dat`.
5. **`4) lock`**: Immediately wipes the in-memory session password and locks the vault.
6. **`5) status`**: Displays lock state, failed-attempt count (`n/5`), and whether `vault_data.dat` exists.
7. **`6) quit`**: Wipes session secrets, releases the session lock, and exits cleanly (`0`).
8. **`7) change password`**: Atomically rotates the account password and re-encrypts `vault_data.dat` under the new key.
9. **`8) secrets`**: Manage multiple named key-value secrets (`set`, `get`, `del`, `list`) inside the encrypted container (`VVKV1`).
10. **`9) app token`**: Issue a scoped, short-lived **"Sign in with Void Vault"** capability token (`VVTOK1...`) for an external application/module.

---

## Embedding Void Vault & "Sign in with Void Vault" (Developer Guide)

Void Vault is designed so third-party applications (trading systems, healthcare tools, AI agents, desktop apps, and local services) can let the **end-user own and control their secrets locally** while granting applications **scoped, time-bounded capability tokens (`VVTOK1`)** or **isolated 256-bit cryptographic subkeys**—without ever exposing the user's master password to the application.

### 1. Scoped Capability Tokens (`VVTOK1`) — Local OAuth-Style Authorization

When an application requests access, Void Vault issues an `HMAC-SHA512256`-authenticated token:
```text
VVTOK1.<hex(issued_at || expires_at || app_id || scope)>.<hex(hmac_sha512256)>
```
Supported scopes:
- `*` — Full read/write access to all named secrets.
- `read:*` — Read-only access to all named secrets.
- `read:<prefix>*` (e.g. `read:trader.*`) — Read-only access to secrets starting with `<prefix>`.
- `write:<prefix>*` (e.g. `write:trader.*`) — Read + write access to secrets starting with `<prefix>`.
- `key:<exact_key>` / `read_key:<exact_key>` — Access restricted to a single secret key.
- `auth:only` — Identity verification and zero-knowledge app subkey derivation only (zero secret read/write access).

### 2. Three Ways to Integrate Void Vault into Your Application

#### A. Python SDK (`sdk/python/void_vault.py`) & `--broker` IPC Pipe
Any language can spawn `void_vault --data-dir <dir> --broker` over stdin/stdout pipes. In Python:

```python
from sdk.python.void_vault import VoidVaultClient

with VoidVaultClient("build/void_vault.exe", data_dir="./vault_data") as vault:
    # 1. User unlocks their vault (master password stays inside Void Vault)
    vault.unlock("UserMasterPassword123!")
    vault.set_secret("trader.mt5_password", "BrokerSecret#99")
    vault.set_secret("personal.medical_note", "PrivateRecord")

    # 2. Issue a scoped "Sign in with Void Vault" token for the 'void-trader' module
    token = vault.issue_token(app_id="void-trader", scope="read:trader.*", ttl_seconds=300)

    # 3. The 'void-trader' module can read 'trader.*' secrets, but is blocked from 'personal.*'
    mt5_pw = vault.get_secret_with_token(token, app_id="void-trader", key="trader.mt5_password")

    # 4. Or derive a deterministic 256-bit encryption key isolated to 'void-trader'
    app_encryption_key: bytes = vault.derive_app_key(token, app_id="void-trader", subkey_id=1)
```

#### B. Universal C ABI (`include/void_vault_c.h`)
For C, Rust, Go, Node.js FFI, C# P/Invoke, or MetaTrader 5 (MQL5) DLL integration, include [`include/void_vault_c.h`](include/void_vault_c.h):
- `vv_open`, `vv_close`, `vv_setup_password`, `vv_unlock`, `vv_lock`
- `vv_set_secret`, `vv_get_secret`
- `vv_issue_token`, `vv_verify_token`, `vv_get_secret_with_token`, `vv_set_secret_with_token`, `vv_derive_app_key`

#### C. Native C++20 Library (`void_vault_core`)
Link against `void_vault_core` in CMake and include [`src/vault/broker.hpp`](src/vault/broker.hpp) (`VaultBroker`).

---

### Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Normal exit (`quit` or `EOF` on standard input) |
| `1` | First-time account setup aborted or failed |
| `2` | Invalid command-line argument or nonexistent `--data-dir` |
| `3` | `vault_auth.dat` is unreadable, tampered, or corrupted (fail-closed) |
| `4` | Account is locked out after 5 failed password attempts |
| `5` | Another `void_vault` process holds the active session lock on `--data-dir` |

---

## Lockout & Corruption Recovery

Because confidentiality of `vault_data.dat` is enforced by the Argon2id-derived AEAD key (and **not** by `vault_auth.dat`), legitimate owners who know their original password can recover from a persistent 5-attempt lockout:

1. Close all running `void_vault` processes.
2. Delete or move `vault_auth.dat` (keep `vault_data.dat` intact).
3. Launch `void_vault` and complete first-time setup using the **exact original password** that encrypted `vault_data.dat`.
   - *Safety guarantee:* If you accidentally initialize with a different password, `Vault::saveData` detects that `vault_data.dat` cannot be decrypted with the new password and refuses to overwrite it (`ForeignDataExists`).

---

## License

Released under the [MIT License](LICENSE). See [SECURITY.md](SECURITY.md) for the full threat model and vulnerability reporting instructions.
