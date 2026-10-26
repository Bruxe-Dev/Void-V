# Security Policy & Threat Model

## Cryptographic Architecture

Void Vault uses established primitives from **libsodium** with zero custom cryptography:

| Layer | Primitive | Parameters / Details |
|---|---|---|
| **Key Derivation (KDF)** | `crypto_pwhash` (`Argon2id v1.3`) | 128-bit (16-byte) random salt per save; configurable work factor (`Interactive`: 64 MiB / 2 ops, `Moderate`: 256 MiB / 3 ops, `Sensitive`: 1 GiB / 4 ops) |
| **Authenticated Encryption (AEAD)** | `crypto_aead_xchacha20poly1305_ietf` | 256-bit derived key, 192-bit (24-byte) random nonce, 128-bit (16-byte) Poly1305 authentication tag |
| **Header Authentication (AAD)** | 44-byte header bound as AAD | `magic (4 B) \|\| salt (16 B) \|\| nonce (24 B)` is authenticated via AEAD Additional Authenticated Data to prevent header tampering or KDF downgrade attacks |
| **Online Password Gate** | `crypto_pwhash_str` (`Argon2id v1.3`) | Stored in `vault_auth.dat` (`VVAUTH1` format) with a persistent pre-verification failure counter (`MAX_FAILED_ATTEMPTS = 5`) |

---

## Defense-in-Depth Controls

1. **Zero `std::cin` / `std::string` Secret Buffering (`SecureBuffer`)**
   - Interactive passwords and confidential input lines are read byte-by-byte directly from the OS input handle (`ReadFile(STD_INPUT_HANDLE)` on Windows, `read(STDIN_FILENO)` on POSIX) into `sodium_malloc`-allocated memory (`SecureBuffer`).
   - `sodium_malloc` places guard pages around allocations, locks pages in physical RAM (`VirtualLock` / `mlock`) where OS limits permit, and wipes memory via `sodium_memzero` on release.
   - Derived 256-bit keys are locked with `sodium_mlock` and wiped with `sodium_munlock` on scope exit.
   - Password equality checks use constant-time `sodium_memcmp`.

2. **Process Hardening (`hardenProcess()`)**
   - **Windows:** Enables `HeapEnableTerminationOnCorruption` and suppresses Windows Error Reporting crash dumps (`SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX`) so secrets in memory are not written to crash dump files.
   - **POSIX / Linux:** Sets `RLIMIT_CORE = 0` to disable core dumps and calls `prctl(PR_SET_DUMPABLE, 0)` on Linux to block non-root `ptrace` attachment.

3. **Filesystem & Concurrency Hardening (`Storage` & `FileLock`)**
   - **Atomic Writes:** Every update writes to `<path>.tmp` with exclusive file sharing, flushes OS buffers (`FlushFileBuffers` on Windows, `fsync` on POSIX), and atomically commits via `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` or `rename()` / `link()`.
   - **Owner-Only Permissions:** Restricts file access to the current user SID (`SetNamedSecurityInfoW` with `PROTECTED_DACL_SECURITY_INFORMATION` on Windows; `chmod 0600` on POSIX).
   - **Symlink & Reparse-Point Rejection:** Both read and write paths reject symbolic links and Windows reparse points/junctions (`FILE_ATTRIBUTE_REPARSE_POINT`, `O_NOFOLLOW`) to prevent symlink traversal attacks.
   - **Cross-Process Locking:** Exclusive OS file locks (`LockFileEx` on Windows, `flock` on POSIX) prevent concurrent processes from racing on `vault_auth.dat`, `vault_data.dat`, or an active `--data-dir` session.
   - **Bounded Allocation:** Enforces a strict `16 MiB` (`Storage::MAX_FILE_SIZE`) limit before reading or writing to prevent memory-exhaustion Denial of Service.

4. **Fail-Closed Persistent Lockout & Foreign-Data Protection**
   - In persistent mode, `Authorizer::verifyPassword` increments and atomically persists `failed=<n>` **before** verifying the Argon2id hash, so killing the process mid-check cannot bypass the 5-attempt counter.
   - Any corrupted, empty, or malformed `vault_auth.dat` triggers `hasStorageError() == true` and refuses both login and re-initialization (a corrupted auth file never silently becomes a new account).
   - `Vault::saveData` verifies that any existing `vault_data.dat` can be decrypted with the current session password before overwriting (`VaultError::ForeignDataExists`), preventing accidental data loss if `vault_auth.dat` was recreated with a different password.
5. **Broker Extensions**
   - Ephemeral values are held only in broker memory, checked against a monotonic TTL on access, and wiped by cleanup or vault lock. They are not persisted to the `VVKV1` store.
   - Transit encryption runs in the broker process with a separate key and capability scopes (`transit:encrypt`, `transit:decrypt`). The daemon C ABI sends payload bytes over local process pipes; embedded/in-process C ABI handles do not provide this process boundary.
   - PKI CA private-key bundles are persisted only inside the encrypted vault store. The broker returns certificates, not private CA bundles.
6. **OS-Backed Auto-Unseal**
   - Opt-in auto-unseal encrypts the master password under a random fragment. Windows protects the fragment with current-user DPAPI; Linux stores it in the current user's kernel keyring. The encrypted envelope is stored beside the vault data file.
   - These integrations use OS user-account facilities, not a TPM, secure enclave, or other hardware-isolated key store.
   - This is not protection against malware, administrators, or another process running as the same OS user. Anyone able to execute as that user may be able to use the OS credential context and access the vault files. Auto-unseal is unsuitable for shared accounts or remotely accessible services.

---

## Threat Model Boundaries

- **Offline Brute-Force Resistance:** `vault_auth.dat` enforces a 5-attempt lockout for online interactive sessions. An attacker with direct read access to `vault_data.dat` can mount an offline password-guessing attack bounded by the Argon2id KDF cost (`--kdf sensitive` uses 1 GiB RAM and 4 iterations per guess) and password entropy. Always use a high-entropy passphrase and `--kdf moderate` or `--kdf sensitive` for high-value secrets.
- **Same-UID / Kernel Compromise:** If an attacker already runs arbitrary code as the same OS user (with administrative privileges or kernel access), they can intercept keystrokes before they reach the process.
- **Auto-Unseal Trust Boundary:** Enabling auto-unseal deliberately trades an interactive password prompt for trust in the local OS account. It does not provide hardware-backed isolation from same-user malware and does not make a compromised host safe.
- **Broker IPC Boundary:** The daemon-backed Transit C ABI keeps master keys out of the companion process, but the companion still receives plaintext after a successful decrypt and can retain its own copies. Process pipes are local IPC, not a substitute for OS account isolation.
- **Unattended Cloud / Daemon Workloads:** Void Vault is designed for interactive human-operated credential storage. Unattended cloud workers should use a cloud KMS/HSM (AWS KMS, GCP Secret Manager, Azure Key Vault, or HashiCorp Vault) with short-lived workload identity tokens.

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities.

Instead, report vulnerabilities privately via GitHub Security Advisories or by contacting the repository maintainers directly with:
1. A description of the vulnerability and its potential impact.
2. Minimal steps or a proof-of-concept test case to reproduce the issue.
3. Affected OS, compiler, and `libsodium` version.
