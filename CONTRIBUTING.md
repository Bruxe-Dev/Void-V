# Contributing to Void Vault

Thank you for contributing to **Void Vault**! Because this project handles authentication and encrypted storage, all contributions are held to strict security and correctness standards.

## Security & Engineering Rules

1. **No Custom Cryptography:** Use only established, high-level `libsodium` constructions (`crypto_pwhash`, `crypto_aead_xchacha20poly1305_ietf`, `sodium_malloc`, `sodium_memzero`, `sodium_memcmp`).
2. **Fail Closed:** Every error path (I/O failure, malformed record, failed MAC check, lock contention) must leave output buffers unmodified, wipe temporary secrets, and deny access.
3. **Secret Hygiene:** Never pass passwords through command-line arguments, logs, or un-wiped heap allocations. Use `SecureBuffer` for sensitive strings.
4. **Assertion-Free Tests:** Never place side-effecting expressions inside `assert()` in tests, as `NDEBUG` strips `assert()` in `Release` builds. Always use `tu::check(...)` in `tests/test_util.hpp`.
5. **Zero Compiler Warnings:** All code must compile cleanly under `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2` (GCC/Clang) and `/W4 /permissive-` (MSVC).

## Building and Running Tests Locally

### Windows (MSYS2 UCRT64)
```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -BuildType Release -BuildDir build
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -BuildType Debug -BuildDir build-debug
```

### Linux / macOS
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
```

## Pull Request Checklist

- [ ] Release and Debug builds compile with zero warnings.
- [ ] All 5 CTest suites (`storage_test`, `auth_test`, `encryption_test`, `vault_test`, `app_e2e_test`) pass.
- [ ] Any new security behavior or edge case includes a deterministic regression test.
- [ ] Documentation (`README.md` / `SECURITY.md`) is updated if file formats or CLI flags change.
