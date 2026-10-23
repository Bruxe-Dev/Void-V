// Void Vault interactive application & IPC Capability Broker.
//
// Passwords and confidential payloads are never accepted on the command line
// and never pass through std::cin or std::string buffers. All input is read
// byte-by-byte from the OS console / standard input handle directly into
// sodium_malloc memory (SecureBuffer).

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>

#include <sodium.h>

#include "security/audit_log.hpp"
#include "security/auth.hpp"
#include "security/encryption.hpp"
#include "security/process_hardening.hpp"
#include "security/secure_buffer.hpp"
#include "vault/broker.hpp"
#include "vault/vault.hpp"
#include "storage.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <conio.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace
{
    void wipe(std::string &s)
    {
        if (!s.empty())
        {
            sodium_memzero(s.data(), s.size());
            s.clear();
        }
    }

    std::string encodeHex(std::string_view raw)
    {
        if (raw.empty())
        {
            return {};
        }
        std::string hex(raw.size() * 2 + 1, '\0');
        sodium_bin2hex(
            hex.data(),
            hex.size(),
            reinterpret_cast<const unsigned char *>(raw.data()),
            raw.size());
        hex.resize(raw.size() * 2);
        return hex;
    }

    bool decodeHexToSecureBuffer(std::string_view hex, SecureBuffer &out)
    {
        out.clear();
        if (hex.empty())
        {
            return true;
        }
        if ((hex.size() % 2) != 0)
        {
            return false;
        }
        std::string tmp(hex.size() / 2, '\0');
        std::size_t bin_len = 0;
        const int rc = sodium_hex2bin(
            reinterpret_cast<unsigned char *>(tmp.data()),
            tmp.size(),
            hex.data(),
            hex.size(),
            nullptr,
            &bin_len,
            nullptr);
        if (rc != 0 || bin_len != tmp.size())
        {
            wipe(tmp);
            return false;
        }
        out.assign(tmp);
        wipe(tmp);
        return true;
    }

    bool isInteractiveConsole() noexcept
    {
#ifdef _WIN32
        HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        return h != INVALID_HANDLE_VALUE && h != nullptr && GetConsoleMode(h, &mode) != 0;
#else
        return isatty(STDIN_FILENO) != 0;
#endif
    }

    // Reads a single byte from the OS standard input descriptor without
    // std::cin / stdio buffering, so secrets never linger in stream buffers.
    bool readRawByte(char &out_byte) noexcept
    {
#ifdef _WIN32
        HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
        if (h == INVALID_HANDLE_VALUE || h == nullptr)
        {
            return false;
        }
        DWORD bytes_read = 0;
        if (!ReadFile(h, &out_byte, 1, &bytes_read, nullptr) || bytes_read != 1)
        {
            return false;
        }
        return true;
#else
        const ssize_t n = ::read(STDIN_FILENO, &out_byte, 1);
        return n == 1;
#endif
    }

#ifndef _WIN32
    // RAII: disables console echo while alive on POSIX terminals.
    class EchoGuard
    {
    public:
        EchoGuard()
        {
            if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_) == 0)
            {
                termios t = old_;
                t.c_lflag &= ~static_cast<tcflag_t>(ECHO);
                active_ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) == 0;
            }
        }
        ~EchoGuard()
        {
            if (!active_)
            {
                return;
            }
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_);
            std::cout << '\n';
        }
        EchoGuard(const EchoGuard &) = delete;
        EchoGuard &operator=(const EchoGuard &) = delete;

    private:
        bool active_ = false;
        termios old_{};
    };
#endif

    bool readSecureStreamLine(SecureBuffer &out)
    {
        out.clear();
        out.reserve(SecureBuffer::DEFAULT_CAPACITY);
        char c = '\0';
        bool got_any = false;
        while (readRawByte(c))
        {
            got_any = true;
            if (c == '\n')
            {
                sodium_memzero(&c, sizeof(c));
                break;
            }
            if (c == '\b' || c == 0x7F)
            {
                out.pop_back();
                sodium_memzero(&c, sizeof(c));
                continue;
            }
            if (!out.push_back(c))
            {
                sodium_memzero(&c, sizeof(c));
                out.clear();
                return false;
            }
            sodium_memzero(&c, sizeof(c));
        }
        sodium_memzero(&c, sizeof(c));
        if (!got_any)
        {
            out.clear();
            return false;
        }
        if (!out.empty() && out.view().back() == '\r')
        {
            out.pop_back();
        }
        return true;
    }

    // Reads a password directly into sodium_malloc memory.
    // On an interactive Windows console, uses _getch() with '*' visual feedback,
    // clean Backspace erasure ("\b \b"), and extended-keycode filtering so
    // arrow/function keys never insert garbage bytes into the password.
    bool readSecret(const char *prompt, SecureBuffer &out)
    {
        std::cout << prompt << std::flush;
#ifdef _WIN32
        if (isInteractiveConsole())
        {
            out.clear();
            out.reserve(SecureBuffer::DEFAULT_CAPACITY);
            while (true)
            {
                int ch = _getch();
                if (ch == EOF || ch == 3) // EOF or Ctrl+C
                {
                    sodium_memzero(&ch, sizeof(ch));
                    std::cout << '\n';
                    out.clear();
                    return false;
                }
                if (ch == '\r' || ch == '\n')
                {
                    sodium_memzero(&ch, sizeof(ch));
                    std::cout << '\n';
                    return true;
                }
                if (ch == 0 || ch == 0xE0)
                {
                    // Consume two-byte extended key (arrow keys, Delete, F-keys)
                    (void)_getch();
                    sodium_memzero(&ch, sizeof(ch));
                    continue;
                }
                if (ch == '\b' || ch == 127)
                {
                    if (!out.empty())
                    {
                        out.pop_back();
                        std::cout << "\b \b" << std::flush;
                    }
                    sodium_memzero(&ch, sizeof(ch));
                    continue;
                }
                if (ch >= 0x20 && ch < 0x7F)
                {
                    const char c = static_cast<char>(ch);
                    if (out.push_back(c))
                    {
                        std::cout << '*' << std::flush;
                    }
                }
                sodium_memzero(&ch, sizeof(ch));
            }
        }
        return readSecureStreamLine(out);
#else
        EchoGuard guard;
        return readSecureStreamLine(out);
#endif
    }

    // Reads a single line (echo enabled) directly into sodium_malloc memory.
    bool readSensitiveLine(const char *prompt, SecureBuffer &out)
    {
        std::cout << prompt << std::flush;
        return readSecureStreamLine(out);
    }

    bool readLine(const char *prompt, std::string &out)
    {
        SecureBuffer buf;
        if (!readSensitiveLine(prompt, buf))
        {
            return false;
        }
        out.assign(buf.view().data(), buf.view().size());
        return true;
    }

    bool isKvContainer(std::string_view raw) noexcept
    {
        return raw.size() >= 5 && raw.compare(0, 5, "VVKV1") == 0;
    }

    void printHelp()
    {
        std::cout << "Void Vault v2.0.0 — Authenticated Encrypted Local Vault & Capability Broker\n"
                     "Usage: void_vault [--data-dir <directory>] [--kdf <interactive|moderate|sensitive>]\n"
                     "                  [--idle-timeout <seconds>] [--verify-audit]\n"
                     "                  [--broker] [--version] [--help]\n"
                     "  Stores vault_auth.dat (password hash + failed-attempt counter),\n"
                     "  vault_data.dat (XChaCha20-Poly1305 AEAD encrypted record),\n"
                     "  vault_recovery.dat (optional Emergency Recovery Key capsule),\n"
                     "  and vault_audit.log (BLAKE2b-256 hash-chained tamper-evident audit log)\n"
                     "  in the data directory (default: current directory).\n";
    }

    void printMenu(bool unlocked)
    {
        if (isInteractiveConsole())
        {
            std::cout << "\n============================================================\n"
                      << "  VOID VAULT v2.0 STATUS : [" << (unlocked ? "UNLOCKED" : "LOCKED") << "]\n"
                      << "============================================================\n"
                      << "  [1] Unlock Vault              [6] Quit (Lock & Exit)\n"
                      << "  [2] Save Quick Text Note      [7] Change Master Password\n"
                      << "  [3] View All Stored Data      [8] Manage Named Secrets (Key-Value)\n"
                      << "  [4] Lock Vault                [9] Generate / Revoke App Tokens\n"
                      << "  [5] Check Vault Status        [10] Emergency Recovery & Audit Log\n"
                      << "------------------------------------------------------------\n";
        }
        else
        {
            std::cout << "\n[" << (unlocked ? "UNLOCKED" : "LOCKED") << "] "
                      << "1) unlock  2) save text  3) show data  4) lock  5) status  6) quit  "
                      << "7) change password  8) secrets  9) app token  10) recovery/audit\n";
        }
    }

    int firstTimeSetup(Authorizer &authorizer, Storage &storage, Vault &vault)
    {
        const bool recovering_existing_data = storage.exists();
        if (recovering_existing_data)
        {
            std::cout << "\n============================================================\n"
                      << "  ACCOUNT RECOVERY MODE (Existing vault_data.dat found!)\n"
                      << "============================================================\n"
                      << "An encrypted vault_data.dat file already exists in this folder,\n"
                      << "but vault_auth.dat is missing.\n"
                      << "To recover your existing secrets, enter the ORIGINAL master\n"
                      << "password that was used to encrypt vault_data.dat.\n\n";
        }
        else
        {
            std::cout << "No account found. First-time setup.\n"
                      << "Choose a password of at least " << Authorizer::MIN_PASSWORD_LENGTH
                      << " characters.\n";
        }

        for (int tries = 0; tries < 3; ++tries)
        {
            SecureBuffer first, second;
            if (!readSecret("New password: ", first) || !readSecret("Confirm password: ", second))
            {
                std::cout << "Input closed; setup aborted.\n";
                return 1;
            }
            if (first.view().size() < Authorizer::MIN_PASSWORD_LENGTH)
            {
                std::cout << "Password too short (minimum " << Authorizer::MIN_PASSWORD_LENGTH
                          << " characters required).\n";
                continue;
            }
            if (!Authorizer::isPasswordAcceptable(first.view()))
            {
                std::cout << "Password rejected (must contain printable, non-repeating characters).\n";
                continue;
            }
            if (!first.constantTimeEquals(second))
            {
                std::cout << "Passwords do not match. Please try again.\n";
                continue;
            }
            if (recovering_existing_data && !vault.canDecryptExistingData(first.view()))
            {
                std::cout << "\n[!] Password mismatch: That password cannot decrypt the existing vault_data.dat!\n"
                          << "    Please enter the exact password that was active when your data was saved.\n"
                          << "    (If you want to start a brand-new empty vault instead, delete or move vault_data.dat).\n\n";
                continue;
            }
            if (!authorizer.setPassword(first.view()))
            {
                std::cerr << "Account setup failed (could not write the auth file safely).\n";
                return 1;
            }
            std::cout << "Account created.\n";
            if (recovering_existing_data)
            {
                std::cout << "Existing encrypted vault data verified and linked to your recovered account.\n";
            }
            return 0;
        }
        std::cout << "Too many invalid setup attempts.\n";
        return 1;
    }

    // IPC Broker loop for external application modules ("Sign in with Void Vault"
    // & Scoped Secret Broker over standard input/output pipes).
    int runBrokerMode(
        Authorizer &authorizer,
        Vault &vault,
        VaultBroker &broker,
        AuditLog &audit_log,
        const std::string &recovery_path)
    {
        SecureBuffer line_buf;
        while (readSecureStreamLine(line_buf))
        {
            vault.checkIdleTimeout();
            std::string line(line_buf.view().data(), line_buf.view().size());
            line_buf.clear();
            if (line.empty())
            {
                continue;
            }

            std::istringstream in(line);
            std::string cmd;
            in >> cmd;

            if (cmd == "QUIT")
            {
                wipe(line);
                vault.lock();
                std::cout << "OK bye\n" << std::flush;
                return 0;
            }
            else if (cmd == "SETUP")
            {
                std::string pw_hex;
                in >> pw_hex;
                SecureBuffer pw;
                if (decodeHexToSecureBuffer(pw_hex, pw) &&
                    vault.canDecryptExistingData(pw.view()) &&
                    authorizer.setPassword(pw.view()))
                {
                    audit_log.append("ACCOUNT_INITIALIZED", "mode=broker");
                    std::cout << "OK initialized\n" << std::flush;
                }
                else
                {
                    std::cout << "ERR setup_failed\n" << std::flush;
                }
                wipe(pw_hex);
            }
            else if (cmd == "UNLOCK")
            {
                std::string pw_hex;
                in >> pw_hex;
                SecureBuffer pw;
                if (decodeHexToSecureBuffer(pw_hex, pw) &&
                    vault.authenticate(pw.view()) && vault.unlock())
                {
                    std::cout << "OK unlocked\n" << std::flush;
                }
                else
                {
                    std::cout << "ERR auth_failed\n" << std::flush;
                }
                wipe(pw_hex);
            }
            else if (cmd == "LOCK")
            {
                vault.lock();
                std::cout << "OK locked\n" << std::flush;
            }
            else if (cmd == "SET_SECRET")
            {
                std::string key, val_hex;
                in >> key >> val_hex;
                SecureBuffer val;
                if (decodeHexToSecureBuffer(val_hex, val) && broker.setSecret(key, val.view()))
                {
                    std::cout << "OK saved\n" << std::flush;
                }
                else
                {
                    std::cout << "ERR set_secret_failed\n" << std::flush;
                }
                wipe(val_hex);
            }
            else if (cmd == "GET_SECRET")
            {
                std::string key, val;
                in >> key;
                if (broker.getSecret(key, val))
                {
                    std::string hex = encodeHex(val);
                    wipe(val);
                    std::cout << "OK " << hex << '\n' << std::flush;
                    wipe(hex);
                }
                else
                {
                    std::cout << "ERR get_secret_failed\n" << std::flush;
                }
            }
            else if (cmd == "DELETE_SECRET")
            {
                std::string key;
                in >> key;
                if (broker.deleteSecret(key))
                {
                    std::cout << "OK deleted\n" << std::flush;
                }
                else
                {
                    std::cout << "ERR delete_secret_failed\n" << std::flush;
                }
            }
            else if (cmd == "LIST_KEYS")
            {
                std::vector<std::string> keys;
                if (broker.listKeys(keys))
                {
                    std::cout << "OK ";
                    for (std::size_t i = 0; i < keys.size(); ++i)
                    {
                        if (i > 0)
                        {
                            std::cout << ',';
                        }
                        std::cout << keys[i];
                    }
                    std::cout << '\n' << std::flush;
                }
                else
                {
                    std::cout << "ERR list_keys_failed\n" << std::flush;
                }
            }
            else if (cmd == "ISSUE_TOKEN")
            {
                std::string app_id, scope;
                std::uint64_t ttl = VaultBroker::DEFAULT_TOKEN_TTL_SECONDS;
                in >> app_id >> scope >> ttl;
                std::string token;
                if (broker.issueToken(app_id, scope, ttl, token))
                {
                    std::cout << "OK " << token << '\n' << std::flush;
                }
                else
                {
                    std::cout << "ERR issue_token_failed\n" << std::flush;
                }
            }
            else if (cmd == "VERIFY_TOKEN")
            {
                std::string token, app_id;
                in >> token >> app_id;
                CapabilityClaims claims;
                if (broker.verifyToken(token, app_id, claims))
                {
                    std::cout << "OK " << claims.scope << ' ' << claims.expires_at << '\n' << std::flush;
                }
                else
                {
                    std::cout << "ERR invalid_token\n" << std::flush;
                }
            }
            else if (cmd == "TOKEN_GET_SECRET")
            {
                std::string token, app_id, key, val;
                in >> token >> app_id >> key;
                if (broker.getSecretWithToken(token, app_id, key, val))
                {
                    std::string hex = encodeHex(val);
                    wipe(val);
                    std::cout << "OK " << hex << '\n' << std::flush;
                    wipe(hex);
                }
                else
                {
                    std::cout << "ERR token_get_denied\n" << std::flush;
                }
            }
            else if (cmd == "TOKEN_SET_SECRET")
            {
                std::string token, app_id, key, val_hex;
                in >> token >> app_id >> key >> val_hex;
                SecureBuffer val;
                if (decodeHexToSecureBuffer(val_hex, val) &&
                    broker.setSecretWithToken(token, app_id, key, val.view()))
                {
                    std::cout << "OK saved\n" << std::flush;
                }
                else
                {
                    std::cout << "ERR token_set_denied\n" << std::flush;
                }
                wipe(val_hex);
            }
            else if (cmd == "DERIVE_APP_KEY")
            {
                std::string token, app_id;
                std::uint64_t subkey_id = 1;
                in >> token >> app_id >> subkey_id;
                std::string key_hex;
                if (broker.deriveAppKey(token, app_id, subkey_id, key_hex))
                {
                    std::cout << "OK " << key_hex << '\n' << std::flush;
                    wipe(key_hex);
                }
                else
                {
                    std::cout << "ERR derive_key_denied\n" << std::flush;
                }
            }
            else if (cmd == "REVOKE_TOKENS")
            {
                if (broker.revokeAllTokens())
                {
                    std::cout << "OK revoked\n" << std::flush;
                }
                else
                {
                    std::cout << "ERR revoke_failed\n" << std::flush;
                }
            }
            else if (cmd == "REVOKE_APP_TOKENS")
            {
                std::string app_id;
                in >> app_id;
                if (broker.revokeAppTokens(app_id))
                {
                    std::cout << "OK revoked_app\n" << std::flush;
                }
                else
                {
                    std::cout << "ERR revoke_app_failed\n" << std::flush;
                }
            }
            else if (cmd == "GENERATE_RECOVERY_KEY")
            {
                std::string rec_key;
                if (vault.generateRecoveryKey(recovery_path, rec_key))
                {
                    std::cout << "OK " << rec_key << '\n' << std::flush;
                    wipe(rec_key);
                }
                else
                {
                    std::cout << "ERR generate_recovery_failed\n" << std::flush;
                }
            }
            else if (cmd == "RECOVER_WITH_KEY")
            {
                std::string rec_hex, new_pw_hex;
                in >> rec_hex >> new_pw_hex;
                SecureBuffer rec_buf, new_pw_buf;
                if (decodeHexToSecureBuffer(rec_hex, rec_buf) &&
                    decodeHexToSecureBuffer(new_pw_hex, new_pw_buf) &&
                    vault.recoverWithEmergencyKey(recovery_path, rec_buf.view(), new_pw_buf.view()))
                {
                    std::cout << "OK recovered\n" << std::flush;
                }
                else
                {
                    std::cout << "ERR recovery_failed\n" << std::flush;
                }
                wipe(rec_hex);
                wipe(new_pw_hex);
            }
            else if (cmd == "VERIFY_AUDIT")
            {
                std::size_t count = 0;
                if (audit_log.verifyChain(&count))
                {
                    std::cout << "OK " << count << '\n' << std::flush;
                }
                else
                {
                    std::cout << "ERR audit_tampered\n" << std::flush;
                }
            }
            else
            {
                std::cout << "ERR unknown_command\n" << std::flush;
            }
            wipe(line);
        }
        vault.lock();
        return 0;
    }
}

int main(int argc, char **argv)
{
    hardenProcess();

    std::filesystem::path data_dir = ".";
    KdfProfile kdf_profile = KdfProfile::Interactive;
    bool broker_mode = false;
    bool verify_audit_only = false;
    std::uint64_t idle_timeout_seconds = 0;

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h")
        {
            printHelp();
            return 0;
        }
        if (arg == "--version" || arg == "-v")
        {
            std::cout << "void_vault 2.0.0 (libsodium " << sodium_version_string() << ")\n";
            return 0;
        }
        if (arg == "--broker")
        {
            broker_mode = true;
            continue;
        }
        if (arg == "--verify-audit")
        {
            verify_audit_only = true;
            continue;
        }
        if (arg == "--idle-timeout" && i + 1 < argc)
        {
            try
            {
                idle_timeout_seconds = std::stoull(argv[++i]);
                continue;
            }
            catch (...)
            {
                std::cerr << "Invalid --idle-timeout value\n";
                return 2;
            }
        }
        if (arg == "--data-dir" && i + 1 < argc)
        {
            data_dir = argv[++i];
            continue;
        }
        if (arg == "--kdf" && i + 1 < argc)
        {
            const std::string mode = argv[++i];
            if (mode == "interactive")
            {
                kdf_profile = KdfProfile::Interactive;
                continue;
            }
            if (mode == "moderate")
            {
                kdf_profile = KdfProfile::Moderate;
                continue;
            }
            if (mode == "sensitive")
            {
                kdf_profile = KdfProfile::Sensitive;
                continue;
            }
            std::cerr << "Invalid --kdf profile: " << mode << " (expected interactive, moderate, or sensitive)\n";
            return 2;
        }
        std::cerr << "Unknown or incomplete argument: " << arg << '\n';
        printHelp();
        return 2;
    }

    std::error_code ec;
    if (!std::filesystem::is_directory(data_dir, ec))
    {
        std::cerr << "Data directory does not exist: " << data_dir.string() << '\n';
        return 2;
    }

    AuditLog audit_log((data_dir / "vault_audit.log").string());
    if (verify_audit_only)
    {
        std::size_t count = 0;
        if (audit_log.verifyChain(&count))
        {
            std::cout << "Audit log verified OK (" << count << " hash-chained entries intact).\n";
            return 0;
        }
        std::cerr << "ALERT: Audit log verification FAILED! Tampering or corruption detected.\n";
        return 6;
    }

    FileLock session_lock((data_dir / "vault_session").string());
    if (!session_lock.isLocked())
    {
        std::cerr << "Another Void Vault process is already using this data directory.\n";
        return 5;
    }

    const std::string recovery_path = (data_dir / "vault_recovery.dat").string();
    Authorizer authorizer((data_dir / "vault_auth.dat").string());
    Storage storage((data_dir / "vault_data.dat").string());

    if (authorizer.hasStorageError())
    {
        std::cerr << "The auth file exists but is unreadable or corrupted. Refusing to continue.\n"
                     "Recovery: restore vault_auth.dat from backup, or move it aside and re-create the\n"
                     "account with the ORIGINAL password (data stays encrypted with that password).\n";
        return 3;
    }

    Vault vault(authorizer, storage);
    vault.setKdfProfile(kdf_profile);
    vault.setAuditLog(&audit_log);
    vault.setIdleTimeoutSeconds(idle_timeout_seconds);

    VaultBroker broker(vault);
    broker.setAuditLog(&audit_log);

    if (broker_mode)
    {
        return runBrokerMode(authorizer, vault, broker, audit_log, recovery_path);
    }

    std::cout << "=== Void Vault ===\n";

    if (!authorizer.isInitialized())
    {
        const int rc = firstTimeSetup(authorizer, storage, vault);
        if (rc != 0)
        {
            return rc;
        }
        audit_log.append("ACCOUNT_INITIALIZED", "mode=interactive");
    }

    while (true)
    {
        if (vault.checkIdleTimeout())
        {
            std::cout << "\n[Auto-Lock] Vault automatically locked due to inactivity.\n";
        }

        if (authorizer.isLockedOut())
        {
            std::cerr << "Account is locked after " << Authorizer::MAX_FAILED_ATTEMPTS
                      << " failed attempts (persists across restarts).\n";
            Storage rec_storage(recovery_path);
            if (isInteractiveConsole() && rec_storage.exists())
            {
                std::cout << "\n[Emergency Recovery Key Capsule Detected!]\n"
                          << "Would you like to unlock & reset your master password using your\n"
                          << "Emergency Recovery Key (VVREC-XXXX-...)? (y/n): ";
                std::string ans;
                if (readLine("", ans) && (ans == "y" || ans == "Y" || ans == "yes"))
                {
                    SecureBuffer rec_key, new_pw, confirm_pw;
                    if (readSecret("Enter Emergency Recovery Key: ", rec_key) &&
                        readSecret("New Master Password (min 12 chars): ", new_pw) &&
                        readSecret("Confirm New Master Password: ", confirm_pw))
                    {
                        if (!new_pw.constantTimeEquals(confirm_pw))
                        {
                            std::cout << "Recovery aborted: New passwords do not match.\n";
                        }
                        else if (vault.recoverWithEmergencyKey(recovery_path, rec_key.view(), new_pw.view()))
                        {
                            std::cout << "Emergency recovery succeeded! Master password updated and vault unlocked.\n";
                            continue;
                        }
                        else
                        {
                            std::cout << "Emergency recovery failed: " << vaultErrorMessage(vault.lastError()) << '\n';
                        }
                    }
                }
            }
            std::cerr << "Recovery: Use an Emergency Recovery Key, or delete vault_auth.dat, launch\n"
                         "void_vault.exe again, and enter your ORIGINAL master password to recover\n"
                         "your encrypted vault_data.dat.\n";
            vault.lock();
            return 4;
        }

        printMenu(vault.isUnlocked());
        std::string choice;
        if (!readLine("Select option (1-10): > ", choice))
        {
            std::cout << "\nInput closed. Locking and exiting.\n";
            vault.lock();
            return 0;
        }

        if (vault.checkIdleTimeout())
        {
            std::cout << "\n[Auto-Lock] Vault automatically locked due to inactivity.\n";
        }

        if (choice == "1" || choice == "unlock")
        {
            SecureBuffer password;
            if (!readSecret("Password: ", password))
            {
                continue;
            }
            if (vault.authenticate(password.view()) && vault.unlock())
            {
                std::cout << "Vault unlocked.\n";
            }
            else
            {
                std::cout << "Authentication failed. Remaining attempts before lockout: "
                          << (Authorizer::MAX_FAILED_ATTEMPTS - authorizer.failedAttempts()) << '\n';
            }
        }
        else if (choice == "2" || choice == "save")
        {
            if (!vault.isUnlocked())
            {
                std::cout << "Rejected: " << vaultErrorMessage(VaultError::Locked) << '\n';
                continue;
            }
            SecureBuffer text;
            if (!readSensitiveLine("Text to store (single line): ", text))
            {
                continue;
            }
            // If the vault already contains a VVKV1 key-value store, preserve all
            // existing named secrets by storing this note under the "default" key.
            std::string existing_raw;
            const bool has_kv = storage.exists() && vault.loadData(existing_raw) && isKvContainer(existing_raw);
            wipe(existing_raw);

            const bool saved = has_kv ? broker.setSecret("default", text.view())
                                      : vault.saveData(text.view());
            if (saved)
            {
                std::cout << "Saved (encrypted).\n";
            }
            else
            {
                std::cout << "Save failed: " << vaultErrorMessage(vault.lastError()) << '\n';
            }
        }
        else if (choice == "3" || choice == "show")
        {
            std::string text;
            if (!vault.loadData(text))
            {
                std::cout << "Load failed: " << vaultErrorMessage(vault.lastError()) << '\n';
                continue;
            }
            if (isKvContainer(text))
            {
                wipe(text);
                std::vector<std::string> keys;
                if (broker.listKeys(keys))
                {
                    if (keys.empty())
                    {
                        std::cout << "Stored data: (vault key-value container is currently empty)\n";
                    }
                    else
                    {
                        std::cout << "--- Stored Vault Secrets (" << keys.size() << ") ---\n";
                        for (const auto &k : keys)
                        {
                            std::string val;
                            if (broker.getSecret(k, val))
                            {
                                std::cout << "  " << k << " = " << val << '\n';
                                wipe(val);
                            }
                        }
                    }
                }
                else
                {
                    std::cout << "Load failed: could not parse key-value store.\n";
                }
            }
            else
            {
                std::cout << "Stored data: " << text << '\n';
                wipe(text);
            }
        }
        else if (choice == "4" || choice == "lock")
        {
            vault.lock();
            std::cout << "Vault locked.\n";
        }
        else if (choice == "5" || choice == "status")
        {
            std::size_t audit_entries = 0;
            const bool audit_ok = audit_log.verifyChain(&audit_entries);
            std::cout << "Unlocked: " << (vault.isUnlocked() ? "yes" : "no")
                      << " | failed attempts: " << authorizer.failedAttempts() << '/'
                      << Authorizer::MAX_FAILED_ATTEMPTS
                      << " | data file present: " << (storage.exists() ? "yes" : "no")
                      << " | audit log: " << (audit_ok ? "intact" : "TAMPERED")
                      << " (" << audit_entries << " entries)\n";
        }
        else if (choice == "6" || choice == "q" || choice == "quit")
        {
            vault.lock();
            std::cout << "Vault locked. Goodbye.\n";
            return 0;
        }
        else if (choice == "7")
        {
            if (!vault.isUnlocked())
            {
                std::cout << "Rejected: " << vaultErrorMessage(VaultError::Locked) << '\n';
                continue;
            }
            SecureBuffer current_pw, new_pw, confirm_pw;
            if (!readSecret("Current password: ", current_pw) ||
                !readSecret("New password (min 12 chars): ", new_pw) ||
                !readSecret("Confirm new password: ", confirm_pw))
            {
                continue;
            }
            if (!new_pw.constantTimeEquals(confirm_pw))
            {
                std::cout << "Password change aborted: New passwords do not match (your password was NOT changed).\n";
                continue;
            }
            if (vault.changePassword(current_pw.view(), new_pw.view()))
            {
                std::cout << "Password changed and data re-encrypted.\n";
            }
            else
            {
                std::cout << "Password change failed: " << vaultErrorMessage(vault.lastError()) << '\n';
                if (vault.lastError() == VaultError::WrongCurrentPassword)
                {
                    std::cout << "Vault has been locked for security. Remaining attempts before lockout: "
                              << (Authorizer::MAX_FAILED_ATTEMPTS - authorizer.failedAttempts()) << '\n';
                }
            }
        }
        else if (choice == "8" || choice == "secrets")
        {
            if (!vault.isUnlocked())
            {
                std::cout << "Rejected: " << vaultErrorMessage(VaultError::Locked) << '\n';
                continue;
            }
            if (isInteractiveConsole())
            {
                std::cout << "\n--- Named Secrets Manager ---\n"
                          << "  [1 or set]  Save or update a secret (Key -> Value)\n"
                          << "  [2 or get]  View a specific secret by Key\n"
                          << "  [3 or list] List all stored secret Keys\n"
                          << "  [4 or del]  Delete a secret by Key\n"
                          << "  [5 or back] Return to main menu\n";
            }
            std::string action;
            if (!readLine("Secrets [1=set / 2=get / 3=list / 4=del / 5=back]: ", action))
            {
                continue;
            }
            if (action == "1" || action == "set")
            {
                std::string key;
                SecureBuffer val;
                if (!readLine("Key name (no spaces, e.g. date or trader.api_key): ", key) ||
                    !readSensitiveLine("Secret value: ", val))
                {
                    continue;
                }
                if (broker.setSecret(key, val.view()))
                {
                    std::cout << "Secret '" << key << "' saved.\n";
                }
                else
                {
                    std::cout << "Failed to save secret (key name must not contain spaces or start with '__vv_').\n";
                }
            }
            else if (action == "2" || action == "get")
            {
                std::string key, val;
                if (!readLine("Key name: ", key))
                {
                    continue;
                }
                if (broker.getSecret(key, val))
                {
                    std::cout << key << " = " << val << '\n';
                    wipe(val);
                }
                else
                {
                    std::cout << "Secret '" << key << "' not found.\n";
                }
            }
            else if (action == "3" || action == "list")
            {
                std::vector<std::string> keys;
                if (broker.listKeys(keys))
                {
                    if (keys.empty())
                    {
                        std::cout << "No secrets stored yet.\n";
                    }
                    else
                    {
                        std::cout << "Stored Keys (" << keys.size() << "):\n";
                        for (const auto &k : keys)
                        {
                            std::cout << "  - " << k << '\n';
                        }
                    }
                }
            }
            else if (action == "4" || action == "del")
            {
                std::string key;
                if (!readLine("Key name to delete: ", key))
                {
                    continue;
                }
                std::cout << (broker.deleteSecret(key) ? "Secret deleted.\n" : "Secret not found.\n");
            }
        }
        else if (choice == "9" || choice == "token")
        {
            if (!vault.isUnlocked())
            {
                std::cout << "Rejected: " << vaultErrorMessage(VaultError::Locked) << '\n';
                continue;
            }
            if (isInteractiveConsole())
            {
                std::cout << "\n--- 'Sign in with Void Vault' App Token Manager ---\n"
                          << "  Scope examples:\n"
                          << "    *               (full access to all secrets)\n"
                          << "    read:*          (read-only access to all secrets)\n"
                          << "    read:trader.*   (read-only access to keys starting with 'trader.')\n"
                          << "    key:date        (read/write access only to key 'date')\n"
                          << "  Tip: Enter 'revoke' as the Application ID to revoke tokens.\n";
            }
            std::string app_id;
            if (!readLine("Application ID (e.g. void-trader, or 'revoke'): ", app_id))
            {
                continue;
            }
            if (app_id == "revoke")
            {
                std::string target_app;
                if (!readLine("App ID to revoke (or '*' to revoke ALL apps): ", target_app))
                {
                    continue;
                }
                const bool ok = (target_app == "*") ? broker.revokeAllTokens()
                                                    : broker.revokeAppTokens(target_app);
                std::cout << (ok ? "Tokens revoked immediately.\n" : "Failed to revoke tokens.\n");
                continue;
            }
            std::string scope;
            if (!readLine("Allowed scope (e.g. read:trader.* or *): ", scope))
            {
                continue;
            }
            std::string token;
            if (broker.issueToken(app_id, scope, VaultBroker::DEFAULT_TOKEN_TTL_SECONDS, token))
            {
                std::cout << "Issued scoped capability token (TTL 300s):\n" << token << '\n';
            }
            else
            {
                std::cout << "Failed to issue token (app_id and scope must not contain spaces).\n";
            }
        }
        else if (choice == "10" || choice == "recovery" || choice == "audit")
        {
            if (isInteractiveConsole())
            {
                std::cout << "\n--- Emergency Recovery & Tamper-Evident Audit Log ---\n"
                          << "  [1] Generate One-Time Emergency Recovery Key (requires unlocked vault)\n"
                          << "  [2] Recover Account / Reset Forgotten Password using Emergency Key\n"
                          << "  [3] Verify Tamper-Evident Audit Log Chain (vault_audit.log)\n"
                          << "  [4] Return to main menu\n";
            }
            std::string sub;
            if (!readLine("Recovery/Audit [1=generate / 2=recover / 3=verify-audit / 4=back]: ", sub))
            {
                continue;
            }
            if (sub == "1" || sub == "generate")
            {
                if (!vault.isUnlocked())
                {
                    std::cout << "Rejected: " << vaultErrorMessage(VaultError::Locked) << '\n';
                    continue;
                }
                std::string rec_key;
                if (vault.generateRecoveryKey(recovery_path, rec_key))
                {
                    std::cout << "\n============================================================\n"
                              << "  ONE-TIME EMERGENCY RECOVERY KEY (WRITE THIS DOWN OFFLINE!)\n"
                              << "============================================================\n"
                              << "  " << rec_key << "\n"
                              << "============================================================\n"
                              << "Keep this key in a safe place. It can recover your vault even if\n"
                              << "you forget your master password or lock out your account.\n";
                    wipe(rec_key);
                }
                else
                {
                    std::cout << "Failed to generate recovery key: " << vaultErrorMessage(vault.lastError()) << '\n';
                }
            }
            else if (sub == "2" || sub == "recover")
            {
                SecureBuffer rec_key, new_pw, confirm_pw;
                if (!readSecret("Enter Emergency Recovery Key (VVREC-...): ", rec_key) ||
                    !readSecret("New Master Password (min 12 chars): ", new_pw) ||
                    !readSecret("Confirm New Master Password: ", confirm_pw))
                {
                    continue;
                }
                if (!new_pw.constantTimeEquals(confirm_pw))
                {
                    std::cout << "Recovery aborted: New passwords do not match.\n";
                    continue;
                }
                if (vault.recoverWithEmergencyKey(recovery_path, rec_key.view(), new_pw.view()))
                {
                    std::cout << "Emergency recovery complete! Master password reset, data re-encrypted, and vault unlocked.\n";
                }
                else
                {
                    std::cout << "Recovery failed: " << vaultErrorMessage(vault.lastError()) << '\n';
                }
            }
            else if (sub == "3" || sub == "verify-audit")
            {
                std::size_t count = 0;
                if (audit_log.verifyChain(&count))
                {
                    std::cout << "Audit log verified OK (" << count << " BLAKE2b-256 hash-chained entries intact).\n";
                }
                else
                {
                    std::cout << "WARNING: Audit log verification FAILED! Tampering or corruption detected.\n";
                }
            }
        }
        else if (!choice.empty())
        {
            std::cout << "Unknown option.\n";
        }
    }
}

