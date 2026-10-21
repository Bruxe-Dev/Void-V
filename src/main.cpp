// Void Vault interactive application & IPC Capability Broker.
//
// Passwords and confidential payloads are never accepted on the command line
// and never pass through std::cin or std::string buffers. All input is read
// byte-by-byte from the OS standard input handle directly into sodium_malloc
// memory (SecureBuffer).

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>

#include <sodium.h>

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

    // RAII: disables console echo while alive (no-op if stdin is not a console).
    class EchoGuard
    {
    public:
        EchoGuard()
        {
#ifdef _WIN32
            handle_ = GetStdHandle(STD_INPUT_HANDLE);
            if (handle_ != INVALID_HANDLE_VALUE && GetConsoleMode(handle_, &mode_))
            {
                active_ = SetConsoleMode(handle_, mode_ & ~static_cast<DWORD>(ENABLE_ECHO_INPUT)) != 0;
            }
#else
            if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_) == 0)
            {
                termios t = old_;
                t.c_lflag &= ~static_cast<tcflag_t>(ECHO);
                active_ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) == 0;
            }
#endif
        }
        ~EchoGuard()
        {
            if (!active_)
            {
                return;
            }
#ifdef _WIN32
            SetConsoleMode(handle_, mode_);
#else
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_);
#endif
            std::cout << '\n';
        }
        EchoGuard(const EchoGuard &) = delete;
        EchoGuard &operator=(const EchoGuard &) = delete;

    private:
        bool active_ = false;
#ifdef _WIN32
        HANDLE handle_ = INVALID_HANDLE_VALUE;
        DWORD mode_ = 0;
#else
        termios old_{};
#endif
    };

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

    // Reads a password with echo disabled directly into sodium_malloc memory.
    bool readSecret(const char *prompt, SecureBuffer &out)
    {
        std::cout << prompt << std::flush;
        EchoGuard guard;
        return readSecureStreamLine(out);
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

    void printHelp()
    {
        std::cout << "Void Vault v1.0.0 — Authenticated Encrypted Local Vault & Capability Broker\n"
                     "Usage: void_vault [--data-dir <directory>] [--kdf <interactive|moderate|sensitive>]\n"
                     "                  [--broker] [--version] [--help]\n"
                     "  Stores vault_auth.dat (password hash + failed-attempt counter)\n"
                     "  and vault_data.dat (XChaCha20-Poly1305 AEAD encrypted record) in the data directory\n"
                     "  (default: current directory). Passwords are only read interactively or via --broker IPC.\n";
    }

    int firstTimeSetup(Authorizer &authorizer)
    {
        std::cout << "No account found. First-time setup.\n"
                  << "Choose a password of at least " << Authorizer::MIN_PASSWORD_LENGTH
                  << " characters.\n";
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
                std::cout << "Password too short.\n";
                continue;
            }
            if (!Authorizer::isPasswordAcceptable(first.view()))
            {
                std::cout << "Password rejected (must contain printable, non-repeating characters).\n";
                continue;
            }
            if (!first.constantTimeEquals(second))
            {
                std::cout << "Passwords do not match.\n";
                continue;
            }
            if (!authorizer.setPassword(first.view()))
            {
                std::cerr << "Account setup failed (could not write the auth file safely).\n";
                return 1;
            }
            std::cout << "Account created.\n";
            return 0;
        }
        std::cout << "Too many invalid setup attempts.\n";
        return 1;
    }

    // IPC Broker loop for external application modules ("Sign in with Void Vault"
    // & Scoped Secret Broker over standard input/output pipes).
    int runBrokerMode(Authorizer &authorizer, Vault &vault, VaultBroker &broker)
    {
        SecureBuffer line_buf;
        while (readSecureStreamLine(line_buf))
        {
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
                if (decodeHexToSecureBuffer(pw_hex, pw) && authorizer.setPassword(pw.view()))
                {
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
            std::cout << "void_vault 1.0.0 (libsodium " << sodium_version_string() << ")\n";
            return 0;
        }
        if (arg == "--broker")
        {
            broker_mode = true;
            continue;
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

    FileLock session_lock((data_dir / "vault_session").string());
    if (!session_lock.isLocked())
    {
        std::cerr << "Another Void Vault process is already using this data directory.\n";
        return 5;
    }

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
    VaultBroker broker(vault);

    if (broker_mode)
    {
        return runBrokerMode(authorizer, vault, broker);
    }

    std::cout << "=== Void Vault ===\n";

    if (!authorizer.isInitialized())
    {
        const int rc = firstTimeSetup(authorizer);
        if (rc != 0)
        {
            return rc;
        }
    }

    while (true)
    {
        if (authorizer.isLockedOut())
        {
            std::cerr << "Account is locked after " << Authorizer::MAX_FAILED_ATTEMPTS
                      << " failed attempts (persists across restarts).\n"
                         "Recovery is manual; see README (Lockout recovery).\n";
            vault.lock();
            return 4;
        }

        std::cout << "\n[" << (vault.isUnlocked() ? "UNLOCKED" : "LOCKED") << "] "
                  << "1) unlock  2) save text  3) show data  4) lock  5) status  6) quit  "
                  << "7) change password  8) secrets  9) app token\n";
        std::string choice;
        if (!readLine("> ", choice))
        {
            std::cout << "\nInput closed. Locking and exiting.\n";
            vault.lock();
            return 0;
        }

        if (choice == "1")
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
        else if (choice == "2")
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
            if (vault.saveData(text.view()))
            {
                std::cout << "Saved (encrypted).\n";
            }
            else
            {
                std::cout << "Save failed: " << vaultErrorMessage(vault.lastError()) << '\n';
            }
        }
        else if (choice == "3")
        {
            std::string text;
            if (vault.loadData(text))
            {
                std::cout << "Stored data: " << text << '\n';
            }
            else
            {
                std::cout << "Load failed: " << vaultErrorMessage(vault.lastError()) << '\n';
            }
            wipe(text);
        }
        else if (choice == "4")
        {
            vault.lock();
            std::cout << "Vault locked.\n";
        }
        else if (choice == "5")
        {
            std::cout << "Unlocked: " << (vault.isUnlocked() ? "yes" : "no")
                      << " | failed attempts: " << authorizer.failedAttempts() << '/'
                      << Authorizer::MAX_FAILED_ATTEMPTS
                      << " | data file present: " << (storage.exists() ? "yes" : "no") << '\n';
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
                !readSecret("New password: ", new_pw) ||
                !readSecret("Confirm new password: ", confirm_pw))
            {
                continue;
            }
            if (!new_pw.constantTimeEquals(confirm_pw))
            {
                std::cout << "Passwords do not match.\n";
                continue;
            }
            if (vault.changePassword(current_pw.view(), new_pw.view()))
            {
                std::cout << "Password changed and data re-encrypted.\n";
            }
            else
            {
                std::cout << "Password change failed: " << vaultErrorMessage(vault.lastError()) << '\n';
            }
        }
        else if (choice == "8")
        {
            if (!vault.isUnlocked())
            {
                std::cout << "Rejected: " << vaultErrorMessage(VaultError::Locked) << '\n';
                continue;
            }
            std::string action;
            if (!readLine("Secrets [set/get/del/list]: ", action))
            {
                continue;
            }
            if (action == "set")
            {
                std::string key;
                SecureBuffer val;
                if (!readLine("Key name: ", key) || !readSensitiveLine("Secret value: ", val))
                {
                    continue;
                }
                if (broker.setSecret(key, val.view()))
                {
                    std::cout << "Secret '" << key << "' saved.\n";
                }
                else
                {
                    std::cout << "Failed to save secret.\n";
                }
            }
            else if (action == "get")
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
                    std::cout << "Secret not found.\n";
                }
            }
            else if (action == "del")
            {
                std::string key;
                if (!readLine("Key name: ", key))
                {
                    continue;
                }
                std::cout << (broker.deleteSecret(key) ? "Secret deleted.\n" : "Secret not found.\n");
            }
            else if (action == "list")
            {
                std::vector<std::string> keys;
                if (broker.listKeys(keys))
                {
                    std::cout << "Keys (" << keys.size() << "):";
                    for (const auto &k : keys)
                    {
                        std::cout << ' ' << k;
                    }
                    std::cout << '\n';
                }
            }
        }
        else if (choice == "9")
        {
            if (!vault.isUnlocked())
            {
                std::cout << "Rejected: " << vaultErrorMessage(VaultError::Locked) << '\n';
                continue;
            }
            std::string app_id, scope;
            if (!readLine("Application ID (e.g. void-trader): ", app_id) ||
                !readLine("Allowed scope (e.g. read:trader.* or *): ", scope))
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
                std::cout << "Failed to issue token (check app_id / scope format).\n";
            }
        }
        else if (!choice.empty())
        {
            std::cout << "Unknown option.\n";
        }
    }
}
