#include "../../include/void_vault_c.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "../../include/storage.hpp"
#include "../security/audit_log.hpp"
#include "../security/auth.hpp"
#include "broker.hpp"
#include "transit_engine.hpp"
#include "vault.hpp"

struct VoidVaultHandle {
    Authorizer authorizer;
    Storage storage;
    std::unique_ptr<AuditLog> audit_log;
    Vault vault;
    VaultBroker broker;

    VoidVaultHandle(
        const std::string& auth_path,
        const std::string& data_path,
        const std::string& audit_path)
        : authorizer(auth_path),
          storage(data_path),
          audit_log(audit_path.empty() ? nullptr : std::make_unique<AuditLog>(audit_path)),
          vault(authorizer, storage),
          broker(vault)
    {
        vault.setAuditLog(audit_log.get());
    }
};

struct VoidVaultDaemonClient {
    std::mutex mutex;
    std::string pending_output;
#ifdef _WIN32
    HANDLE process = nullptr;
    HANDLE input = nullptr;
    HANDLE output = nullptr;
#else
    pid_t process = -1;
    int socket = -1;
#endif
};

namespace
{
    constexpr std::size_t MAX_BROKER_RESPONSE_SIZE = 65536;

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

    std::string encodeHexBytes(const void* bytes, std::size_t size)
    {
        if (size == 0)
        {
            return "-";
        }
        std::string hex(size * 2 + 1, '\0');
        sodium_bin2hex(
            hex.data(),
            hex.size(),
            static_cast<const unsigned char*>(bytes),
            size);
        hex.resize(size * 2);
        return hex;
    }

    bool decodeHexBytes(std::string_view hex, std::string& bytes)
    {
        if (hex.empty())
        {
            bytes.clear();
            return true;
        }
        if (hex == "-")
        {
            bytes.clear();
            return true;
        }
        if (hex.empty() || (hex.size() % 2) != 0)
        {
            return false;
        }
        std::string result(hex.size() / 2, '\0');
        std::size_t written = 0;
        if (sodium_hex2bin(
                reinterpret_cast<unsigned char*>(result.data()),
                result.size(),
                hex.data(),
                hex.size(),
                nullptr,
                &written,
                nullptr) != 0 ||
            written != result.size())
        {
            sodium_memzero(result.data(), result.size());
            return false;
        }
        bytes = std::move(result);
        return true;
    }

#ifdef _WIN32
    std::string quoteWindowsArgument(std::string_view argument)
    {
        std::string quoted("\"");
        std::size_t backslashes = 0;
        for (const char c : argument)
        {
            if (c == '\\')
            {
                ++backslashes;
                continue;
            }
            if (c == '"')
            {
                quoted.append(backslashes * 2 + 1, '\\');
                quoted.push_back('"');
                backslashes = 0;
                continue;
            }
            quoted.append(backslashes, '\\');
            backslashes = 0;
            quoted.push_back(c);
        }
        quoted.append(backslashes * 2, '\\');
        quoted.push_back('"');
        return quoted;
    }
#endif

    bool writeBrokerRequest(VoidVaultDaemonClient& client, std::string_view request)
    {
        std::string line(request);
        line.push_back('\n');
#ifdef _WIN32
        std::size_t offset = 0;
        while (offset < line.size())
        {
            DWORD written = 0;
            const DWORD chunk = static_cast<DWORD>(
                std::min<std::size_t>(line.size() - offset, MAXDWORD));
            if (!WriteFile(client.input, line.data() + offset, chunk, &written, nullptr) ||
                written == 0)
            {
                sodium_memzero(line.data(), line.size());
                return false;
            }
            offset += written;
        }
#else
        std::size_t offset = 0;
        while (offset < line.size())
        {
            const ssize_t written = send(
                client.socket,
                line.data() + offset,
                line.size() - offset,
                MSG_NOSIGNAL);
            if (written < 0 && errno == EINTR)
            {
                continue;
            }
            if (written <= 0)
            {
                sodium_memzero(line.data(), line.size());
                return false;
            }
            offset += static_cast<std::size_t>(written);
        }
#endif
        sodium_memzero(line.data(), line.size());
        return true;
    }

    bool readBrokerResponse(VoidVaultDaemonClient& client, std::string& response)
    {
        for (;;)
        {
            const std::size_t newline = client.pending_output.find('\n');
            if (newline != std::string::npos)
            {
                response.assign(client.pending_output.data(), newline);
                if (newline > 0)
                {
                    sodium_memzero(client.pending_output.data(), newline);
                }
                client.pending_output.erase(0, newline + 1);
                if (!response.empty() && response.back() == '\r')
                {
                    response.pop_back();
                }
                return true;
            }
            if (client.pending_output.size() > MAX_BROKER_RESPONSE_SIZE)
            {
                return false;
            }

            char buffer[1024];
#ifdef _WIN32
            DWORD received = 0;
            if (!ReadFile(client.output, buffer, sizeof(buffer), &received, nullptr) ||
                received == 0)
            {
                return false;
            }
            client.pending_output.append(buffer, received);
            sodium_memzero(buffer, received);
#else
            const ssize_t received = recv(client.socket, buffer, sizeof(buffer), 0);
            if (received < 0 && errno == EINTR)
            {
                continue;
            }
            if (received <= 0)
            {
                return false;
            }
            client.pending_output.append(buffer, static_cast<std::size_t>(received));
            sodium_memzero(buffer, static_cast<std::size_t>(received));
#endif
        }
    }

    bool daemonRequest(
        VoidVaultDaemonClient& client,
        std::string_view request,
        std::string& response)
    {
        std::lock_guard<std::mutex> lock(client.mutex);
        if (!writeBrokerRequest(client, request) ||
            !readBrokerResponse(client, response))
        {
            return false;
        }
        if (response.rfind("ERR ", 0) == 0)
        {
            sodium_memzero(response.data(), response.size());
            response.clear();
            return false;
        }
        if (response == "OK")
        {
            response.clear();
            return true;
        }
        if (response.rfind("OK ", 0) == 0)
        {
            response.erase(0, 3);
            return true;
        }
        sodium_memzero(response.data(), response.size());
        response.clear();
        return false;
    }
}

extern "C" {

VV_API VoidVaultDaemonClient* vv_daemon_client_open(
    const char* executable_path,
    const char* data_dir,
    int auto_unseal)
{
    if (executable_path == nullptr || data_dir == nullptr ||
        (auto_unseal != 0 && auto_unseal != 1))
    {
        return nullptr;
    }
    try
    {
        if (sodium_init() < 0)
        {
            return nullptr;
        }
        std::filesystem::create_directories(data_dir);
        auto client = std::make_unique<VoidVaultDaemonClient>();
#ifdef _WIN32
        SECURITY_ATTRIBUTES security{};
        security.nLength = sizeof(security);
        security.bInheritHandle = TRUE;

        HANDLE child_input = nullptr;
        HANDLE parent_input = nullptr;
        HANDLE parent_output = nullptr;
        HANDLE child_output = nullptr;
        if (!CreatePipe(&child_input, &parent_input, &security, 0) ||
            !CreatePipe(&parent_output, &child_output, &security, 0))
        {
            if (child_input != nullptr) CloseHandle(child_input);
            if (parent_input != nullptr) CloseHandle(parent_input);
            if (parent_output != nullptr) CloseHandle(parent_output);
            if (child_output != nullptr) CloseHandle(child_output);
            return nullptr;
        }
        SetHandleInformation(parent_input, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(parent_output, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = child_input;
        startup.hStdOutput = child_output;
        startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);

        std::string command = quoteWindowsArgument(executable_path) +
                              " --data-dir " + quoteWindowsArgument(data_dir) +
                              " --broker";
        if (auto_unseal != 0)
        {
            command += " --auto-unseal";
        }
        PROCESS_INFORMATION process_info{};
        const BOOL started = CreateProcessA(
            executable_path,
            command.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startup,
            &process_info);
        CloseHandle(child_input);
        CloseHandle(child_output);
        if (!started)
        {
            CloseHandle(parent_input);
            CloseHandle(parent_output);
            return nullptr;
        }

        CloseHandle(process_info.hThread);
        client->process = process_info.hProcess;
        client->input = parent_input;
        client->output = parent_output;
#else
        int sockets[2]{};
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        {
            return nullptr;
        }
        const pid_t child = fork();
        if (child < 0)
        {
            close(sockets[0]);
            close(sockets[1]);
            return nullptr;
        }
        if (child == 0)
        {
            close(sockets[0]);
            if (dup2(sockets[1], STDIN_FILENO) < 0 ||
                dup2(sockets[1], STDOUT_FILENO) < 0)
            {
                _exit(127);
            }
            close(sockets[1]);
            if (auto_unseal != 0)
            {
                execl(
                    executable_path,
                    executable_path,
                    "--data-dir",
                    data_dir,
                    "--broker",
                    "--auto-unseal",
                    static_cast<char*>(nullptr));
            }
            else
            {
                execl(
                    executable_path,
                    executable_path,
                    "--data-dir",
                    data_dir,
                    "--broker",
                    static_cast<char*>(nullptr));
            }
            _exit(127);
        }
        close(sockets[1]);
        client->process = child;
        client->socket = sockets[0];
#endif
        return client.release();
    }
    catch (...)
    {
        return nullptr;
    }
}

VV_API void vv_daemon_client_close(VoidVaultDaemonClient* client)
{
    if (client == nullptr)
    {
        return;
    }
    std::string response;
    (void)daemonRequest(*client, "QUIT", response);
#ifdef _WIN32
    if (client->input != nullptr)
    {
        CloseHandle(client->input);
    }
    if (client->output != nullptr)
    {
        CloseHandle(client->output);
    }
    if (client->process != nullptr)
    {
        if (WaitForSingleObject(client->process, 5000) == WAIT_TIMEOUT)
        {
            TerminateProcess(client->process, 1);
            (void)WaitForSingleObject(client->process, 5000);
        }
        CloseHandle(client->process);
    }
#else
    if (client->socket >= 0)
    {
        close(client->socket);
    }
    if (client->process > 0)
    {
        int status = 0;
        while (waitpid(client->process, &status, 0) < 0 && errno == EINTR)
        {
        }
    }
#endif
    delete client;
}

VV_API int vv_daemon_client_setup(
    VoidVaultDaemonClient* client,
    const char* master_password)
{
    if (client == nullptr || master_password == nullptr)
    {
        return 0;
    }
    try
    {
        const std::string_view password(master_password);
        std::string password_hex = encodeHexBytes(password.data(), password.size());
        std::string response;
        std::string request = "SETUP " + password_hex;
        const bool ok = daemonRequest(*client, request, response);
        sodium_memzero(request.data(), request.size());
        if (password_hex != "-")
        {
            sodium_memzero(password_hex.data(), password_hex.size());
        }
        return ok && response == "initialized" ? 1 : 0;
    }
    catch (...)
    {
        return 0;
    }
}

VV_API int vv_daemon_client_unlock(
    VoidVaultDaemonClient* client,
    const char* master_password)
{
    if (client == nullptr || master_password == nullptr)
    {
        return 0;
    }
    try
    {
        const std::string_view password(master_password);
        std::string password_hex = encodeHexBytes(password.data(), password.size());
        std::string response;
        std::string request = "UNLOCK " + password_hex;
        const bool ok = daemonRequest(*client, request, response);
        sodium_memzero(request.data(), request.size());
        if (!password_hex.empty() && password_hex != "-")
        {
            sodium_memzero(password_hex.data(), password_hex.size());
        }
        return ok && response == "unlocked" ? 1 : 0;
    }
    catch (...)
    {
        return 0;
    }
}

VV_API int vv_daemon_client_enable_auto_unseal(
    VoidVaultDaemonClient* client,
    const char* current_password)
{
    if (client == nullptr || current_password == nullptr)
    {
        return 0;
    }
    try
    {
        const std::string_view password(current_password);
        std::string password_hex = encodeHexBytes(password.data(), password.size());
        std::string response;
        std::string request = "ENABLE_AUTO_UNSEAL " + password_hex;
        const bool ok = daemonRequest(*client, request, response);
        sodium_memzero(request.data(), request.size());
        if (password_hex != "-")
        {
            sodium_memzero(password_hex.data(), password_hex.size());
        }
        return ok && response == "auto_unseal_enabled" ? 1 : 0;
    }
    catch (...)
    {
        return 0;
    }
}

VV_API int vv_daemon_client_disable_auto_unseal(VoidVaultDaemonClient* client)
{
    if (client == nullptr)
    {
        return 0;
    }
    std::string response;
    return daemonRequest(*client, "DISABLE_AUTO_UNSEAL", response) &&
                   response == "auto_unseal_disabled"
        ? 1
        : 0;
}

VV_API int vv_daemon_client_issue_token(
    VoidVaultDaemonClient* client,
    const char* app_id,
    const char* scope,
    uint64_t ttl_seconds,
    char* out_token_buf,
    size_t out_token_buf_size)
{
    if (client == nullptr || app_id == nullptr || scope == nullptr)
    {
        return 0;
    }
    try
    {
        std::string response;
        const std::string request = std::string("ISSUE_TOKEN ") + app_id + " " +
                                    scope + " " + std::to_string(ttl_seconds);
        if (!daemonRequest(*client, request, response))
        {
            return 0;
        }
        return copyOutString(response, out_token_buf, out_token_buf_size);
    }
    catch (...)
    {
        return 0;
    }
}

namespace
{
    int daemonTransit(
        VoidVaultDaemonClient* client,
        const char* command,
        const char* token,
        const char* app_id,
        const char* key_id,
        const void* input,
        std::size_t input_size,
        void* output,
        std::size_t output_size,
        std::size_t* output_written)
    {
        if (output_written != nullptr)
        {
            *output_written = 0;
        }
        if (client == nullptr || token == nullptr || app_id == nullptr ||
            key_id == nullptr || output_written == nullptr ||
            (input == nullptr && input_size != 0) ||
            input_size > TransitEngine::MAX_MESSAGE_SIZE + 64)
        {
            return 0;
        }
        try
        {
            std::string input_hex = encodeHexBytes(input, input_size);
            std::string response;
            std::string request = std::string(command) + " " + token + " " +
                                  app_id + " " + key_id + " " + input_hex;
            const bool requested = daemonRequest(*client, request, response);
            sodium_memzero(request.data(), request.size());
            if (!input_hex.empty() && input_hex != "-")
            {
                sodium_memzero(input_hex.data(), input_hex.size());
            }
            if (!requested)
            {
                return 0;
            }

            std::string binary;
            const bool decoded = decodeHexBytes(response, binary);
            if (!response.empty())
            {
                sodium_memzero(response.data(), response.size());
            }
            if (!decoded)
            {
                return 0;
            }
            *output_written = binary.size();
            if (binary.size() > output_size || (output == nullptr && !binary.empty()))
            {
                if (!binary.empty())
                {
                    sodium_memzero(binary.data(), binary.size());
                }
                return 0;
            }
            if (!binary.empty())
            {
                std::memcpy(output, binary.data(), binary.size());
                sodium_memzero(binary.data(), binary.size());
            }
            return 1;
        }
        catch (...)
        {
            return 0;
        }
    }
}

VV_API int vv_daemon_transit_encrypt(
    VoidVaultDaemonClient* client,
    const char* token,
    const char* app_id,
    const char* key_id,
    const void* plaintext,
    size_t plaintext_size,
    void* out_ciphertext,
    size_t out_ciphertext_size,
    size_t* out_ciphertext_written)
{
    return daemonTransit(
        client, "TRANSIT_ENCRYPT", token, app_id, key_id,
        plaintext, plaintext_size, out_ciphertext, out_ciphertext_size,
        out_ciphertext_written);
}

VV_API int vv_daemon_transit_decrypt(
    VoidVaultDaemonClient* client,
    const char* token,
    const char* app_id,
    const char* key_id,
    const void* ciphertext,
    size_t ciphertext_size,
    void* out_plaintext,
    size_t out_plaintext_size,
    size_t* out_plaintext_written)
{
    return daemonTransit(
        client, "TRANSIT_DECRYPT", token, app_id, key_id,
        ciphertext, ciphertext_size, out_plaintext, out_plaintext_size,
        out_plaintext_written);
}

VV_API VoidVaultHandle* vv_open(const char* auth_file_path, const char* data_file_path)
{
    if (auth_file_path == nullptr || data_file_path == nullptr)
    {
        return nullptr;
    }
    const std::string audit_path = std::string(data_file_path) + ".audit.log";
    return vv_open_with_audit(auth_file_path, data_file_path, audit_path.c_str());
}

VV_API VoidVaultHandle* vv_open_with_audit(
    const char* auth_file_path,
    const char* data_file_path,
    const char* audit_log_path)
{
    if (auth_file_path == nullptr || data_file_path == nullptr)
    {
        return nullptr;
    }
    try
    {
        const std::string audit = (audit_log_path != nullptr) ? std::string(audit_log_path) : std::string();
        return new VoidVaultHandle(auth_file_path, data_file_path, audit);
    }
    catch (...)
    {
        return nullptr;
    }
}

VV_API void vv_close(VoidVaultHandle* handle)
{
    delete handle;
}

VV_API int vv_is_initialized(const VoidVaultHandle* handle)
{
    if (handle == nullptr)
    {
        return 0;
    }
    return handle->authorizer.isInitialized() ? 1 : 0;
}

VV_API int vv_is_unlocked(const VoidVaultHandle* handle)
{
    if (handle == nullptr)
    {
        return 0;
    }
    return handle->vault.isUnlocked() ? 1 : 0;
}

VV_API int vv_setup_password(VoidVaultHandle* handle, const char* new_password)
{
    if (handle == nullptr || new_password == nullptr)
    {
        return 0;
    }
    if (!handle->vault.canDecryptExistingData(new_password))
    {
        return 0;
    }
    return handle->authorizer.setPassword(new_password) ? 1 : 0;
}

VV_API int vv_unlock(VoidVaultHandle* handle, const char* password)
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

VV_API void vv_lock(VoidVaultHandle* handle)
{
    if (handle != nullptr)
    {
        handle->vault.lock();
    }
}

VV_API int vv_enable_auto_unseal(VoidVaultHandle* handle, const char* current_password)
{
    if (handle == nullptr || current_password == nullptr)
    {
        return 0;
    }
    return handle->vault.enableAutoUnseal(current_password) ? 1 : 0;
}

VV_API int vv_disable_auto_unseal(VoidVaultHandle* handle)
{
    if (handle == nullptr)
    {
        return 0;
    }
    return handle->vault.disableAutoUnseal() ? 1 : 0;
}

VV_API int vv_auto_unseal(VoidVaultHandle* handle)
{
    if (handle == nullptr)
    {
        return 0;
    }
    return handle->vault.autoUnseal() ? 1 : 0;
}

VV_API int vv_set_secret(VoidVaultHandle* handle, const char* key, const char* value)
{
    if (handle == nullptr || key == nullptr || value == nullptr)
    {
        return 0;
    }
    return handle->broker.setSecret(key, value) ? 1 : 0;
}

VV_API int vv_get_secret(
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

VV_API int vv_delete_secret(VoidVaultHandle* handle, const char* key)
{
    if (handle == nullptr || key == nullptr)
    {
        return 0;
    }
    return handle->broker.deleteSecret(key) ? 1 : 0;
}

VV_API int vv_set_ephemeral_secret(
    VoidVaultHandle* handle,
    const char* key,
    const char* value,
    uint64_t ttl_seconds)
{
    if (handle == nullptr || key == nullptr || value == nullptr)
    {
        return 0;
    }
    return handle->broker.setEphemeralSecret(key, value, ttl_seconds) ? 1 : 0;
}

VV_API int vv_get_ephemeral_secret(
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
    if (!handle->broker.getEphemeralSecret(key, val))
    {
        return 0;
    }
    return copyOutString(val, out_buf, out_buf_size);
}

VV_API int vv_delete_ephemeral_secret(VoidVaultHandle* handle, const char* key)
{
    if (handle == nullptr || key == nullptr)
    {
        return 0;
    }
    return handle->broker.deleteEphemeralSecret(key) ? 1 : 0;
}

VV_API int vv_derive_ephemeral_key(
    VoidVaultHandle* handle,
    const char* key,
    uint64_t subkey_id,
    char* out_hex_buf,
    size_t out_hex_buf_size)
{
    if (handle == nullptr || key == nullptr)
    {
        return 0;
    }
    std::string key_hex;
    if (!handle->broker.deriveEphemeralKey(key, subkey_id, key_hex))
    {
        return 0;
    }
    const int copied = copyOutString(key_hex, out_hex_buf, out_hex_buf_size);
    if (!key_hex.empty())
    {
        sodium_memzero(key_hex.data(), key_hex.size());
    }
    return copied;
}

VV_API int vv_list_keys(
    VoidVaultHandle* handle,
    char* out_csv_buf,
    size_t out_buf_size)
{
    if (handle == nullptr)
    {
        return 0;
    }
    std::vector<std::string> keys;
    if (!handle->broker.listKeys(keys))
    {
        return 0;
    }
    std::string csv;
    for (std::size_t i = 0; i < keys.size(); ++i)
    {
        if (i > 0)
        {
            csv.push_back(',');
        }
        csv.append(keys[i]);
    }
    return copyOutString(csv, out_csv_buf, out_buf_size);
}

VV_API int vv_issue_token(
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

VV_API int vv_verify_token(
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

VV_API int vv_revoke_app_tokens(VoidVaultHandle* handle, const char* app_id)
{
    if (handle == nullptr || app_id == nullptr)
    {
        return 0;
    }
    return handle->broker.revokeAppTokens(app_id) ? 1 : 0;
}

VV_API int vv_revoke_all_tokens(VoidVaultHandle* handle)
{
    if (handle == nullptr)
    {
        return 0;
    }
    return handle->broker.revokeAllTokens() ? 1 : 0;
}

VV_API int vv_get_secret_with_token(
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

VV_API int vv_set_secret_with_token(
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

VV_API int vv_derive_app_key(
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

VV_API int vv_generate_recovery_key(
    VoidVaultHandle* handle,
    char* out_key_buf,
    size_t out_key_buf_size)
{
    if (handle == nullptr)
    {
        return 0;
    }
    std::string key;
    if (!handle->vault.generateRecoveryKey(key))
    {
        return 0;
    }
    return copyOutString(key, out_key_buf, out_key_buf_size);
}

VV_API int vv_recover_with_emergency_key(
    VoidVaultHandle* handle,
    const char* recovery_key,
    const char* new_password)
{
    if (handle == nullptr || recovery_key == nullptr || new_password == nullptr)
    {
        return 0;
    }
    return handle->vault.recoverWithEmergencyKey(recovery_key, new_password) ? 1 : 0;
}

VV_API int vv_verify_audit_log(
    const char* audit_log_path,
    size_t* out_entry_count,
    size_t* out_failed_line)
{
    if (audit_log_path == nullptr)
    {
        return 0;
    }
    try
    {
        AuditLog log(audit_log_path);
        return log.verify(out_entry_count, out_failed_line) ? 1 : 0;
    }
    catch (...)
    {
        return 0;
    }
}

} // extern "C"
