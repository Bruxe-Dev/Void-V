#include "void_vault_c.h"

#include <array>
#include <cstring>
#include <string>

#include "test_util.hpp"

using tu::check;

int main(int argc, char** argv)
{
    std::cout << "=== Daemon C ABI Transit Tests ===\n";
    if (argc != 2)
    {
        std::cerr << "Expected path to the void_vault executable\n";
        return 2;
    }

    tu::TempDir dir("daemon_client");
    VoidVaultDaemonClient* client = vv_daemon_client_open(
        argv[1], dir.path().string().c_str(), 0);
    check(client != nullptr, "C ABI starts a separate broker process");
    if (client == nullptr)
    {
        return tu::finish("daemon_client");
    }

    constexpr char PASSWORD[] = "DaemonClientPassword123!";
    check(vv_daemon_client_setup(client, PASSWORD) == 1,
          "C ABI initializes the daemon vault");
    check(vv_daemon_client_unlock(client, PASSWORD) == 1,
          "C ABI unlocks the daemon vault");

    std::array<char, 512> token{};
    check(vv_daemon_client_issue_token(
              client,
              "transit-test",
              "transit:*",
              300,
              token.data(),
              token.size()) == 1,
          "C ABI issues a Transit-scoped capability");

    const std::string plaintext("payload\0with-binary", 19);
    std::array<unsigned char, 128> ciphertext{};
    std::size_t ciphertext_size = 0;
    check(vv_daemon_transit_encrypt(
              client,
              token.data(),
              "transit-test",
              "test-key",
              plaintext.data(),
              plaintext.size(),
              ciphertext.data(),
              ciphertext.size(),
              &ciphertext_size) == 1,
          "Plaintext is encrypted by the separate daemon");

    std::array<char, 64> recovered{};
    std::size_t recovered_size = 0;
    check(vv_daemon_transit_decrypt(
              client,
              token.data(),
              "transit-test",
              "test-key",
              ciphertext.data(),
              ciphertext_size,
              recovered.data(),
              recovered.size(),
              &recovered_size) == 1 &&
              recovered_size == plaintext.size() &&
              std::memcmp(recovered.data(), plaintext.data(), plaintext.size()) == 0,
          "C ABI receives the original binary plaintext after daemon decryption");

    check(vv_daemon_transit_decrypt(
              client,
              token.data(),
              "transit-test",
              "wrong-key",
              ciphertext.data(),
              ciphertext_size,
              recovered.data(),
              recovered.size(),
              &recovered_size) == 0,
          "Daemon rejects ciphertext with the wrong Transit key identifier");

    vv_daemon_client_close(client);
    return tu::finish("daemon_client");
}
