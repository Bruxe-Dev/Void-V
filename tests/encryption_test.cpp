#include "security/encryption.hpp"
#include "security/secure_buffer.hpp"

#include <string>

#include "test_util.hpp"

using tu::check;

int main()
{
    std::cout << "=== Encryption Tests ===\n";
    Encryption encryption;

    const std::string password = "TestPassword123!";
    const std::string original = "Void Vault secret data";

    std::string encrypted;
    std::string decrypted;

    const bool enc_ok = encryption.encrypt(original, password, encrypted);
    check(enc_ok, "Encrypt succeeds");
    check(encrypted.size() == 4 + 16 + 24 + 16 + original.size(), "Record size = header + MAC + plaintext");
    check(encrypted.compare(0, 4, "VV02") == 0, "Default AEAD record uses VV02 header");
    check(encrypted.find(original) == std::string::npos, "Ciphertext does not contain plaintext");
    check(encryption.decrypt(encrypted, password, decrypted) && decrypted == original, "Round trip");

    std::string again;
    check(encryption.encrypt(original, password, again) && again != encrypted,
          "Two encryptions differ (random salt/nonce)");

    std::string result = "unchanged";
    check(!encryption.decrypt(encrypted, "IncorrectPassword!", result), "Wrong password rejected");
    check(result == "unchanged", "Failed decrypt leaves output unchanged");

    // Tamper with a sample of positions covering magic, salt, nonce, MAC, ciphertext.
    if (enc_ok)
    {
        const std::size_t positions[] = {0, 3, 4, 19, 20, 43, 44, 59, 60, encrypted.size() - 1};
        bool all_rejected = true;
        for (std::size_t pos : positions)
        {
            std::string modified = encrypted;
            modified[pos] = static_cast<char>(modified[pos] ^ 0x01);
            std::string out = "unchanged";
            if (encryption.decrypt(modified, password, out) || out != "unchanged")
            {
                all_rejected = false;
            }
        }
        check(all_rejected, "Tampering anywhere (magic/salt/nonce/MAC/ciphertext) rejected");

        // Header downgrade attack: changing VV02 -> VV01 with same salt/nonce/ciphertext is rejected.
        std::string downgraded = encrypted;
        downgraded[3] = '1';
        std::string downgrade_out = "unchanged";
        check(!encryption.decrypt(downgraded, password, downgrade_out) && downgrade_out == "unchanged",
              "Header version downgrade attack rejected by AEAD AAD");

        bool truncated_rejected = true;
        for (std::size_t len : {std::size_t{0}, std::size_t{3}, std::size_t{4}, std::size_t{44},
                                std::size_t{59}, encrypted.size() - 1})
        {
            std::string out = "unchanged";
            if (encryption.decrypt(encrypted.substr(0, len), password, out) || out != "unchanged")
            {
                truncated_rejected = false;
            }
        }
        check(truncated_rejected, "Truncated records rejected");

        std::string extended = encrypted + "X";
        check(!encryption.decrypt(extended, password, result), "Appended bytes rejected");
    }

    // Legacy VV01 backward-compatibility round-trip test.
    {
        std::string legacy_v1;
        std::string legacy_dec;
        check(encryption.encryptLegacyV1(original, password, legacy_v1) &&
                  legacy_v1.compare(0, 4, "VV01") == 0,
              "Legacy VV01 record generated");
        check(encryption.decrypt(legacy_v1, password, legacy_dec) && legacy_dec == original,
              "Legacy VV01 record decrypts transparently");
    }

    // Moderate KDF profile self-describing header round-trip test.
    {
        Encryption mod_enc(KdfProfile::Moderate);
        std::string mod_cipher, mod_plain;
        check(mod_enc.encrypt(original, password, mod_cipher) &&
                  mod_cipher.compare(0, 4, "VV2M") == 0,
              "Moderate KDF profile encodes VV2M header");
        check(encryption.decrypt(mod_cipher, password, mod_plain) && mod_plain == original,
              "Default Encryption instance auto-detects and decrypts VV2M record");
    }

    // SecureBuffer incremental push_back/pop_back/constantTimeEquals test.
    {
        SecureBuffer sb1, sb2;
        for (char c : std::string_view("SecretPass123!"))
        {
            check(sb1.push_back(c), "SecureBuffer push_back");
        }
        sb1.push_back('X');
        sb1.pop_back();
        sb2.assign("SecretPass123!");
        check(sb1.constantTimeEquals(sb2), "SecureBuffer constantTimeEquals matches identical content");
        check(!sb1.constantTimeEquals("DifferentPass1!"), "SecureBuffer constantTimeEquals rejects different content");
    }

    check(!encryption.decrypt("VV01", password, result), "Header-only record rejected");
    check(!encryption.decrypt(std::string(80, 'Z'), password, result), "Wrong magic rejected");

    std::string empty_enc;
    check(!encryption.encrypt(original, "", empty_enc) && empty_enc.empty(), "Empty password rejected for encrypt");
    check(!encryption.decrypt(encrypted, "", result), "Empty password rejected for decrypt");

    std::string empty_pt_enc, empty_pt = "x";
    check(encryption.encrypt("", password, empty_pt_enc) &&
              encryption.decrypt(empty_pt_enc, password, empty_pt) && empty_pt.empty(),
          "Empty plaintext round trip");

    const std::string binary("\0\x01\xff\0secret\0", 11);
    std::string bin_enc, bin_dec;
    check(encryption.encrypt(binary, password, bin_enc) &&
              encryption.decrypt(bin_enc, password, bin_dec) && bin_dec == binary,
          "Binary plaintext with NULs round trip");

    const std::string large(1 << 20, 'L');
    std::string large_enc, large_dec;
    check(encryption.encrypt(large, password, large_enc) &&
              encryption.decrypt(large_enc, password, large_dec) && large_dec == large,
          "1 MiB plaintext round trip");

    const std::string unicode_pw = "p\xC3\xA4ssw\xC3\xB6rd-\xE2\x82\xAC-123";
    std::string u_enc, u_dec;
    check(encryption.encrypt(original, unicode_pw, u_enc) &&
              encryption.decrypt(u_enc, unicode_pw, u_dec) && u_dec == original,
          "UTF-8 password round trip");

    return tu::finish("encryption");
}