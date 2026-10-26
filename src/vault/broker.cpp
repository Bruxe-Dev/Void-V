#include "broker.hpp"

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>

namespace
{
    constexpr char KV_MAGIC[] = "VVKV1";
    constexpr std::size_t KV_MAGIC_SIZE = 5;
    constexpr char TOKEN_PREFIX[] = "VVTOK1.";
    constexpr std::size_t TOKEN_PREFIX_SIZE = 7;
    constexpr char INTERNAL_BROKER_KEY_NAME[] = "__vv_internal_broker_key__";
    constexpr char INTERNAL_APP_GEN_PREFIX[] = "__vv_app_gen_";
    constexpr char LEGACY_RAW_KEY_NAME[] = "default";

    std::uint64_t currentUnixTime() noexcept
    {
        const auto now = std::chrono::system_clock::now();
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        return secs > 0 ? static_cast<std::uint64_t>(secs) : 0ULL;
    }

    void writeU32(std::string &out, std::uint32_t v)
    {
        const char bytes[4] = {
            static_cast<char>((v >> 24) & 0xFFU),
            static_cast<char>((v >> 16) & 0xFFU),
            static_cast<char>((v >> 8) & 0xFFU),
            static_cast<char>(v & 0xFFU),
        };
        out.append(bytes, 4);
    }

    bool readU32(std::string_view in, std::size_t &offset, std::uint32_t &out) noexcept
    {
        if (offset + 4 > in.size())
        {
            return false;
        }
        const auto b0 = static_cast<std::uint32_t>(static_cast<unsigned char>(in[offset]));
        const auto b1 = static_cast<std::uint32_t>(static_cast<unsigned char>(in[offset + 1]));
        const auto b2 = static_cast<std::uint32_t>(static_cast<unsigned char>(in[offset + 2]));
        const auto b3 = static_cast<std::uint32_t>(static_cast<unsigned char>(in[offset + 3]));
        out = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        offset += 4;
        return true;
    }

    void writeU64(std::string &out, std::uint64_t v)
    {
        writeU32(out, static_cast<std::uint32_t>((v >> 32) & 0xFFFFFFFFULL));
        writeU32(out, static_cast<std::uint32_t>(v & 0xFFFFFFFFULL));
    }

    bool readU64(std::string_view in, std::size_t &offset, std::uint64_t &out) noexcept
    {
        std::uint32_t hi = 0;
        std::uint32_t lo = 0;
        if (!readU32(in, offset, hi) || !readU32(in, offset, lo))
        {
            return false;
        }
        out = (static_cast<std::uint64_t>(hi) << 32) | static_cast<std::uint64_t>(lo);
        return true;
    }

    std::string toHex(const unsigned char *data, std::size_t len)
    {
        std::string hex(len * 2 + 1, '\0');
        sodium_bin2hex(hex.data(), hex.size(), data, len);
        hex.resize(len * 2);
        return hex;
    }

    bool fromHex(std::string_view hex, std::string &out_bin)
    {
        if (hex.empty() || (hex.size() % 2) != 0)
        {
            return false;
        }
        std::string bin(hex.size() / 2, '\0');
        std::size_t bin_len = 0;
        if (sodium_hex2bin(
                reinterpret_cast<unsigned char *>(bin.data()),
                bin.size(),
                hex.data(),
                hex.size(),
                nullptr,
                &bin_len,
                nullptr) != 0 ||
            bin_len != bin.size())
        {
            return false;
        }
        out_bin = std::move(bin);
        return true;
    }

    void wipeString(std::string &s) noexcept
    {
        if (!s.empty())
        {
            sodium_memzero(s.data(), s.size());
            s.clear();
        }
    }

    bool isSafeIdentifier(std::string_view s) noexcept
    {
        if (s.empty() || s.size() > VaultBroker::MAX_KEY_LENGTH)
        {
            return false;
        }
        for (char c : s)
        {
            const auto uc = static_cast<unsigned char>(c);
            if (uc <= 0x20U || uc >= 0x7FU)
            {
                return false;
            }
        }
        return true;
    }

    std::string appGenKey(std::string_view app_id)
    {
        std::string k(INTERNAL_APP_GEN_PREFIX);
        k.append(app_id.data(), app_id.size());
        return k;
    }

    // Derives the HMAC signing key for a specific (app_id, app_generation) pair.
    bool deriveAppSigningKey(
        const unsigned char master_key[32],
        std::string_view app_id,
        std::string_view app_gen,
        unsigned char out_sign_key[crypto_auth_hmacsha512256_KEYBYTES])
    {
        unsigned char root_sign[crypto_auth_hmacsha512256_KEYBYTES]{};
        if (crypto_kdf_derive_from_key(
                root_sign,
                sizeof(root_sign),
                1ULL,
                "VVTOKENS",
                master_key) != 0)
        {
            return false;
        }
        std::string ctx;
        ctx.reserve(app_id.size() + app_gen.size() + 2);
        ctx.append(app_id.data(), app_id.size());
        ctx.push_back(':');
        ctx.append(app_gen.data(), app_gen.size());

        crypto_auth_hmacsha512256(
            out_sign_key,
            reinterpret_cast<const unsigned char *>(ctx.data()),
            ctx.size(),
            root_sign);
        sodium_memzero(root_sign, sizeof(root_sign));
        return true;
    }
}

VaultBroker::VaultBroker(Vault &vault)
    : vault_(vault)
{
    expiry_thread_ = std::thread(&VaultBroker::runExpiryWorker, this);
}

VaultBroker::~VaultBroker()
{
    {
        std::lock_guard<std::mutex> lock(ephemeral_mutex_);
        stop_expiry_thread_ = true;
    }
    ephemeral_cv_.notify_one();
    if (expiry_thread_.joinable())
    {
        expiry_thread_.join();
    }
}

void VaultBroker::recordAudit(std::string_view event, std::string_view actor, std::string_view target)
{
    if (vault_.auditLog() != nullptr)
    {
        (void)vault_.auditLog()->append(event, actor, target);
    }
}

bool VaultBroker::isValidKeyName(std::string_view key) noexcept
{
    if (!isSafeIdentifier(key))
    {
        return false;
    }
    // Reserved internal prefix
    if (key.rfind("__vv_", 0) == 0)
    {
        return false;
    }
    return true;
}

bool VaultBroker::scopeAllowsRead(std::string_view scope, std::string_view key) noexcept
{
    if (!isValidKeyName(key))
    {
        return false;
    }
    if (scope == "*" || scope == "read:*")
    {
        return true;
    }
    if (scope.rfind("key:", 0) == 0)
    {
        return scope.substr(4) == key;
    }
    if (scope.rfind("read_key:", 0) == 0)
    {
        return scope.substr(9) == key;
    }
    if (scope.rfind("read:", 0) == 0 && scope.back() == '*')
    {
        const std::string_view prefix = scope.substr(5, scope.size() - 6);
        return !prefix.empty() && key.rfind(prefix, 0) == 0;
    }
    if (scope.rfind("write:", 0) == 0 && scope.back() == '*')
    {
        const std::string_view prefix = scope.substr(6, scope.size() - 7);
        return !prefix.empty() && key.rfind(prefix, 0) == 0;
    }
    return false;
}

bool VaultBroker::scopeAllowsWrite(std::string_view scope, std::string_view key) noexcept
{
    if (!isValidKeyName(key))
    {
        return false;
    }
    if (scope == "*")
    {
        return true;
    }
    if (scope.rfind("key:", 0) == 0)
    {
        return scope.substr(4) == key;
    }
    if (scope.rfind("write:", 0) == 0 && scope.back() == '*')
    {
        const std::string_view prefix = scope.substr(6, scope.size() - 7);
        return !prefix.empty() && key.rfind(prefix, 0) == 0;
    }
    return false;
}

bool VaultBroker::loadStore(
    std::vector<KeyValue> &entries,
    unsigned char master_key[32],
    bool &has_master_key)
{
    entries.clear();
    has_master_key = false;
    sodium_memzero(master_key, 32);

    (void)vault_.checkIdleTimeout();
    if (!vault_.isUnlocked())
    {
        return false;
    }

    std::string raw;
    if (!vault_.loadData(raw))
    {
        if (vault_.lastError() == VaultError::NoData)
        {
            return true;
        }
        return false;
    }

    if (raw.empty())
    {
        return true;
    }

    // Backward compatibility: if the vault currently holds a single raw string
    // (not starting with VVKV1), preserve it under the "default" key.
    if (raw.size() < KV_MAGIC_SIZE || raw.compare(0, KV_MAGIC_SIZE, KV_MAGIC) != 0)
    {
        entries.push_back(KeyValue{LEGACY_RAW_KEY_NAME, raw});
        wipeString(raw);
        return true;
    }

    std::size_t offset = KV_MAGIC_SIZE;
    std::uint32_t count = 0;
    if (!readU32(raw, offset, count) || count > 10000U)
    {
        wipeString(raw);
        return false;
    }

    for (std::uint32_t i = 0; i < count; ++i)
    {
        std::uint32_t klen = 0;
        if (!readU32(raw, offset, klen) || offset + klen > raw.size())
        {
            wipeString(raw);
            return false;
        }
        std::string k(raw.data() + offset, klen);
        offset += klen;

        std::uint32_t vlen = 0;
        if (!readU32(raw, offset, vlen) || offset + vlen > raw.size())
        {
            wipeString(raw);
            return false;
        }
        std::string v(raw.data() + offset, vlen);
        offset += vlen;

        if (k == INTERNAL_BROKER_KEY_NAME)
        {
            if (v.size() == 32)
            {
                std::memcpy(master_key, v.data(), 32);
                has_master_key = true;
            }
            wipeString(v);
        }
        else
        {
            entries.push_back(KeyValue{std::move(k), std::move(v)});
        }
    }

    const bool ok = (offset == raw.size());
    wipeString(raw);
    return ok;
}

bool VaultBroker::saveStore(
    const std::vector<KeyValue> &entries,
    const unsigned char master_key[32])
{
    std::string serialized;
    serialized.append(KV_MAGIC, KV_MAGIC_SIZE);

    const auto total_count = static_cast<std::uint32_t>(entries.size() + 1);
    writeU32(serialized, total_count);

    // Always store the 32-byte internal broker key as the first entry.
    const std::string_view bkey_name(INTERNAL_BROKER_KEY_NAME);
    writeU32(serialized, static_cast<std::uint32_t>(bkey_name.size()));
    serialized.append(bkey_name.data(), bkey_name.size());
    writeU32(serialized, 32U);
    serialized.append(reinterpret_cast<const char *>(master_key), 32);

    for (const auto &kv : entries)
    {
        writeU32(serialized, static_cast<std::uint32_t>(kv.key.size()));
        serialized.append(kv.key);
        writeU32(serialized, static_cast<std::uint32_t>(kv.value.size()));
        serialized.append(kv.value);
    }

    const bool ok = vault_.saveData(serialized);
    wipeString(serialized);
    return ok;
}

bool VaultBroker::ensureBrokerKey(
    std::vector<KeyValue> &entries,
    unsigned char master_key[32])
{
    bool has_key = false;
    if (!loadStore(entries, master_key, has_key))
    {
        return false;
    }
    if (!has_key)
    {
        randombytes_buf(master_key, 32);
        if (!saveStore(entries, master_key))
        {
            sodium_memzero(master_key, 32);
            return false;
        }
    }
    return true;
}

bool VaultBroker::setSecret(std::string_view key, std::string_view value)
{
    if (!isValidKeyName(key))
    {
        return false;
    }
    std::vector<KeyValue> entries;
    unsigned char master_key[32]{};
    bool has_key = false;
    if (!loadStore(entries, master_key, has_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    if (!has_key)
    {
        randombytes_buf(master_key, sizeof(master_key));
    }

    bool updated = false;
    for (auto &kv : entries)
    {
        if (kv.key == key)
        {
            wipeString(kv.value);
            kv.value.assign(value.data(), value.size());
            updated = true;
            break;
        }
    }
    if (!updated)
    {
        entries.push_back(KeyValue{std::string(key), std::string(value)});
    }

    const bool ok = saveStore(entries, master_key);
    sodium_memzero(master_key, sizeof(master_key));
    for (auto &kv : entries)
    {
        wipeString(kv.value);
    }
    if (ok)
    {
        recordAudit("SECRET_SAVED", "owner", key);
    }
    return ok;
}

bool VaultBroker::getSecret(std::string_view key, std::string &out_value)
{
    if (!isValidKeyName(key))
    {
        return false;
    }
    std::vector<KeyValue> entries;
    unsigned char master_key[32]{};
    bool has_key = false;
    if (!loadStore(entries, master_key, has_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    sodium_memzero(master_key, sizeof(master_key));

    bool found = false;
    for (auto &kv : entries)
    {
        if (kv.key == key)
        {
            out_value = kv.value;
            found = true;
        }
        wipeString(kv.value);
    }
    if (found)
    {
        recordAudit("SECRET_READ", "owner", key);
    }
    return found;
}

bool VaultBroker::deleteSecret(std::string_view key)
{
    if (!isValidKeyName(key))
    {
        return false;
    }
    std::vector<KeyValue> entries;
    unsigned char master_key[32]{};
    bool has_key = false;
    if (!loadStore(entries, master_key, has_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    if (!has_key)
    {
        randombytes_buf(master_key, sizeof(master_key));
    }

    bool removed = false;
    for (auto it = entries.begin(); it != entries.end();)
    {
        if (it->key == key)
        {
            wipeString(it->value);
            it = entries.erase(it);
            removed = true;
        }
        else
        {
            ++it;
        }
    }

    const bool ok = removed && saveStore(entries, master_key);
    sodium_memzero(master_key, sizeof(master_key));
    for (auto &kv : entries)
    {
        wipeString(kv.value);
    }
    if (ok)
    {
        recordAudit("SECRET_DELETED", "owner", key);
    }
    return ok;
}

bool VaultBroker::listKeys(std::vector<std::string> &out_keys)
{
    std::vector<KeyValue> entries;
    unsigned char master_key[32]{};
    bool has_key = false;
    if (!loadStore(entries, master_key, has_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    sodium_memzero(master_key, sizeof(master_key));

    out_keys.clear();
    out_keys.reserve(entries.size());
    for (auto &kv : entries)
    {
        if (kv.key.rfind("__vv_", 0) != 0)
        {
            out_keys.push_back(kv.key);
        }
        wipeString(kv.value);
    }
    std::sort(out_keys.begin(), out_keys.end());
    return true;
}

bool VaultBroker::issueToken(
    std::string_view app_id,
    std::string_view scope,
    std::uint64_t ttl_seconds,
    std::string &out_token,
    std::uint64_t now_unix)
{
    if (!isSafeIdentifier(app_id) || !isSafeIdentifier(scope) ||
        ttl_seconds == 0 || ttl_seconds > MAX_TOKEN_TTL_SECONDS)
    {
        return false;
    }

    std::vector<KeyValue> entries;
    unsigned char master_key[32]{};
    if (!ensureBrokerKey(entries, master_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }

    std::string app_gen = "0";
    const std::string gen_key = appGenKey(app_id);
    for (auto &kv : entries)
    {
        if (kv.key == gen_key)
        {
            app_gen = kv.value;
        }
        wipeString(kv.value);
    }

    unsigned char sign_key[crypto_auth_hmacsha512256_KEYBYTES]{};
    if (!deriveAppSigningKey(master_key, app_id, app_gen, sign_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    sodium_memzero(master_key, sizeof(master_key));

    const std::uint64_t issued = now_unix != 0 ? now_unix : currentUnixTime();
    const std::uint64_t expires = issued + ttl_seconds;

    std::string payload;
    writeU64(payload, issued);
    writeU64(payload, expires);
    writeU32(payload, static_cast<std::uint32_t>(app_id.size()));
    payload.append(app_id.data(), app_id.size());
    writeU32(payload, static_cast<std::uint32_t>(scope.size()));
    payload.append(scope.data(), scope.size());

    unsigned char mac[crypto_auth_hmacsha512256_BYTES]{};
    crypto_auth_hmacsha512256(
        mac,
        reinterpret_cast<const unsigned char *>(payload.data()),
        payload.size(),
        sign_key);
    sodium_memzero(sign_key, sizeof(sign_key));

    const std::string payload_hex = toHex(
        reinterpret_cast<const unsigned char *>(payload.data()),
        payload.size());
    const std::string mac_hex = toHex(mac, sizeof(mac));
    sodium_memzero(mac, sizeof(mac));

    out_token.clear();
    out_token.append(TOKEN_PREFIX, TOKEN_PREFIX_SIZE);
    out_token.append(payload_hex);
    out_token.push_back('.');
    out_token.append(mac_hex);
    recordAudit("TOKEN_ISSUED", app_id, scope);
    return true;
}

bool VaultBroker::verifyToken(
    std::string_view token,
    std::string_view expected_app_id,
    CapabilityClaims &out_claims,
    std::uint64_t now_unix)
{
    if (token.size() <= TOKEN_PREFIX_SIZE ||
        token.compare(0, TOKEN_PREFIX_SIZE, TOKEN_PREFIX) != 0)
    {
        return false;
    }

    const std::string_view rest = token.substr(TOKEN_PREFIX_SIZE);
    const std::size_t dot = rest.find('.');
    if (dot == std::string_view::npos || dot == 0 || dot + 1 >= rest.size())
    {
        return false;
    }

    std::string payload;
    std::string mac_bin;
    if (!fromHex(rest.substr(0, dot), payload) ||
        !fromHex(rest.substr(dot + 1), mac_bin) ||
        mac_bin.size() != crypto_auth_hmacsha512256_BYTES)
    {
        return false;
    }

    std::vector<KeyValue> entries;
    unsigned char master_key[32]{};
    bool has_key = false;
    if (!loadStore(entries, master_key, has_key) || !has_key)
    {
        sodium_memzero(master_key, sizeof(master_key));
        for (auto &kv : entries)
        {
            wipeString(kv.value);
        }
        return false;
    }

    std::string app_gen = "0";
    const std::string gen_key = appGenKey(expected_app_id);
    for (auto &kv : entries)
    {
        if (kv.key == gen_key)
        {
            app_gen = kv.value;
        }
        wipeString(kv.value);
    }

    unsigned char sign_key[crypto_auth_hmacsha512256_KEYBYTES]{};
    if (!deriveAppSigningKey(master_key, expected_app_id, app_gen, sign_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    sodium_memzero(master_key, sizeof(master_key));

    const int mac_ok = crypto_auth_hmacsha512256_verify(
        reinterpret_cast<const unsigned char *>(mac_bin.data()),
        reinterpret_cast<const unsigned char *>(payload.data()),
        payload.size(),
        sign_key);
    sodium_memzero(sign_key, sizeof(sign_key));

    if (mac_ok != 0)
    {
        recordAudit("TOKEN_INVALID_MAC", expected_app_id, "verify");
        return false;
    }

    std::size_t offset = 0;
    std::uint64_t issued = 0;
    std::uint64_t expires = 0;
    std::uint32_t app_len = 0;
    std::uint32_t scope_len = 0;
    if (!readU64(payload, offset, issued) ||
        !readU64(payload, offset, expires) ||
        !readU32(payload, offset, app_len) ||
        offset + app_len > payload.size())
    {
        return false;
    }
    std::string app(payload.data() + offset, app_len);
    offset += app_len;

    if (!readU32(payload, offset, scope_len) ||
        offset + scope_len != payload.size())
    {
        return false;
    }
    std::string scope(payload.data() + offset, scope_len);

    const std::uint64_t now = now_unix != 0 ? now_unix : currentUnixTime();
    if (now > expires || app != expected_app_id)
    {
        recordAudit("TOKEN_EXPIRED_OR_MISMATCH", expected_app_id, scope);
        return false;
    }

    out_claims.issued_at = issued;
    out_claims.expires_at = expires;
    out_claims.app_id = std::move(app);
    out_claims.scope = std::move(scope);
    return true;
}

bool VaultBroker::revokeAppTokens(std::string_view app_id)
{
    if (!isSafeIdentifier(app_id))
    {
        return false;
    }

    std::vector<KeyValue> entries;
    unsigned char master_key[32]{};
    bool has_key = false;
    if (!loadStore(entries, master_key, has_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    if (!has_key)
    {
        randombytes_buf(master_key, sizeof(master_key));
    }

    const std::string gen_key = appGenKey(app_id);
    bool updated = false;
    for (auto &kv : entries)
    {
        if (kv.key == gen_key)
        {
            std::uint64_t g = 0;
            for (char c : kv.value)
            {
                if (c >= '0' && c <= '9')
                {
                    g = g * 10 + static_cast<std::uint64_t>(c - '0');
                }
            }
            kv.value = std::to_string(g + 1);
            updated = true;
            break;
        }
    }
    if (!updated)
    {
        entries.push_back(KeyValue{gen_key, "1"});
    }

    const bool ok = saveStore(entries, master_key);
    sodium_memzero(master_key, sizeof(master_key));
    for (auto &kv : entries)
    {
        wipeString(kv.value);
    }
    if (ok)
    {
        recordAudit("APP_TOKENS_REVOKED", app_id, "revoke_app");
    }
    return ok;
}

bool VaultBroker::revokeAllTokens()
{
    std::vector<KeyValue> entries;
    unsigned char master_key[32]{};
    bool has_key = false;
    if (!loadStore(entries, master_key, has_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    randombytes_buf(master_key, sizeof(master_key));
    const bool ok = saveStore(entries, master_key);
    sodium_memzero(master_key, sizeof(master_key));
    for (auto &kv : entries)
    {
        wipeString(kv.value);
    }
    if (ok)
    {
        recordAudit("ALL_TOKENS_REVOKED", "owner", "all");
    }
    return ok;
}

bool VaultBroker::getSecretWithToken(
    std::string_view token,
    std::string_view app_id,
    std::string_view key,
    std::string &out_value,
    std::uint64_t now_unix)
{
    CapabilityClaims claims;
    if (!verifyToken(token, app_id, claims, now_unix))
    {
        return false;
    }
    if (!scopeAllowsRead(claims.scope, key))
    {
        recordAudit("TOKEN_SCOPE_DENIED_READ", app_id, key);
        return false;
    }
    const bool ok = getSecret(key, out_value);
    if (ok)
    {
        recordAudit("TOKEN_SECRET_READ", app_id, key);
    }
    return ok;
}

bool VaultBroker::setSecretWithToken(
    std::string_view token,
    std::string_view app_id,
    std::string_view key,
    std::string_view value,
    std::uint64_t now_unix)
{
    CapabilityClaims claims;
    if (!verifyToken(token, app_id, claims, now_unix))
    {
        return false;
    }
    if (!scopeAllowsWrite(claims.scope, key))
    {
        recordAudit("TOKEN_SCOPE_DENIED_WRITE", app_id, key);
        return false;
    }
    const bool ok = setSecret(key, value);
    if (ok)
    {
        recordAudit("TOKEN_SECRET_WRITTEN", app_id, key);
    }
    return ok;
}

bool VaultBroker::deriveAppKey(
    std::string_view token,
    std::string_view app_id,
    std::uint64_t subkey_id,
    std::string &out_key_hex,
    std::uint64_t now_unix)
{
    CapabilityClaims claims;
    if (!verifyToken(token, app_id, claims, now_unix))
    {
        return false;
    }

    std::vector<KeyValue> entries;
    unsigned char master_key[32]{};
    if (!ensureBrokerKey(entries, master_key))
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    for (auto &kv : entries)
    {
        wipeString(kv.value);
    }

    // Step 1: Derive an intermediate master key for this app_id via HMAC-SHA512256
    unsigned char app_master[32]{};
    unsigned char kdf_root[32]{};
    if (crypto_kdf_derive_from_key(kdf_root, sizeof(kdf_root), 2ULL, "VVAPPKDF", master_key) != 0)
    {
        sodium_memzero(master_key, sizeof(master_key));
        return false;
    }
    sodium_memzero(master_key, sizeof(master_key));

    crypto_auth_hmacsha512256(
        app_master,
        reinterpret_cast<const unsigned char *>(app_id.data()),
        app_id.size(),
        kdf_root);
    sodium_memzero(kdf_root, sizeof(kdf_root));

    // Step 2: Derive the requested subkey_id from the app-isolated master key
    unsigned char derived[32]{};
    const int rc = crypto_kdf_derive_from_key(
        derived,
        sizeof(derived),
        subkey_id,
        "APPSUBKY",
        app_master);
    sodium_memzero(app_master, sizeof(app_master));
    if (rc != 0)
    {
        sodium_memzero(derived, sizeof(derived));
        return false;
    }

    out_key_hex = toHex(derived, sizeof(derived));
    sodium_memzero(derived, sizeof(derived));
    recordAudit("APP_KEY_DERIVED", app_id, std::to_string(subkey_id));
    return true;
}
void VaultBroker::purgeExpiredEphemeralSecrets(Clock::time_point now)
{
    for (auto it = ephemeral_secrets_.begin(); it != ephemeral_secrets_.end();)
    {
        if (it->second.expires_at <= now)
        {
            it->second.value.clear();
            it = ephemeral_secrets_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void VaultBroker::runExpiryWorker()
{
    std::unique_lock<std::mutex> lock(ephemeral_mutex_);
    while (!stop_expiry_thread_)
    {
        if (ephemeral_cv_.wait_for(
                lock,
                std::chrono::seconds(1),
                [this] { return stop_expiry_thread_; }))
        {
            break;
        }
        purgeExpiredEphemeralSecrets(Clock::now());
    }
}

bool VaultBroker::setEphemeralSecret(
    std::string_view key,
    std::string_view value,
    std::uint64_t ttl_seconds)
{
    if (!isValidKeyName(key) ||
        ttl_seconds == 0 ||
        ttl_seconds > MAX_EPHEMERAL_TTL_SECONDS ||
        value.size() > SecureBuffer::MAX_CAPACITY)
    {
        return false;
    }

    (void)vault_.checkIdleTimeout();
    if (!vault_.isUnlocked())
    {
        return false;
    }

    EphemeralSecret entry;
    entry.value.assign(value);
    entry.expires_at = Clock::now() +
                       std::chrono::seconds(
                           static_cast<std::chrono::seconds::rep>(ttl_seconds));

    {
        std::lock_guard<std::mutex> lock(ephemeral_mutex_);
        purgeExpiredEphemeralSecrets(Clock::now());
        ephemeral_secrets_.insert_or_assign(std::string(key), std::move(entry));
    }

    ephemeral_cv_.notify_one();
    recordAudit("EPHEMERAL_SECRET_SAVED", "owner", key);
    return true;
}

bool VaultBroker::getEphemeralSecret(
    std::string_view key,
    std::string &out_value)
{
    if (!isValidKeyName(key))
    {
        return false;
    }

    (void)vault_.checkIdleTimeout();
    if (!vault_.isUnlocked())
    {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(ephemeral_mutex_);
        purgeExpiredEphemeralSecrets(Clock::now());

        const auto it = ephemeral_secrets_.find(std::string(key));
        if (it == ephemeral_secrets_.end())
        {
            return false;
        }

        const std::string_view value = it->second.value.view();
        out_value.assign(value);
    }

    recordAudit("EPHEMERAL_SECRET_READ", "owner", key);
    return true;
}

bool VaultBroker::deleteEphemeralSecret(std::string_view key)
{
    if (!isValidKeyName(key))
    {
        return false;
    }

    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(ephemeral_mutex_);
        purgeExpiredEphemeralSecrets(Clock::now());

        const auto it = ephemeral_secrets_.find(std::string(key));
        if (it != ephemeral_secrets_.end())
        {
            it->second.value.clear();
            ephemeral_secrets_.erase(it);
            removed = true;
        }
    }

    if (removed)
    {
        recordAudit("EPHEMERAL_SECRET_DELETED", "owner", key);
    }
    return removed;
}