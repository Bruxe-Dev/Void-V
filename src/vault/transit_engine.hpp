#ifndef VOID_VAULT_TRANSIT_ENGINE_HPP
#define VOID_VAULT_TRANSIT_ENGINE_HPP

#include <string>
#include <string_view>

#include "operation_engine.hpp"

class TransitEngine : public OperationEngine
{
public:
    static constexpr std::size_t MAX_MESSAGE_SIZE = 16U * 1024U;

    EngineKind kind() const noexcept override { return EngineKind::Transit; }
    bool supportsOperation(std::string_view operation) const noexcept override;

    bool encrypt(
        const unsigned char root_key[32],
        std::string_view key_id,
        std::string_view plaintext,
        std::string& out_ciphertext) const;

    bool decrypt(
        const unsigned char root_key[32],
        std::string_view key_id,
        std::string_view ciphertext,
        std::string& out_plaintext) const;
};

#endif
