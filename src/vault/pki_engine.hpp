#ifndef VOID_VAULT_PKI_ENGINE_HPP
#define VOID_VAULT_PKI_ENGINE_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "operation_engine.hpp"

class PkiEngine : public OperationEngine
{
public:
    EngineKind kind() const noexcept override { return EngineKind::Pki; }
    bool supportsOperation(std::string_view operation) const noexcept override;

    bool createAuthority(
        std::string_view common_name,
        std::string& out_private_bundle,
        std::string& out_certificate) const;

    bool issueCertificate(
        std::string_view private_bundle,
        std::string_view common_name,
        std::uint64_t validity_days,
        std::string& out_certificate) const;
};

#endif
