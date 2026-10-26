#ifndef VOID_VAULT_OPERATION_ENGINE_HPP
#define VOID_VAULT_OPERATION_ENGINE_HPP

#include <array>
#include <cstddef>
#include <string_view>

enum class EngineKind
{
    KeyValue,
    Transit,
    Pki
};

class OperationEngine
{
public:
    virtual ~OperationEngine() = default;
    virtual EngineKind kind() const noexcept = 0;
    virtual bool supportsOperation(std::string_view operation) const noexcept = 0;
};

class EngineRouter
{
public:
    static constexpr std::size_t ENGINE_COUNT = 3;

    bool registerEngine(OperationEngine& engine) noexcept
    {
        const std::size_t index = static_cast<std::size_t>(engine.kind());
        if (index >= engines_.size() || engines_[index] != nullptr)
        {
            return false;
        }
        engines_[index] = &engine;
        return true;
    }

    OperationEngine* route(std::string_view operation) const noexcept
    {
        for (OperationEngine* engine : engines_)
        {
            if (engine != nullptr && engine->supportsOperation(operation))
            {
                return engine;
            }
        }
        return nullptr;
    }

private:
    std::array<OperationEngine*, ENGINE_COUNT> engines_{};
};

#endif
