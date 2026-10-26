#ifndef VOID_VAULT_AUTO_UNSEAL_HPP
#define VOID_VAULT_AUTO_UNSEAL_HPP

#include <string>
#include <string_view>

class AutoUnsealStore
{
public:
    static bool protectFragment(
        const std::string& vault_path,
        std::string_view fragment);
    static bool unprotectFragment(
        const std::string& vault_path,
        std::string& fragment);
    static bool removeFragment(const std::string& vault_path);
};

#endif
