#ifndef VOID_VAULT_TEST_UTIL_HPP
#define VOID_VAULT_TEST_UTIL_HPP

// Always-evaluated checks (unlike assert(), never compiled out in Release).

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace tu
{
    inline int failures = 0;

    inline void check(bool condition, const char *message)
    {
        if (condition)
        {
            std::cout << "PASS: " << message << '\n';
        }
        else
        {
            std::cerr << "FAIL: " << message << '\n';
            ++failures;
        }
    }

    inline int finish(const char *suite)
    {
        if (failures == 0)
        {
            std::cout << "All " << suite << " tests passed.\n";
            return EXIT_SUCCESS;
        }
        std::cerr << failures << ' ' << suite << " check(s) failed.\n";
        return EXIT_FAILURE;
    }

    // Unique scratch directory removed on scope exit (even when checks fail).
    class TempDir
    {
    public:
        explicit TempDir(const std::string &tag)
        {
            path_ = std::filesystem::current_path() /
                    ("vv_" + tag + "_" + std::to_string(std::rand()) + "_tmp");
            std::filesystem::remove_all(path_);
            std::filesystem::create_directories(path_);
        }
        ~TempDir()
        {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
        std::string file(const std::string &name) const { return (path_ / name).string(); }
        const std::filesystem::path &path() const { return path_; }

    private:
        std::filesystem::path path_;
    };

    inline std::string readAll(const std::string &path)
    {
        std::ifstream f(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    }

    inline void writeAll(const std::string &path, const std::string &data)
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f.write(data.data(), static_cast<std::streamsize>(data.size()));
    }
}

#endif
