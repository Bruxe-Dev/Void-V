#ifndef VOID_VAULT_SECURE_BUFFER_HPP
#define VOID_VAULT_SECURE_BUFFER_HPP

#include <sodium.h>

#include <cstddef>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string_view>

// Holds a secret in sodium_malloc'd memory (canary + guard pages, mlock'd
// where the OS allows, wiped with sodium_memzero on free).
// Non-copyable so the secret is never accidentally duplicated.
// Supports direct byte-by-byte appending into pre-allocated locked memory so
// interactive secrets can be read from the OS console/descriptor without ever
// passing through std::cin or std::string.
class SecureBuffer
{
public:
    static constexpr std::size_t DEFAULT_CAPACITY = 256;
    static constexpr std::size_t MAX_CAPACITY = 4096;

    SecureBuffer()
    {
        if (sodium_init() < 0)
        {
            throw std::runtime_error("Libsodium initialization failed");
        }
    }

    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;

    SecureBuffer(SecureBuffer &&other) noexcept
        : data_(other.data_), size_(other.size_), capacity_(other.capacity_)
    {
        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }

    SecureBuffer &operator=(SecureBuffer &&other) noexcept
    {
        if (this != &other)
        {
            clear();
            data_ = other.data_;
            size_ = other.size_;
            capacity_ = other.capacity_;
            other.data_ = nullptr;
            other.size_ = 0;
            other.capacity_ = 0;
        }
        return *this;
    }

    ~SecureBuffer() { clear(); }

    void reserve(std::size_t new_capacity)
    {
        if (new_capacity <= capacity_)
        {
            return;
        }
        if (new_capacity > MAX_CAPACITY)
        {
            throw std::length_error("SecureBuffer capacity exceeds MAX_CAPACITY");
        }
        void *mem = sodium_malloc(new_capacity);
        if (mem == nullptr)
        {
            throw std::bad_alloc();
        }
        sodium_memzero(mem, new_capacity);
        if (data_ != nullptr)
        {
            if (size_ > 0)
            {
                std::memcpy(mem, data_, size_);
            }
            sodium_free(data_);
        }
        data_ = static_cast<char *>(mem);
        capacity_ = new_capacity;
    }

    bool push_back(char c)
    {
        if (size_ >= MAX_CAPACITY)
        {
            return false;
        }
        if (size_ == capacity_)
        {
            const std::size_t next = capacity_ == 0
                ? DEFAULT_CAPACITY
                : (capacity_ * 2 > MAX_CAPACITY ? MAX_CAPACITY : capacity_ * 2);
            reserve(next);
        }
        data_[size_++] = c;
        return true;
    }

    void pop_back() noexcept
    {
        if (size_ > 0)
        {
            --size_;
            sodium_memzero(data_ + size_, 1);
        }
    }

    void assign(std::string_view value)
    {
        clear();
        if (value.empty())
        {
            return;
        }
        void *mem = sodium_malloc(value.size());
        if (mem == nullptr)
        {
            throw std::bad_alloc();
        }
        std::memcpy(mem, value.data(), value.size());
        data_ = static_cast<char *>(mem);
        size_ = value.size();
        capacity_ = value.size();
    }

    void clear() noexcept
    {
        if (data_ != nullptr)
        {
            sodium_free(data_);   // wipes before freeing
            data_ = nullptr;
            size_ = 0;
            capacity_ = 0;
        }
    }

    // Constant-time comparison using sodium_memcmp.
    bool constantTimeEquals(std::string_view other) const noexcept
    {
        if (size_ != other.size())
        {
            return false;
        }
        if (size_ == 0)
        {
            return true;
        }
        return sodium_memcmp(data_, other.data(), size_) == 0;
    }

    bool constantTimeEquals(const SecureBuffer &other) const noexcept
    {
        return constantTimeEquals(other.view());
    }

    bool empty() const noexcept { return size_ == 0; }
    std::size_t size() const noexcept { return size_; }
    std::string_view view() const noexcept { return {data_, size_}; }

private:
    char *data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t capacity_ = 0;
};

#endif
