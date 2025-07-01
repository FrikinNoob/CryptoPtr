#pragma once 
#include <stdint.h>
#include <type_traits>
#include <functional>

namespace enc
{
    namespace detail
    {
#define reca reinterpret_cast
#define stca static_cast
#define ConstStrLen(Str) ((sizeof(Str) - sizeof(Str[0])) / sizeof(Str[0]))
#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
        template <typename StrType>
        constexpr unsigned short HashStr(StrType Data, int Len)
        {
            unsigned short CRC = 0xFFFF;
            while (Len--) {
                auto CurChar = *Data++;
                if (!CurChar) break;
                CRC ^= ToLower(CurChar) << 8;
                for (int i = 0; i < 8; ++i)
                    CRC = (CRC & 0x8000) ? (CRC << 1) ^ 0x6491u : (CRC << 1);
            }
            return CRC;
        }

#define ConstHashStr(Str) []() { constexpr unsigned short C = ::enc::detail::HashStr(Str, ConstStrLen(Str)); return C; }()
        struct CryptKeyBuilder {
            static constexpr uint64_t value() {
                return (static_cast<uint64_t>(ConstHashStr(__TIME__) & 0xFFFF) << 48) |
                    (static_cast<uint64_t>(ConstHashStr(__DATE__) & 0xFFFF) << 32) |
                    (static_cast<uint64_t>(ConstHashStr(__FILE__) & 0xFFFF) << 16) |
                    (static_cast<uint64_t>(ConstHashStr(__TIMESTAMP__) & 0xFFFF));
            }
        };

        template <typename T>
        constexpr uint64_t xorkey(T value) noexcept
        {
            return (uint64_t)(value) ^ CryptKeyBuilder::value();
        }
    } // namespace detail 

    template<typename T>
    class unique_enc_ptr
    {
    private:
        uint64_t encrypted;
        std::function<void(T*)> deleter;

    public:
        constexpr unique_enc_ptr() : encrypted(0), deleter([](T* p) {
            if constexpr (std::is_void_v<T>) free(p);
            else delete p;
            }) {}

        explicit unique_enc_ptr(T* ptr) noexcept
            : encrypted(detail::xorkey(ptr)), deleter([](T* p) {
            if constexpr (std::is_void_v<T>) free(p);
            else delete p;
                }) {}

        unique_enc_ptr(T* ptr, std::function<void(T*)> d) noexcept
            : encrypted(detail::xorkey(ptr)), deleter(d) {}

        template<typename Deleter>
        unique_enc_ptr(T* ptr, Deleter&& d) noexcept
            : encrypted(detail::xorkey(ptr)), deleter(std::forward<Deleter>(d)) {}

        unique_enc_ptr(unique_enc_ptr&& other) noexcept
            : encrypted(other.encrypted), deleter(std::move(other.deleter))
        {
            other.encrypted = 0;
        }

        unique_enc_ptr& operator=(unique_enc_ptr&& other) noexcept
        {
            if (this != &other)
            {
                reset(other.release());
                deleter = std::move(other.deleter);
            }
            return *this;
        }

        unique_enc_ptr(const unique_enc_ptr&) = delete;
        unique_enc_ptr& operator=(const unique_enc_ptr&) = delete;

        ~unique_enc_ptr() { reset(); }

        T* get() const noexcept
        {
            return reca<T*>(detail::xorkey(encrypted));
        }

        template<typename U = T>
        typename std::enable_if<!std::is_void<U>::value, U*>::type operator->() const noexcept
        {
            return get();
        }

        template<typename U = T>
        typename std::enable_if<!std::is_void<U>::value, U&>::type operator*() const noexcept
        {
            return *get();
        }

        explicit operator bool() const noexcept
        {
            return encrypted != 0;
        }

        T* release() noexcept
        {
            T* p = get();
            encrypted = 0;
            return p;
        }

        void reset(T* ptr = nullptr) noexcept
        {
            T* old = get();
            encrypted = detail::xorkey(ptr);
            if (old) deleter(old);
        }

        uint64_t get_enc_value() const noexcept
        {
            return encrypted;
        }

        void set_deleter(std::function<void(T*)> d) noexcept
        {
            deleter = d;
        }
    };

    template<typename T, typename... Args>
    [[nodiscard]] unique_enc_ptr<T> make_unique_enc(Args&&... args)
    {
        if constexpr (std::is_void_v<T>) {
            if constexpr (sizeof...(args) == 0) {
                return unique_enc_ptr<T>(static_cast<T*>(new uint64_t()));
            }
            else {
                return unique_enc_ptr<T>(static_cast<T*>(new uint64_t(std::forward<Args>(args)...)));
            }
        }
        else {
            return unique_enc_ptr<T>(new T(std::forward<Args>(args)...));
        }
    }

    template<typename T>
    [[nodiscard]] unique_enc_ptr<T> make_enc_ptr(T* ptr, std::function<void(T*)> deleter = nullptr)
    {
        if (!deleter) {
            if constexpr (std::is_void_v<T>) {
                deleter = [](T* p) { free(p); };
            }
            else {
                deleter = [](T* p) { delete p; };
            }
        }
        return unique_enc_ptr<T>(ptr, deleter);
    }
#undef ConstHashStr
#undef ToLower
#undef ConstStrLen
#undef stca 
#undef reca 
} // namespace enc
