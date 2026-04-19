/*
 * Copyright (c) 2021, Brian Gianforcaro <bgianf@serenityos.org>
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/Memory.h>
#include <AK/Noncopyable.h>
#include <AK/Platform.h>
#include <AK/ScopeGuard.h>
#include <AK/StringView.h>
#include <AK/Types.h>

namespace Core {

// Like the normal String class, but erases the memory when it's freed, locks it to prevent it from being swapped out,
// compares values in constant-time, and on Windows systems, encrypts it with CryptProtectMemory().
//
// This class obviously has performance overhead, so it should only be used for data like passwords and authentication tokens. Also try to avoid using it for large values.

class SecretString {
    AK_MAKE_NONCOPYABLE(SecretString);
    AK_MAKE_DEFAULT_MOVABLE(SecretString);

public:
    [[nodiscard]] static ErrorOr<SecretString> take_ownership(char*&, size_t);

    SecretString() = default;
    ~SecretString() = default; // The ByteBuffer will do the actual zero-on-free, not SecretString itself

    [[nodiscard]] ALWAYS_INLINE size_t length() const
    {
#if defined(AK_OS_WINDOWS)
        return m_data.decrypted_size;
#else
        return m_data.buffer.size();
#endif
    }

    [[nodiscard]] ALWAYS_INLINE bool is_empty() const
    {
        return length() == 0;
    }

    [[nodiscard]] ErrorOr<String> make_unsecured_string_copy()
    {
        TRY(decrypt_memory());
        ScopeGuard guard([&]() {
            // In case we have an error before we can reach the end of the function, we do this here instead of at the end:
            MUST(encrypt_memory());
        });

        String str = "";
        ByteBuffer new_buf = TRY(ByteBuffer::copy(m_data.buffer, ByteBuffer::EraseBufferOnFree::Yes));
        char const* characters = reinterpret_cast<char const*>(new_buf.data());
        size_t size = new_buf.length();
        TRY(str.replace_with_new_string(StringView { characters, size }));

        return str;
    }

    [[nodiscard]] SecretString(String&& str)
    {
        auto res = SecretString(MUST(ByteBuffer::copy(str.bytes(), ByteBuffer::EraseBufferOnFree::Yes)));
        secure_memzero(&str);
        return res;
    }

    [[nodiscard]] SecretString(Bytes&& bytes)
    {
        auto res = SecretString(MUST(ByteBuffer::copy(bytes, ByteBuffer::EraseBufferOnFree::Yes)));
        if (bytes.size() > 0)
            secure_memzero(bytes.data(), bytes.size());
        return res;
    }

    [[nodiscard]] bool operator==(String const& other) const
    {
        if (length() != other.byte_count())
            return false;

        MUST(decrypt_memory());
        ScopeGuard guard([&]() { MUST(encrypt_memory()); });

        return timing_safe_compare(bytes(), other.bytes(), length());
    }

    [[nodiscard]] bool operator==(SecretString const& other) const
    {
        if (length() != other.length())
            return false;

        MUST(decrypt_memory());
        MUST(other.decrypt_memory());
        ScopeGuard guard([&]() {
            MUST(encrypt_memory());
            MUST(other.encrypt_memory());
        });

        return timing_safe_compare(bytes(), other.bytes(), length());
    }

    [[nodiscard]] SecretString operator+(SecretString const& other)
    {
        MUST(decrypt_memory());
        MUST(other.decrypt_memory());
        ScopeGuard guard([&]() {
            MUST(encrypt_memory());
            MUST(other.encrypt_memory());
        });

        SecretString res = SecretString();
        res.m_data.buffer = m_data.buffer;
        res.m_data.buffer += other.m_data.buffer;
#if defined(AK_OS_WINDOWS)
        // res.buffer_is_encrypted = false;
        res.m_data.decrypted_size += other.m_data.decrypted_size;
#endif

        MUST(res.encrypt_memory());
        return res;
    }

    [[nodiscard]] SecretString operator+(Variant<String, StringView> const& other)
    {
        MUST(decrypt_memory());
        ScopeGuard guard([&]() { MUST(encrypt_memory()); });

        StringView const& view = other.visit(
            [](String& val) { return val.bytes_as_string_view(); },
            [](StringView& val) { return val; });

        m_data.buffer.append(view.bytes());
    }

    void operator+=(SecretString const& other)
    {
        MUST(decrypt_memory());
        MUST(other.decrypt_memory());

        m_data.buffer += other.m_data.buffer;
#if defined(AK_OS_WINDOWS)
        m_data.decrypted_size += other.decrypted_size;
#endif

        MUST(encrypt_memory());
        MUST(other.encrypt_memory());
    }

private:
    explicit SecretString(ByteBuffer&&);

    struct {
        ByteBuffer buffer;
#if defined(AK_OS_WINDOWS)
        size_t decrypted_size { 0 };
        bool buffer_is_encrypted { false };
        bool dont_encrypt_memory_again { false };
#endif
    } m_data;

    ErrorOr<void> encrypt_memory();
    ErrorOr<void> decrypt_memory();
};

}
