/*
 * Copyright (c) 2021, Brian Gianforcaro <bgianf@serenityos.org>
 * Copyright (c) 2021, Mustafa Quraish <mustafa@serenityos.org>
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "SecretString.h"

#include <AK/Assertions.h>
#include <AK/Checked.h>
#include <AK/Memory.h>
#include <AK/Platform>
#include <AK/Types.h>

#if defined(AK_OS_WINDOWS)
#    include <AK/Windows.h>

#    pragma comment(lib, "Crypt32.lib")

#    include <Memoryapi.h>
#    include <Wincrypt.h>
#    include <psapi.h>
#else
#    include <sys/mman.h>

#    if !defined(MADV_DODUMP) && defined(MADV_CORE)
#        define MADV_DODUMP MADV_CORE
#        define MADV_DONTDUMP MADV_NOCORE
#    endif
#endif

namespace Core {

#if defined(AK_OS_WINDOWS)
inline size_t calculate_memory_size(size_t desired_size)
{
    auto const closest_multiple = [&](size_t n, size_t x) -> size_t {
        VERIFY(x > 0 && n > 0);
        if (x > n)
            return x;

        n += x / 2;
        n -= n % x;
        return n;
    };

    size_t const max_size = CRYPTPROTECTMEMORY_BLOCK_SIZE; // this should be 16
    return (desired_size % max_size == 0) ? desired_size : closest_multiple(max_size, desired_size);
}

ErrorOr<void> SecretString::set_memory_sizes()
{
    size_t const base_size = m_data.decrypted_size;
    size_t const buffer_len = calculate_memory_size(base_size);
    if (buffer_len != base_size)
        return m_data.decrypted_size.try_resize(buffer_len);
    return {};
}
#endif

ErrorOr<void> SecretString::encrypt_memory()
{
#if defined(AK_OS_WINDOWS)
    if (m_data.dont_encrypt_memory_again || m_data.buffer_is_encrypted || m_data.decrypted_size == 0)
        return {};

    TRY(SecretString::set_memory_sizes());
    if (CryptProtectMemory(m_data.buffer.data(), m_data.buffer.size(), CRYPTPROTECTMEMORY_SAME_PROCESS) != TRUE) [[unlikely]] {
        auto err = Error::from_windows_error();
        warnln("cannot encrypt SecretString memory: {}", err);
        m_data.dont_encrypt_memory_again = true;
        return err;
    }

    m_data.buffer_is_encrypted = true;
#else
    // FIXME: Can this be implemented outside Windows?
#endif
    return {};
}

ErrorOr<void> SecretString::decrypt_memory()
{
#if defined(AK_OS_WINDOWS)
    if (!m_data.buffer_is_encrypted || m_data.decrypted_size == 0)
        return {};

    size_t const buffer_size = m_data.buffer.size();
    VERIFY(m_data.decrypted_size <= buffer_size);

    if (CryptUnprotectMemory(m_data.buffer.data(), buffer_size, CRYPTPROTECTMEMORY_SAME_PROCESS) != TRUE) [[unlikely]] {
        auto err = Error::from_windows_error();
        warnln("cannot decrypt SecretString memory: {}", err);
        return err;
    }

    if (buffer_size > m_data.decrypted_size)
        m_data.buffer.trim(m_data.decrypted_size, false);

    m_data.buffer_is_encrypted = false;
#else
    // FIXME: Can this be implemented outside Windows?
#endif
    return {};
}

ErrorOr<SecretString> SecretString::take_ownership(char*& cstring, size_t length)
{
    auto buffer = TRY(ByteBuffer::copy(cstring, length, ByteBuffer::EraseBufferOnFree::Yes));

    kfree_sized_sensitive(cstring, length);
    cstring = nullptr;

    return SecretString(move(buffer));
}

SecretString::SecretString(ByteBuffer&& buffer)
    : m_data.buffer(ByteBuffer(buffer, ByteBuffer::EraseBufferOnFree::Yes))
{
    m_data.decrypted_size = m_data.buffer.size();
    if (m_data.buffer.is_empty() || (m_data.buffer[m_data.buffer.size() - 1] != 0)) {
        u8 nul = '\0';
        m_data.buffer.append(&nul, 1);
    }
    MUST(encrypt_memory());
}

}
