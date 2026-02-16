/*
 * Copyright (c) 2021, Brian Gianforcaro <bgianf@serenityos.org>
 * Copyright (c) 2021, Mustafa Quraish <mustafa@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Memory.h>
#include <AK/Types.h>
#include <LibCore/SecretString.h>

namespace Core {

ErrorOr<SecretString> SecretString::take_ownership(char*& cstring, size_t length)
{
    auto buffer = TRY(ByteBuffer::copy(cstring, length, AK::EraseBufferOnFree::Yes));

    kfree_sized_sensitive(cstring, length);
    cstring = nullptr;

    return SecretString(move(buffer));
}

SecretString SecretString::take_ownership(ByteBuffer&& buffer)
{
    return SecretString(move(ByteBuffer(buffer, AK::EraseBufferOnFree::Yes)));
}

SecretString::SecretString(ByteBuffer&& buffer)
    : m_secure_buffer(move(buffer))
{
    if (m_secure_buffer.is_empty() || (m_secure_buffer[m_secure_buffer.size() - 1] != 0)) {
        u8 nul = '\0';
        m_secure_buffer.append(&nul, 1);
    }
}

SecretString::~SecretString()
{
    if (!m_secure_buffer.is_empty())
        secure_memzero(m_secure_buffer.data(), m_secure_buffer.capacity());
}

}
