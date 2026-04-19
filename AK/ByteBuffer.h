/*
 * Copyright (c) 2018-2021, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2021, Gunnar Beutner <gbeutner@serenityos.org>
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Assertions.h>
#include <AK/Badge.h>
#include <AK/Error.h>
#include <AK/Memory.h>
#include <AK/Span.h>
#include <AK/Types.h>
#include <AK/kmalloc.h>

namespace AK {
namespace Detail {

template<size_t inline_capacity>
class ByteBuffer {
public:
    ByteBuffer() = default;

    ~ByteBuffer()
    {
        clear();
    }

    // FIX-BEFORE-PR: does the way i am doing zero-on-free really work
    constexpr auto ZERO_ON_FREE_FLAG = 1;
    constexpr auto INLINE_BUFFER_FLAG = 2;

    enum class EraseBufferOnFree : u8 {
        Unspecified,
        No,
        Yes,
    };

    enum class ZeroFillNewElements : u8 {
        No,
        Yes,
    };

    ByteBuffer(EraseBufferOnFree erase_option)
    {
        auto buffer = ByteBuffer();
        buffer.set_erase_on_free(erase_option);
        move_from(move(buffer));
    }

    ByteBuffer(ByteBuffer const& other, EraseBufferOnFree erase_option = EraseBufferOnFree::Unspecified)
    {
        set_erase_on_free(erase_option);

        MUST(try_resize(other.size()));
        VERIFY(m_size == other.size());
        __builtin_memcpy(data(), other.data(), other.size());
    }

    ByteBuffer(ByteBuffer&& other, EraseBufferOnFree erase_option = EraseBufferOnFree::Unspecified)
    {
        // this will also apply to the new buffer because move_from() will apply it
        // if its unspecified we'll end up with just whatever was in the old buffer
        set_erase_on_free(erase_option);
        move_from(move(other));
    }

    ByteBuffer& operator=(ByteBuffer&& other)
    {
        if (this != &other) {
            clear();
            move_from(move(other));
        }
        return *this;
    }

    ByteBuffer& operator=(ByteBuffer const& other)
    {
        if (this != &other) {
            set_erase_on_free(other.is_erase_on_free());

            if (m_size > other.size()) {
                trim(other.size(), true);
            } else {
                MUST(try_resize(other.size()));
            }

            __builtin_memcpy(data(), other.data(), other.size());
        }
        return *this;
    }

    [[nodiscard]] static ErrorOr<ByteBuffer> create_uninitialized(size_t size, EraseBufferOnFree erase_option = EraseBufferOnFree::Unspecified)
    {
        auto buffer = ByteBuffer(erase_option);
        TRY(buffer.try_resize(size));
        return { move(buffer) };
    }

    [[nodiscard]] static ErrorOr<ByteBuffer> create_zeroed(size_t size, EraseBufferOnFree erase_option = EraseBufferOnFree::Unspecified)
    {
        auto buffer = TRY(create_uninitialized(size, erase_option));

        buffer.zero_fill();
        VERIFY(size == 0 || (buffer[0] == 0 && buffer[size - 1] == 0));
        return { move(buffer) };
    }

    [[nodiscard]] static ErrorOr<ByteBuffer> copy(void const* data, size_t size, EraseBufferOnFree erase_option = EraseBufferOnFree::Unspecified)
    {
        auto buffer = TRY(create_uninitialized(size, erase_option));
        if (buffer.is_inline() && size > inline_capacity)
            VERIFY_NOT_REACHED();
        if (size != 0)
            __builtin_memcpy(buffer.data(), data, size);

        return { move(buffer) };
    }

    [[nodiscard]] static ErrorOr<ByteBuffer> copy(ReadonlyBytes bytes, EraseBufferOnFree erase_option = EraseBufferOnFree::Unspecified)
    {
        return copy(bytes.data(), bytes.size(), erase_option);
    }

    [[nodiscard]] static ErrorOr<ByteBuffer> xor_buffers(ReadonlyBytes first, ReadonlyBytes second, EraseBufferOnFree erase_option = EraseBufferOnFree::Unspecified)
    {
        if (first.size() != second.size())
            return Error::from_errno(EINVAL);

        auto buffer = TRY(create_uninitialized(first.size(), erase_option));
        auto buffer_data = buffer.data();
        auto first_data = first.data();
        auto second_data = second.data();
        for (size_t i = 0; i < first.size(); ++i)
            buffer_data[i] = first_data[i] ^ second_data[i];

        return { move(buffer) };
    }

    template<size_t other_inline_capacity>
    bool operator==(ByteBuffer<other_inline_capacity> const& other) const
    {
        if (size() != other.size())
            return false;

        // So they both have data, and the same length.
        return !__builtin_memcmp(data(), other.data(), size());
    }

    [[nodiscard]] u8& operator[](size_t i)
    {
        VERIFY(i < m_size);
        return data()[i];
    }

    [[nodiscard]] u8 const& operator[](size_t i) const
    {
        VERIFY(i < m_size);
        return data()[i];
    }

    [[nodiscard]] ALWAYS_INLINE size_t capacity() const { return is_inline() ? m_inline_capacity : m_outline_capacity; }
    [[nodiscard]] ALWAYS_INLINE size_t size() const { return m_size; }
    [[nodiscard]] ALWAYS_INLINE bool is_empty() const { return m_size == 0; }
    [[nodiscard]] ALWAYS_INLINE bool is_inline() const { return flags & INLINE_BUFFER_FLAG; }
    [[nodiscard]] ALWAYS_INLINE bool is_erase_on_free() const { return m_flags & ZERO_ON_FREE_FLAG; }

    ALWAYS_INLINE void set_erase_on_free(bool option)
    {
        if (is_erase_on_free() == option)
            return;

        if (option)
            m_flags |= ZERO_ON_FREE_FLAG;
        else
            m_flags &= ~ZERO_ON_FREE_FLAG;
    }

    ALWAYS_INLINE void set_erase_on_free(EraseBufferOnFree option)
    {
        if (option != EraseBufferOnFree::Unspecified)
            set_erase_on_free(option == EraseBufferOnFree::Yes);
    }

    ALWAYS_INLINE void set_buffer_is_inline(bool option)
    {
        if (is_inline() == option)
            return;

        if (option)
            m_flags |= INLINE_BUFFER_FLAG;
        else
            m_flags &= ~INLINE_BUFFER_FLAG;
    }

#ifdef AK_COMPILER_GCC
#    pragma GCC diagnostic push
//   Workaround for https://gcc.gnu.org/bugzilla/show_bug.cgi?id=109727
#    pragma GCC diagnostic ignored "-Warray-bounds"
#endif
    [[nodiscard]] u8* data()
    {
        return is_inline() ? m_inline_buffer : m_outline_buffer;
    }
    [[nodiscard]] u8 const* data() const { return is_inline() ? m_inline_buffer : m_outline_buffer; }
#ifdef AK_COMPILER_GCC
#    pragma GCC diagnostic pop
#endif

    [[nodiscard]] Bytes bytes() && LIFETIME_BOUND = delete;
    [[nodiscard]] Bytes bytes() & LIFETIME_BOUND
    {
        return { data(), size() };
    }

    [[nodiscard]] ReadonlyBytes bytes() const&& = delete;
    [[nodiscard]] ReadonlyBytes bytes() const& LIFETIME_BOUND { return { data(), size() }; }

    [[nodiscard]] AK::Bytes span() LIFETIME_BOUND { return { data(), size() }; }
    [[nodiscard]] AK::ReadonlyBytes span() const LIFETIME_BOUND { return { data(), size() }; }

    [[nodiscard]] u8* offset_pointer(size_t offset) { return data() + offset; }
    [[nodiscard]] u8 const* offset_pointer(size_t offset) const { return data() + offset; }

    [[nodiscard]] void* end_pointer() { return data() + m_size; }
    [[nodiscard]] void const* end_pointer() const { return data() + m_size; }

    [[nodiscard]] ErrorOr<ByteBuffer> slice(size_t offset, size_t size) const
    {
        // I cannot hand you a slice I don't have
        VERIFY(offset + size <= this->size());

        return copy(offset_pointer(offset), size, is_erase_on_free() ? EraseBufferOnFree::Yes : EraseBufferOnFree::Unspecified);
    }

    // Frees memory allocated for the buffer and erases the buffer data if marked as zero-on-free
    void clear()
    {
        bool const is_memzero = is_erase_on_free();

        if (is_inline()) {
            if (is_memzero)
                secure_memzero(m_inline_buffer, inline_capacity);
        } else {
            if (is_memzero) {
                kfree_sized_sensitive(m_outline_buffer, m_outline_capacity);
            } else {
                kfree_sized(m_outline_buffer, m_outline_capacity);
            }

            set_buffer_is_inline(true);
        }

        m_size = 0;
    }

    ALWAYS_INLINE void resize(size_t new_size, ZeroFillNewElements zero_fill_new_elements = ZeroFillNewElements::No)
    {
        MUST(try_resize(new_size, zero_fill_new_elements));
    }

    void trim(size_t size, bool may_discard_existing_data)
    {
        VERIFY(size <= m_size);

        if (size == m_size)
            return;

        if (is_erase_on_free())
            secure_memzero(offset_pointer(size), m_size - size); // erase everything past the new location

        if (!is_inline() && size <= inline_capacity)
            shrink_into_inline_buffer(size, may_discard_existing_data);

        m_size = size;
    }

    ALWAYS_INLINE void ensure_capacity(size_t new_capacity)
    {
        MUST(try_ensure_capacity(new_capacity));
    }

    void set_size(size_t new_size, ZeroFillNewElements zero_fill_new_elements = ZeroFillNewElements::No)
    {
        ASSERT(new_size <= capacity());

        if (zero_fill_new_elements == ZeroFillNewElements::Yes) {
            __builtin_memset(data() + m_size, 0, new_size - m_size);
        }

        m_size = new_size;
    }

    ErrorOr<void> try_resize(size_t new_size, ZeroFillNewElements zero_fill_new_elements = ZeroFillNewElements::No)
    {
        if (new_size <= m_size) {
            trim(new_size, false);
            return {};
        }
        TRY(try_ensure_capacity(new_size));

        set_size(new_size, zero_fill_new_elements);

        return {};
    }

    ErrorOr<void> try_ensure_capacity(size_t new_capacity)
    {
        if (new_capacity <= capacity())
            return {};
        return try_ensure_capacity_slowpath(new_capacity);
    }

    /// Return a span of bytes past the end of this ByteBuffer for writing.
    /// Ensures that the required space is available.
    ErrorOr<Bytes> get_bytes_for_writing(size_t length)
    {
        auto const old_size = size();
        TRY(try_resize(old_size + length));
        return Bytes { data() + old_size, length };
    }

    /// Like get_bytes_for_writing, but crashes if allocation fails.
    Bytes must_get_bytes_for_writing(size_t length) LIFETIME_BOUND
    {
        return MUST(get_bytes_for_writing(length));
    }

    void append(u8 byte)
    {
        MUST(try_append(byte));
    }

    void append(ReadonlyBytes bytes)
    {
        MUST(try_append(bytes));
    }

    void append(void const* data, size_t data_size) { append({ data, data_size }); }

    ErrorOr<void> try_append(u8 byte)
    {
        auto old_size = size();
        auto new_size = old_size + 1;
        VERIFY(new_size > old_size);
        TRY(try_resize(new_size));
        data()[old_size] = byte;
        return {};
    }

    ErrorOr<void> try_append(ReadonlyBytes bytes)
    {
        return try_append(bytes.data(), bytes.size());
    }

    ErrorOr<void> try_append(void const* data, size_t data_size)
    {
        if (data_size == 0)
            return {};
        VERIFY(data != nullptr);
        auto old_size = size();
        TRY(try_resize(size() + data_size));
        __builtin_memcpy(this->data() + old_size, data, data_size);
        return {};
    }

    void operator+=(ByteBuffer const& other)
    {
        MUST(try_append(other.data(), other.size()));
    }

    void overwrite(size_t offset, void const* data, size_t data_size)
    {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
        // make sure we're not told to write past the end
        VERIFY(offset + data_size <= size());
        __builtin_memmove(this->data() + offset, data, data_size);
#pragma GCC diagnostic pop
    }

    void zero_fill()
    {
        __builtin_memset(data(), 0, m_size);
    }

    operator Bytes() && = delete;
    operator Bytes() & LIFETIME_BOUND { return bytes(); }
    operator ReadonlyBytes() const&& = delete;
    operator ReadonlyBytes() const& LIFETIME_BOUND { return bytes(); }

    struct OutlineBuffer {
        Bytes buffer;
        size_t capacity { 0 };
    };
    Optional<OutlineBuffer> leak_outline_buffer(Badge<StringBuilder>)
    {
        if (is_inline())
            return {};

        auto buffer = bytes();
        set_buffer_is_inline(true);
        m_size = 0;

        return OutlineBuffer { buffer, capacity() };
    }

private:
    void move_from(ByteBuffer&& other)
    {
        m_size = other.m_size;
        set_buffer_is_inline(other.is_inline());
        set_erase_on_free(other.is_erase_on_free());
        if (!other.is_inline()) {
            m_outline_buffer = other.m_outline_buffer;
            m_outline_capacity = other.m_outline_capacity;
        } else {
            VERIFY(other.m_size <= inline_capacity);
            __builtin_memcpy(m_inline_buffer, other.m_inline_buffer, other.m_size);
        }

        other.m_size = 0;
        other.set_buffer_is_inline(true);
    }

    NEVER_INLINE void shrink_into_inline_buffer(size_t size, bool may_discard_existing_data)
    {
        // m_inline_buffer and m_outline_buffer are part of a union, so save the pointer
        auto* outline_buffer = m_outline_buffer;
        if (!may_discard_existing_data)
            __builtin_memcpy(m_inline_buffer, outline_buffer, size);

        if (is_erase_on_free()) {
            kfree_sized_sensitive(outline_buffer, outline_capacity);
        } else {
            kfree_sized(outline_buffer, outline_capacity);
        }

        set_buffer_is_inline(true);
    }

    NEVER_INLINE ErrorOr<void> try_ensure_capacity_slowpath(size_t new_capacity)
    {
        // When we are asked to raise the capacity by very small amounts,
        // the caller is perhaps appending very little data in many calls.
        // To avoid copying the entire ByteBuffer every single time,
        // we raise the capacity exponentially, by a factor of roughly 1.5.
        // This is most noticeable in Lagom, where kmalloc_good_size is just a no-op.
        new_capacity = max(new_capacity, (capacity() * 3) / 2);
        new_capacity = kmalloc_good_size(new_capacity);

        u8* new_buffer = nullptr;
        bool const is_memzero = is_erase_on_free;

        if (is_memzero) {
            new_buffer = static_cast<u8*>(kmalloc_sensitive(new_capacity));
        } else {
            new_buffer = static_cast<u8*>(kmalloc(new_capacity));
        }

        if (!new_buffer)
            return Error::from_errno(ENOMEM);

        if (is_inline()) {
            __builtin_memcpy(new_buffer, data(), m_size);
        } else if (m_outline_buffer) {
            __builtin_memcpy(new_buffer, m_outline_buffer, min(new_capacity, m_outline_capacity));
            if (is_memzero) {
                kfree_sized_sensitive(m_outline_buffer, m_outline_capacity);
            } else {
                kfree_sized(m_outline_buffer, m_outline_capacity);
            }
        }

        m_outline_buffer = new_buffer;
        m_outline_capacity = new_capacity;
        set_buffer_is_inline(false);
        return {};
    }

    union {
        u8 m_inline_buffer[inline_capacity];
        struct {
            u8* m_outline_buffer;
            size_t m_outline_capacity;
        };
    };
    size_t m_size { 0 };
    u8 m_flags { 0 };
};

}

template<>
struct Traits<ByteBuffer> : public DefaultTraits<ByteBuffer> {
    static unsigned hash(ByteBuffer const& byte_buffer)
    {
        return Traits<ReadonlyBytes>::hash(byte_buffer.span());
    }
    static bool equals(ByteBuffer const& byte_buffer, Bytes const& other)
    {
        return byte_buffer.bytes() == other;
    }
    static bool equals(ByteBuffer const& byte_buffer, ReadonlyBytes const& other)
    {
        return byte_buffer.bytes() == other;
    }
};

}
