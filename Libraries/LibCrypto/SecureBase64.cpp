/*
 * Copyright (c) 2014, Steve "Sc00bz" Thomas (steve at tobtu dot com)
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>.
 *
 * Original code is under the MIT license from https://github.com/Sc00bz/ConstTimeEncoding.
 * All modifications are under the BSD-2 license.
 * SPDX-License-Identifier: BSD-2-Clause
 */

// This is an implementation of Base64 intended for secret data.
// It performs encoding/decoding in constant time, and erases data when unused.
//
// Encoding/decoding operations can leak secret data. See: https://arxiv.org/abs/2108.04600
// It's fairly unlikely that the circumstances to make the timing differenec exploitable this would occur in a web browser in most cases,
// but we will use this when encoding/decoding secret information anyway.

/*
    Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#include "SecureBase64.h"

#include <AK/Array.h>
#include <AK/Base64.h>
#include <AK/ByteBuffer.h>
#include <AK/Error.h>
#include <AK/Platform.h>
#include <AK/ScopeGuard.h>
#include <AK/StringBuilder.h>
#include <AK/StringView.h>
#include <AK/Types.h>
#include <LibCore/SecretString.h>

namespace Crypto {

// Exported functions are at the bottom

static char const INVALID_BASE64_CHARACTERS = "Invalid base64 characters";

[[nodiscard]] static ALWAYS_INLINE bool is_invalid(u8 x)
{
    return x == 0xFF;
}

[[nodiscard]] static inline Array<u8, 256> decode_table_from(char const* alphabet)
{
    // ALL decoding tables must be 256 bytes.
    // Each contains 8-bit -> 6-bit value OR 0xFF (invalid)
    Array<u8, 256> table {};
    table.fill(0xFF);
    for (size_t i = 0; i < 64; i++)
        table[static_cast<u8>(alphabet[i])] = static_cast<u8>(i);
    return table;
}

static char const* STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char const* URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

[[nodiscard]] static ALWAYS_INLINE size_t approximate_len_for_str_decode(size_t input_len)
{
    // AK::size_required_to_decode_base64 would require repeatedly decrypting the SecretString characters
    // and putting them in a StringView then zeroing out the stringview, which would make the code needlessly complex.
    //
    // This is based on https://github.com/simdutf/simdutf/blob/06258b2c046d233fa53957cced61bc279fadfb41/include/simdutf/scalar/base64.h#L655-L695,
    // but it's less precise.
    VERIFY(input_len != 0);
    if (input_len % 4 <= 1)
        return input_len / 4 * 3;

    return input_len / 4 * 3 + (input_len % 4) - 1;
}

[[nodiscard]] static inline size_t variant_str_length(VariantString const& val)
{
    return val.visit(
        [](String& str) {
            return str.byte_count();
        },
        [](StringView& view) {
            return view.length();
        },
        [](Core::SecretString& secret_str) {
            return secret_str.length();
        });
}

// FIX-BEFORE-PR: probably types wrong
static inline ErrorOr<String> encode_impl(ReadonlyBytes& input, char const* alphabet, AK::OmitPadding omit_padding)
{
    StringBuilder builder = StringBuilder(((input.size() + 2) / 3) * 4);
    ScopeGuard guard([&]() {
        builder.clear_sensitive();
    });

    size_t i = 0;
    while (i + 3 <= input.size()) {
        u32 v = (input[i] << 16) | (input[i + 1] << 8) | input[i + 2];
        TRY(builder.try_append(alphabet[(v >> 18) & 0x3F]));
        TRY(builder.try_append(alphabet[(v >> 12) & 0x3F]));
        TRY(builder.try_append(alphabet[(v >> 6) & 0x3F]));
        TRY(builder.try_append(alphabet[v & 0x3F]));
        i += 3;
    }

    size_t rem = input.size() - i;
    // FIX-BEFORE-PR: maybe incorrect
    if (omit_padding == AK::OmitPadding::No) {
        if (rem == 1) {
            u32 v = (input[i] << 16);
            TRY(builder.try_append(alphabet[(v >> 18) & 0x3F]));
            TRY(builder.try_append(alphabet[(v >> 12) & 0x3F]));
            TRY(builder.try_append("=="sv));
        } else if (rem == 2) {
            u32 v = (input[i] << 16) | (input[i + 1] << 8);
            TRY(builder.try_append(alphabet[(v >> 18) & 0x3F]));
            TRY(builder.try_append(alphabet[(v >> 12) & 0x3F]));
            TRY(builder.try_append(alphabet[(v >> 6) & 0x3F]));
            TRY(builder.try_append('='));
        }
    }

    return builder.to_string();
}

static inline ErrorOr<size_t> decode_into_impl(VariantString const& input, ByteBuffer& out, Array<u8, 256> const& table)
{
    StringView encoded_value = { nullptr, 0 };
    Optional<String&> str_copy;
    ScopeGuard guard([&]() {
        if (str_copy.has_value())
            secure_memzero(str_copy.ptr());
    });

    input.visit(
        [](String const& str) { encoded_value = str.view(); },
        [](StringView const& view) { encoded_value = view; },
        [](Core::SecretString const& secret_str) {
            String const& input_str = TRY(input.make_unsecured_string_copy());
            *str_copy = move(input_str);
            encoded_value = str_copy.bytes_as_string_view();
        });

    VERIFY(!encoded_value.is_null())
    size_t n = encoded_value.length();

    // Reject impossible length (RFC 4648)
    if (n == 0 || n % 4 == 1) [[unlikely]]
        return Error::from_string_literal("Invalid base64 length");

    // Count '=' padding
    size_t pad = 0;
    if (n >= 1 && encoded_value[n - 1] == '=')
        pad++;
    if (n >= 2 && encoded_value[n - 2] == '=')
        pad++;

    size_t previous_length = out.length();
    // The new length is precise now that we know the amount of padding
    TRY(out.try_resize(approximate_len_for_str_decode(n - pad)));
    ArmedScopeGuard trim_length_back([&]() {
        // put the buffer back to how it was previously if this fails to avoid needlessly increasing the buffer size
        out.trim(previous_length, true);
    });

    // Process groups of 4 chars
    size_t out_index = 0;
    for (size_t i = 0; i < n; i += 4) {
        u8 a = table[(u8)encoded_value[i]];
        u8 b = table[(u8)encoded_value[i + 1]];
        u8 c = table[(u8)encoded_value[i + 2]];
        u8 d = table[(u8)encoded_value[i + 3]];

        // invalid chars (except padding) are errors
        if (is_invalid(a)) [[unlikely]]
            return Error::from_string_literal(INVALID_BASE64_CHARACTERS);

        if (is_invalid(b)) [[unlikely]]
            return Error::from_string_literal(INVALID_BASE64_CHARACTERS);

        // For c + d, we allow '=', but only in legal places
        bool c_pad = (encoded_value[i + 2] == '=');
        bool d_pad = (encoded_value[i + 3] == '=');

        if (!c_pad && is_invalid(c)) [[unlikely]]
            return Error::from_string_literal(INVALID_BASE64_CHARACTERS);

        if (!d_pad && is_invalid(d)) [[unlikely]]
            return Error::from_string_literal(INVALID_BASE64_CHARACTERS);

        u32 v = (a << 18) | (b << 12);
        u32 byte_count = 1;

        if (!c_pad) {
            v |= (c << 6);
            byte_count = 2;
        }
        if (!d_pad) {
            v |= d;
            byte_count = 3;
        }

        if (byte_count >= 1)
            out[out_index++] = (v >> 16) & 0xFF;
        if (byte_count >= 2)
            out[out_index++] = (v >> 8) & 0xFF;
        if (byte_count >= 3)
            out[out_index++] = v & 0xFF;
    }

    trim_length_back.disarm();
    return out_index;
}

static inline ErrorOr<ByteBuffer> decode_impl(VariantString const& input, char const* alphabet)
{
    size_t const input_length = variant_str_length(input);
    size_t const buffer_size = approximate_len_for_str_decode(input_length);

    auto output = TRY(ByteBuffer::create_uninitialized(buffer_size, ByteBuffer::EraseBufferOnFree::Yes));
    TRY(decode_into_impl(input, output, decode_table_from(alphabet)));

    return output;
}

// Exported functions

// Encode
ErrorOr<String> SecureBase64Encode(ReadonlyBytes& input, AK::OmitPadding omit_padding)
{
    return encode_impl(input, STD_ALPHABET, omit_padding);
}

ErrorOr<String> SecureBase64UrlEncode(ReadonlyBytes& input, AK::OmitPadding omit_padding)
{
    return encode_impl(input, URL_ALPHABET, omit_padding);
}

ErrorOr<Core::SecretString> SecureBase64Encode(ReadonlyBytes& input, AK::OmitPadding omit_padding)
{
    String const& str = encode_impl(input, STD_ALPHABET, omit_padding);
    return Core::SecretString(move(str));
}

ErrorOr<Core::SecretString> SecureBase64UrlEncode(ReadonlyBytes& input, AK::OmitPadding omit_padding)
{
    String const& str = encode_impl(input, URL_ALPHABET, omit_padding);
    return Core::SecretString(move(str));
}

// Decode normal

ErrorOr<ByteBuffer> SecureBase64Decode(VariantString const& input)
{
    return decode_impl(input, STD_ALPHABET);
}

ErrorOr<ByteBuffer> SecureBase64UrlDecode(VariantString const& input)
{
    return decode_impl(input, URL_ALPHABET);
}

// Decode into

ErrorOr<size_t> SecureBase64DecodeInto(VariantString const& input, ByteBuffer& output)
{
    output.set_erase_on_free(true);
    return decode_into_impl(input, output, STD_ALPHABET);
}

ErrorOr<size_t> SecureBase64UrlDecodeInto(VariantString const& input, ByteBuffer& output)
{
    output.set_erase_on_free(true);
    return decode_into_impl(input, output, URL_ALPHABET);
}

}
