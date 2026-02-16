/*
 * Copyright (c) 2014, Steve "Sc00bz" Thomas (steve at tobtu dot com)
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>.
 *
 * Original code is under the MIT license from https://github.com/Sc00bz/ConstTimeEncoding.
 * All modifications are under the BSD-2 license.
 * SPDX-License-Identifier: BSD-2-Clause
 */

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

// This is an implementation of Base64 intended for secret data. It performs encoding/decoding in constant time, and erased unneded copies of the secret data.
// Encoding/decoding operations can leak secret data. See: https://arxiv.org/abs/2108.04600
// It's fairly unlikely that the circumstances to make this exploitable this would occur in a web browser,
// but we will use this when encoding/decoding secret information.

// This is overall a best-effort attempt at making constant-time base64 decoding, as it hasn't been extensively tested, but it should work well.
// There are still branching conditions used here, but they are based on padding/formatting, not sensitive data, so it should be safe.
// The same type of conditions are used in BoringSSL, aws-lc, libsodium, and the ConstTimeEncoding repository that was referenced earlier.

#include "SecureBase64.h"

#include <AK/Array.h>
#include <AK/Base64.h>
#include <AK/ByteBuffer.h>
#include <AK/Error.h>
#include <AK/Platform.h>
#include <AK/StringBuilder.h>
#include <AK/StringView.h>
#include <AK/Types.h>

// ALL decoding tables must be 256 bytes.
// Each contains 8-bit -> 6-bit value OR 0xFF (invalid)
static char STD_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char URL_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static auto decode_table_from(char const* alphabet)
{
    Array<u8, 256> table {};
    table.fill(0xFF);
    for (size_t i = 0; i < 64; i++)
        table[static_cast<u8>(alphabet[i])] = static_cast<u8>(i);
    return table;
}

static auto STD_TABLE = decode_table_from(STD_ALPHABET);
static auto URL_TABLE = decode_table_from(URL_ALPHABET);

static ALWAYS_INLINE bool is_invalid(u8 x)
{
    return x == 0xFF;
}

namespace Crypto {

// Exported functions at the bottom

// FIX-BEFORE-PR: probably types wrong
static ErrorOr<String> encode_impl(ReadonlyBytes input, char const* alphabet, AK::OmitPadding omit_padding)
{
    StringBuilder builder = StringBuilder(((input.size() + 2) / 3) * 4);

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
            TRY(builder.try_append('='));
            TRY(builder.try_append('='));
        } else if (rem == 2) {
            u32 v = (input[i] << 16) | (input[i + 1] << 8);
            TRY(builder.try_append(alphabet[(v >> 18) & 0x3F]));
            TRY(builder.try_append(alphabet[(v >> 12) & 0x3F]));
            TRY(builder.try_append(alphabet[(v >> 6) & 0x3F]));
            TRY(builder.try_append('='));
        }
    }

    auto out = builder.to_string();
    builder.clear_sensitive();
    return out;
}

static ErrorOr<size_t, AK::InvalidBase64> decode_into_impl(StringView input, ByteBuffer& out, Array<u8, 256> const& table)
{
    size_t n = input.length();

    // Reject impossible length (RFC 4648)
    if (n % 4 == 1) [[unlikely]] {
        return AK::InvalidBase64 {
            .error = Error::from_string_literal("Invalid base64 length"),
            .valid_input_bytes = 0,
        };
    }

    // Count '=' padding
    size_t pad = 0;
    if (n >= 1 && input[n - 1] == '=')
        pad++;
    if (n >= 2 && input[n - 2] == '=')
        pad++;

    size_t blocks = n / 4;
    size_t out_index = 0;
    size_t out_len = blocks * 3 - pad;

    if (out.try_resize(out_len).is_error()) [[unlikely]] {
        return AK::InvalidBase64 {
            .error = Error::from_errno(ENOMEM),
            .valid_input_bytes = 0,
        };
    }

    // Process groups of 4 chars
    for (size_t i = 0; i < n; i += 4) {
        u8 a = table[(u8)input[i]];
        u8 b = table[(u8)input[i + 1]];
        u8 c = table[(u8)input[i + 2]];
        u8 d = table[(u8)input[i + 3]];

        ScopeGuard guard = [&] {
            secure_memzero(a, sizeof(a));
            secure_memzero(b, sizeof(b));
            secure_memzero(c, sizeof(c));
            secure_memzero(d, sizeof(d));
        };

        // invalid chars (except padding) are errors
        if (is_invalid(a)) [[unlikely]] {
            return AK::InvalidBase64 {
                .error = Error::from_string_literal("Invalid base64 character"),
                .valid_input_bytes = i,
            };
        }

        if (is_invalid(b)) [[unlikely]] {
            return AK::InvalidBase64 {
                .error = Error::from_string_literal("Invalid base64 character"),
                .valid_input_bytes = i + 1,
            };
        }

        // For c + d, we allow '=', but only in legal places
        bool c_pad = (input[i + 2] == '=');
        bool d_pad = (input[i + 3] == '=');

        if (!c_pad && is_invalid(c)) [[unlikely]] {
            return AK::InvalidBase64 {
                .error = Error::from_string_literal("Invalid base64 character"),
                .valid_input_bytes = i + 2,
            };
        }

        if (!d_pad && is_invalid(d)) [[unlikely]] {
            return AK::InvalidBase64 {
                .error = Error::from_string_literal("Invalid base64 character"),
                .valid_input_bytes = i + 3,
            };
        }

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

        secure_memzero(v, sizeof(v));
    }

    return out_index;
}

static ErrorOr<ByteBuffer, AK::InvalidBase64> decode_impl(StringView input, Array<u8, 256> table)
{
    ErrorOr<ByteBuffer> maybe_output = ByteBuffer::create_uninitialized(AK::size_required_to_decode_base64(input), AK::EraseBufferOnFree::Yes);

    if (maybe_output.is_error()) [[unlikely]] {
        return AK::InvalidBase64 {
            .error = Error::from_errno(ENOMEM),
            .valid_input_bytes = 0,
        };
    }

    auto output = maybe_output.release_value();

    TRY(decode_into_impl(input, output, table));

    return output;
}

// Exported functions

// Encode
ErrorOr<String> SecureBase64Encode(ReadonlyBytes input, AK : OmitPadding omit_padding)
{
    TRY(encode_impl(input, &STD_ALPHABET, omit_padding));
}

ErrorOr<String> SecureBase64UrlEncode(ReadonlyBytes input)
{
    TRY(encode_impl(input, &URL_ALPHABET, omit_padding));
}

// Decode normal

ErrorOr<ByteBuffer, AK::InvalidBase64> SecureBase64Decode(StringView input)
{
    TRY(decode_impl(input, STD_TABLE));
}

ErrorOr<ByteBuffer, AK::InvalidBase64> SecureBase64UrlDecode(StringView input)
{
    TRY(decode_impl(input, URL_TABLE));
}

// Decode into

ErrorOr<size_t, AK::InvalidBase64> SecureBase64DecodeInto(StringView input)
{
    TRY(decode_into_impl(input, STD_TABLE));
}

ErrorOr<size_t, AK::InvalidBase64> SecureBase64UrlDecodeInto(StringView input, ByteBuffer& output)
{
    TRY(decode_into_impl(input, URL_TABLE));
}

}
