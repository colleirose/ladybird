/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Base64.h>
#include <AK/Error.h>
#include <AK/Types.h>
#include <LibCore/SecretString.h>

namespace Crypto {

using VariantString = Variant<String, StringView, Core::SecretString>;

// Encode
ErrorOr<String> SecureBase64Encode(ReadonlyBytes& input, AK::OmitPadding omit_padding = AK::OmitPadding::No);
ErrorOr<String> SecureBase64UrlEncode(ReadonlyBytes& input, AK::OmitPadding omit_padding = AK::OmitPadding::No);

ErrorOr<Core::SecretString> SecureBase64Encode(ReadonlyBytes& input, AK::OmitPadding omit_padding = AK::OmitPadding::No);
ErrorOr<Core::SecretString> SecureBase64UrlEncode(ReadonlyBytes& input, AK::OmitPadding omit_padding = AK::OmitPadding::No);

// Decode normal
ErrorOr<ByteBuffer> SecureBase64Decode(VariantString const& input);
ErrorOr<ByteBuffer> SecureBase64UrlDecode(VariantString const& input);

// Decode into
ErrorOr<size_t> SecureBase64DecodeInto(VariantString const& input, ByteBuffer& output);
ErrorOr<size_t> SecureBase64UrlDecodeInto(VariantString const& input, ByteBuffer& output);

}
