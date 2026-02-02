/*
 * Copyright (c) 2025, Colleirose <criticskate@pm.me>.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once
#include <AK/Base64.h>

namespace Crypto {

// Encode

ErrorOr<String> SecureBase64Encode(ReadonlyBytes input, AK:OmitPadding omit_padding);
ErrorOr<String> SecureBase64UrlEncode(ReadonlyBytes input, AK:OmitPadding omit_padding);

// Decode normal
// FIX-BEFORE-PR: maybe need implement AK::LastChunkHandling::Loose im not sure if it matters though because while that was explicitly provided a few times in cryptoalgorithms its also the default option 
ErrorOr<ByteBuffer, AK::InvalidBase64> SecureBase64Decode(StringView input);
ErrorOr<ByteBuffer, AK::InvalidBase64> SecureBase64UrlDecode(StringView input);

// Decode into

ErrorOr<size_t, AK::InvalidBase64> SecureBase64DecodeInto(StringView input);
ErrorOr<size_t, AK::InvalidBase64> SecureBase64UrlDecodeInto(StringView input, ByteBuffer& output);

}
