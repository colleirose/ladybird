/*
 * Copyright (c) 2025, Colleirose <criticskate@pm.me>.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once
#include <AK/Base64.h>

namespace Crypto {

ErrorOr<String> encode_base64_constant_time(ReadonlyBytes input);
ErrorOr<ByteBuffer, AK::InvalidBase64> decode_base64_constant_time(StringView input);
ErrorOr<size_t, AK::InvalidBase64> decode_base64_constant_time_into(StringView input, ByteBuffer& output);

}
