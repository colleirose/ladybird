/*
 * Copyright (c) 2020, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2021-2022, Brian Gianforcaro <bgianf@serenityos.org>
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Types.h>

namespace AK {

using StringPtr = Variant<Utf16String*&, String*&>;
void secure_memzero(void* const ptr, size_t const size);
void secure_memzero(StringPtr ptr); // FIX-BEFORE-PR: Not sure if the & should go here or inside the variant or outside or whatever
bool timing_safe_compare(void const* b1, void const* b2, size_t len);

// Informs the operating system that the memory shouldn't be swapped to pagefiles or included in crash dumps
ErrorOr<void> lock_memory(void* ptr, size_t size);
// Undoes the above
ErrorOr<void> unlock_memory(void* ptr, size_t size);

}

#if USING_AK_GLOBALLY
using AK::secure_memzero;
using AK::timing_safe_compare;
#endif
