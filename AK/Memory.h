/*
 * Copyright (c) 2020, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2021-2022, Brian Gianforcaro <bgianf@serenityos.org>
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Types.h>

namespace AK {

void secure_memzero(void* ptr, size_t size);

void PoisonMemoryRegion(void* ptr, size_t size);

void UnpoisonMemoryRegion(void* ptr, size_t size);

// Naive implementation of a constant time buffer comparison function.
// The goal being to not use any conditional branching so calls are
// guarded against potential timing attacks.
//
// See OpenBSD's timingsafe_memcmp for more advanced implementations.
inline bool timing_safe_compare(void const* b1, void const* b2, size_t len)
{
    unsigned char const volatile* c1 = (unsigned char const volatile*)b1;
    unsigned char const volatile* c2 = (unsigned char const volatile*)b2;
    unsigned char volatile res = 0;

    for (size_t i = 0; i < len; i++) {
        res |= c1[i] ^ c2[i];
    }

    unsigned char nonzero = (unsigned char)((res | -res) >> 7);
    return (bool)(nonzero ^ 1);
}

}

#if USING_AK_GLOBALLY
using AK::PoisonMemoryRegion;
using AK::secure_memzero;
using AK::timing_safe_compare;
using AK::UnpoisonMemoryRegion;
#endif
