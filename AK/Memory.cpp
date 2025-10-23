/*
 * Copyright (c) 2020, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2021-2022, Brian Gianforcaro <bgianf@serenityos.org>
 * Copyright (c) 2025, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Memory.h>
#include <AK/Platform.h>
#if defined(AK_OS_WINDOWS)
#    include <AK/Windows.h>
#endif

namespace AK {

void secure_memzero(void* ptr, size_t size)
{
    if (ptr == nullptr || size == 0) [[unlikely]] {
        return;
    }
#if defined(AK_OS_WINDOWS)
    SecureZeroMemory(ptr, size);
#else
    // As far as we can tell, this seems to be the best way to ensure that the compiler doesn't optimize out the instructions
    __builtin_memset(ptr, 0, size);
    asm volatile("" ::"r"(ptr)
        : "memory");
#endif
}

// Naive implementation of a constant time buffer comparison function.
// The goal being to not use any conditional branching so calls are
// guarded against potential timing attacks.
//
// See OpenBSD's timingsafe_memcmp for more advanced implementations.
bool timing_safe_compare(void const* b1, void const* b2, size_t len) {
    unsigned char const* c1 = (unsigned char const*)b1;
    unsigned char const* c2 = (unsigned char const*)b2;
    unsigned char volatile res = 0;

    for (size_t i = 0; i < len; i++) {
        res |= c1[i] ^ c2[i];
    }

    // It seems like most other implementation of constant-time comparison return an integer instead of a bool,
    // but we usually prefer to use booleans instead of integers for true-false comparisons.
    //
    // While we previously just did `return !res`, there has been concern that some compilers would create branching conditions from it.
    //
    // So, the final return value is more of a best-effort, and while it's very unlikely that this code would create branching conditions,
    // this still hasn't been extensively verified, so no certain guarantees.
    unsigned char nonzero = (unsigned char)((res | -res) >> 7);
    return (bool)(nonzero ^ 1);
}

}
