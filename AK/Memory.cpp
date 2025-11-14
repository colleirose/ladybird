/*
 * Copyright (c) 2020, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2021-2022, Brian Gianforcaro <bgianf@serenityos.org>
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Assertions.h>
#include <AK/Format.h>
#include <AK/Memory.h>
#include <AK/Platform.h>

namespace AK {

void secure_memzero(void* ptr, size_t size)
{
    // This is expected by kmalloc and other places to check for invalid arguments
    if (!ptr || size == 0) [[unlikely]] {
        warnln("secure_memzero was given invalid data");
        return;
    }

#if defined(AK_OS_WINDOWS)
    SecureZeroMemory(ptr, size);
#else
    __builtin_memset(ptr, 0, size);
    // The memory barrier is here to avoid the compiler optimizing
    // away the memset when we rely on it for wiping secrets.
    asm volatile("" ::
            : "memory");
#endif
}

// These functions allow us to test for write-after-free conditions at runtime with lower overhead than we'd get with AddressSanitizer, and also has the benefit of erasing possibly sensitive information from memory.
void PoisonMemoryRegion(void* ptr, size_t size)
{
#if defined(HAS_ADDRESS_SANITIZER)
    ASAN_POISON_MEMORY_REGION(ptr, size);
#else
    // fatal in this case because we want to be sure that we're using this on valid memory
    VERIFY(ptr != nullptr && size != 0);
    secure_memzero(ptr, size);
#endif
}

void UnpoisonMemoryRegion(void* ptr, size_t size)
{
#if defined(HAS_ADDRESS_SANITIZER)
    ASAN_UNPOISON_MEMORY_REGION(ptr, size);
#else
    VERIFY(ptr != nullptr && size != 0);
    for (char* p = (char*)ptr; p < ((char*)ptr) + size; p++) {
        if (*p != 0) [[unlikely]] {
            perror("detected use-after-free");
            VERIFY_NOT_REACHED();
        }
    }
#endif
}

}
