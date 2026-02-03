/*
 * Copyright (c) 2018-2020, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2021, Daniel Bertalan <dani@danielbertalan.dev>
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/kmalloc.h>

// Generally, we will initialize memory on allocation unless we're specifically asked not to (such as when malloc() is called).
// Similarly, if we know the size of some memory area when freeing, we'll take advantage of this to zero the memory before freeing it.

#if defined(AK_OS_SERENITY)

#    include <AK/Assertions.h>

// However deceptively simple these functions look, they must not be inlined.
// Memory allocated in one translation unit has to be deallocatable in another
// translation unit, so these functions must be the same everywhere.
// By making these functions global, this invariant is enforced.

void* operator new(size_t size)
{
    void* ptr = malloc(size);
    VERIFY(ptr);
    secure_memzero(ptr, size);
    return ptr;
}

void* operator new(size_t size, std::nothrow_t const&) noexcept
{
    void* ptr = malloc(size);
    secure_memzero(ptr, size); // note that secure_memzero performs a null pointer check, so checking here is redundant
    return ptr;
}

void operator delete(void* ptr) noexcept
{
    return free(ptr);
}

void operator delete(void* ptr, size_t size) noexcept
{
    secure_memzero(ptr, size);
    return free(ptr);
}

void* operator new[](size_t size)
{
    void* ptr = malloc(size);
    VERIFY(ptr);
    secure_memzero(ptr, size);
    return ptr;
}

void* operator new[](size_t size, std::nothrow_t const&) noexcept
{
    void* ptr = malloc(size);
    secure_memzero(ptr, size);
    return ptr;
}

void operator delete[](void* ptr) noexcept
{
    return free(ptr);
}

void operator delete[](void* ptr, size_t size) noexcept
{
    secure_memzero(ptr, size);
    return free(ptr);
}

// This is usually provided by libstdc++ in most cases, and the kernel has its own definition in
// Kernel/Heap/kmalloc.cpp. If neither of those apply, the following should suffice to not fail during linking.
namespace AK_REPLACED_STD_NAMESPACE {

nothrow_t const nothrow;

}

#endif
