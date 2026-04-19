/*
 * Copyright (c) 2020, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2021-2022, Brian Gianforcaro <bgianf@serenityos.org>
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Assertions.h>
#include <AK/Format.h>
#include <AK/Memory.h>
#include <AK/Platform.h>

#if defined(AK_OS_WINDOWS)
#    include <AK/Windows.h>

#    include <Memoryapi.h>
#    include <psapi.h>
#else
#    include <sys/mman.h>

#    if !defined(MADV_DODUMP) && defined(MADV_CORE)
#        define MADV_DODUMP MADV_CORE
#        define MADV_DONTDUMP MADV_NOCORE
#    endif
#endif

namespace AK {

void secure_memzero(void* const ptr, size_t const size)
{
    if (!ptr || !size) [[unlikely]] {
        auto err = "secure_memzero was given invalid arguments:";
        if (!ptr)
            err += " invalid pointer";
        if (size == 0)
            err += " size is 0";

        warnln(err);
        return;
    }

#if defined(AK_OS_WINDOWS)
    SecureZeroMemory(ptr, size);
#else
    __builtin_memset(ptr, 0, size);
    // The memory barrier is here to avoid the compiler optimizing
    // away the memset when we rely on it for wiping secrets.
    asm volatile("" ::: "memory");
#endif
}

void secure_memzero(StringPtr ptr)
{
    if (ptr == nullptr) [[unlikely]] {
        warnln("secure_memzero was provided a String nullptr");
        return;
    }

    ReadonlyBytes& bytes = ptr->bytes();
    size_t size = bytes.size();
    if (size > 0) {
        secure_memzero(const_cast<u8*>(bytes.data()), size);
        // In case the string will still be used, replace it properly.
        // This operation could be optimized out if the string is never used again, but that's fine,
        // because we've already erased it.
        ptr->replace_with_new_string({ "", 0 });
    }
}

// Naive implementation of a constant time buffer comparison function.
// The goal being to not use any conditional branching so calls are
// guarded against potential timing attacks.
//
// See OpenBSD's timingsafe_memcmp for more advanced implementations.
bool timing_safe_compare(void const* b1, void const* b2, size_t len)
{
    auto c1 = reinterpret_cast<unsigned char const volatile*>(b1);
    auto c2 = reinterpret_cast<unsigned char const volatile*>(b2);
    unsigned char volatile res = 0;

    for (size_t i = 0; i < len; i++) {
        res |= c1[i] ^ c2[i];
    }

    unsigned char nonzero = ((res | -res) >> 7);
    return (bool)(nonzero ^ 1);
}

ErrorOr<void> lock_memory(void* ptr, size_t size)
{
    if (!ptr || !size) [[unlikely]]
        return Error::from_errno(EINVAL);

#if defined(AK_OS_WINDOWS)
    // continue to VirtualLock even if this fails, we'll probably still be able to successfully lock the memory,
    // though we might experience issues later
    ErrorOr<void> extend_res = extend_working_set(size);

    if (VirtualLock(ptr, size) != TRUE) {
        auto lock_error = Error::from_windows_error();

        if (extend_res.is_error()) {
            warnln(
                "failed to extend working set and failed to lock memory; returning locking error to caller. VirtualLock error: {}, working set error: {}",
                lock_error,
                extend_res.release_error());
        }

        return lock_error;
    }

    if (extend_res.is_error()) {
        // This counts as a success case because we've still locked the memory
        warnln("VirtualLock was successful, but extending the working set was not: {}", extend_res.release_error());
    }
#elif defined(MADV_DONTDUMP)
    if (madvise(ptr, size, MADV_DONTDUMP) != 0)
        return Error::from_errno(errno);
#elif defined(AK_OS_LINUX) || defined(AK_OS_MACOS)
    if (mlock(ptr, size) != 0)
        return Error::from_errno(errno);
#endif

    return {};
}

ErrorOr<void> unlock_memory(void* ptr, size_t size)
{
    if (!ptr || !size) [[unlikely]]
        return Error::from_errno(EINVAL);

#if defined(AK_OS_WINDOWS)
    if (VirtualUnlock(ptr, size) == TRUE) {
        TRY(reduce_working_set_memory(size));
    } else {
        return Error::from_windows_error();
    }
#elif defined(MADV_DODUMP)
    if (madvise(ptr, size, MADV_DODUMP) != 0)
        return Error::from_errno(errno);
#elif defined(AK_OS_LINUX) || defined(AK_OS_MACOS)
    if (munlock(ptr, size) != 0)
        return Error::from_errno(errno);
#endif

    return {};
}

#if defined(AK_OS_WINDOWS)
static bool has_sufficient_permissions = true;

inline bool is_win32_err_an_access_err(DWORD err_code)
{
    // The documentation for these functions doesn't specify the particular error codes they might return.
    // The list here is just from the official list of all Windows error codes:
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/1bc92ddf-b79e-413c-bbaa-99a5281a6c90
    static constexpr auto permissions_errors = Array {
        ERROR_ACCESS_DENIED,
        ERROR_EA_ACCESS_DENIED,
        // These errors would probably come from things like specific enterprise policies
        ERROR_ACCESS_DISABLED_BY_POLICY,
        ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY,
    };

    return permissions_errors.contains(err_code);
}

struct WindowsMemoryInformation {
    size_t max_working_set_size;
    size_t min_working_set_size;
    size_t total_unused_memory;
};

inline ErrorOr<WindowsMemoryInformation> get_memory_information()
{
    size_t current_max_working_set_size = 0;
    size_t current_min_working_set_size = 0;

    auto const return_error_value = [&](auto attempted_action) -> ErrorOr<WindowsMemoryInformation> {
        auto err = Error::from_windows_error();
        warnln("when getting memory information, failed to {} because of a Windows error: {}", attempted_action, err);
        if (is_win32_err_an_access_err(err.code))
            has_sufficient_permissions = false;
        return err;
    };

    if (GetProcessWorkingSetSize(GetCurrentProcess(), &current_min_working_set_size, &current_max_working_set_size) != TRUE)
        return return_error_value("get process working set size");

    PROCESS_MEMORY_COUNTERS memory_info;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &memory_info, sizeof(memory_info)) != TRUE)
        return return_error_value("get process memory information");

    return {
        .max_working_set_size = current_max_working_set_size,
        .min_working_set_size = current_min_working_set_size,
        .total_unused_memory = current_max_working_set_size - memory_info.WorkingSetSize,
    };
}

// We need to make sure the process working set is large enough to allow us to lock virtual memory.
// In some cases, trying to use VirtualLock to prevent some memory from being swapped to a pagefile
// won't be possible due to the program's working set being at maximum capacity, when the program
// otherwise wouldn't have errors because it would've previously still been able to swap to a pagefile.
inline ErrorOr<void> extend_working_set(size_t increase_size_by)
{
    if (!has_sufficient_permissions)
        return {};

    WindowsMemoryInformation mem_info = TRY(get_memory_information());

    if (mem_info.total_unused_memory < increase_size_by) {
        size_t max_working_set_size = mem_info.max_working_set_size + (increase_size_by - mem_info.total_unused_memory);
        size_t min_working_set_size = mem_info.min_working_set_size;
        if (SetProcessWorkingSetSize(GetCurrentProcess(), min_working_set_size, max_working_set_size) != TRUE) {
            auto err = Error::from_windows_error();
            warnln("can't set the process working set size to a new value: {}", err);

            // Errors would most likely be due to not having access and can be safely ignored in that case
            // as we're still unlikely to exceed the working set size regardless of whether this call succeeds,
            // but if they're not access errors, this would likely be an OOM error or another problematic condition,
            // and we need to return that as an error.
            if (is_win32_err_an_access_err(err.code())) {
                has_sufficient_permissions = false;
            } else {
                return err;
            }
        }
    }

    return {};
}

inline ErrorOr<void> reduce_working_set_memory(size_t decrease_size_by)
{
    if (!has_sufficient_permissions)
        return {};

    WindowsMemoryInformation mem_info = TRY(get_memory_information());

    size_t new_size = mem_info.max_working_set_size - decrease_size_by;
    if (mem_info.max_working_set_size > new_size) {
        // This can safely fail, there's not much we could do to handle an error here
        // and it's most likely that it'd fail just because the memory is still needed for something.
        if (SetProcessWorkingSetSize(GetCurrentProcess(), mem_info.min_working_set_size, new_size) != TRUE) {
            auto err = Error::from_windows_error();
            warnln("can't set process working set size to a lower value: {}", err);
            // Really shouldn't be possible to get this far and have a permission error, but check anyway
            if (is_win32_err_an_access_err(err.code))
                has_sufficient_permissions = false;
        }
    }

    return {};
}
#endif

}
