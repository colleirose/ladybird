/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/Windows/WindowsMemory.h>

namespace Core::Windows {

// This performs the same function as the Windows HeapAlloc function, but also sets last error code on failure.
// Note that normal LocalAlloc sets the last error value so that isn't needed to be done here.
void HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    // Note that HeapAlloc would generally generate a STATUS_NO_MEMORY or similar exception on failure, but that isn't a valid value to set for the last error value.
    // Therefore, we've just manually found similar error codes. The error codes used here are from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/1bc92ddf-b79e-413c-bbaa-99a5281a6c90.
    if (!hHeap) [[unlikely]] {
        warnln("HeapAlloc was called on an invalid handle.");
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }

    LPVOID result = ::HeapAlloc(hHeap, dwFlags, dwBytes);

    // By default, HeapAlloc won't provide error information, but out of its possible errors, an out-of-memory error is the only likely one at this point.
    // See https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
    if (result == NULL) [[unlikely]] {
        warnln("HeapAlloc failed, likely out of memory.");
        SetLastError(ERROR_OUTOFMEMORY);
    }

    return result;
}

// The Windows free functions can fail and set the last error value,
// but we generally do not want that error to override the current last error value,
// as we often will free things at function exit or error handlers, where a previous failure is almost always more important than a failure to free what is typically a very small amount of memory.
void HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    if (!hHeap) [[unlikely]] {
        warnln("HeapFree was called on an invalid handle.");
        return;
    }

    DWORD previous_last_error = GetLastError();
    size_t size = HeapSize(hHeap);

    // This is the failure value, but no last error information is set.
    // It's unlikely that continuing to HeapFree will be successful, but let's try anyway.
    if (size == (SIZE_T)-1) [[unlikely]] {
        warnln("HeapSize() failed in Core::Windows::HeapFree, the memory is likely invalid. HeapFree will probably fail next.");
    } else {
        // Clear unneeded memory before freeing, as we don't know from a generic function like this if it contains sensitive content.
        secure_memzero(lpMem, size);
    }

    ::HeapFree(hHeap, dwFlags, lpMem);
    DWORD new_last_error = GetLastError();
    if (new_last_error != previous_last_error) [[unlikely]] {
        auto err = Error::from_windows_error();
        warnln("HeapFree failed: {}", err.string_literal());
        SetLastError(previous_last_error);
    }
}

void LocalFree(HLOCAL hMem)
{
    if (!hMem) [[unlikely]] {
        warnln("LocalFree was called on an invalid pointer");
        return;
    }

    DWORD previous_last_error = GetLastError();
    size_t size = LocalSize(hMem);
    if (size == 0) [[unlikely]] {
        // Unlike HeapSize(), LocalSize() sets last error information
        auto err = Error::from_windows_error();
        warnln(
            "LocalSize() failed in Core::Windows::LocalFree, the memory is likely invalid: {}. LocalFree will probably fail next.",
            err.string_literal());
    } else {
        secure_memzero((void*)hMem, size);
    }

    ::LocalFree(hMem);
    DWORD new_last_error = GetLastError();
    if (new_last_error != previous_last_error) [[unlikely]] {
        auto err = Error::from_windows_error();
        warnln("An error occurred in LocalFree: {}", err.string_literal());
        SetLastError(previous_last_error);
    }
}

}
