/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/Windows/WindowsMemory.h>

namespace Core::Windows {

// See WindowsMemory.h for comments on what functions do

// FIX-BEFORE-PR: Replacing heapalloc with kmalloc if it works (remember to look for the commented out heapalloc calls and remove or add back depending on which is needed).
// Also if we can replace heapalloc with kmalloc we can obviously replace heapfree with free
// Also if we can remove heapalloc and heapfree put the "see windowsmemory.h" above localfree and say like "see windowsmemory.h for what this is for" etc
// And move the "clear memory before freeing ..." comemnt inside localfree if this all can be done
// We may be able to also just get rid of the localalloc usages entirely

void LocalFree(HLOCAL hMem)
{
    DWORD previous_last_error = GetLastError();

    if (!hMem) [[unlikely]] {
        warnln("LocalFree was called on an invalid handle");
        return;
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
