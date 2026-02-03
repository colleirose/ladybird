/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/Windows/Windows.h>

namespace Core::Windows {

// This performs the same function as the Windows HeapAlloc function, but also sets last error code on failure.
// Note that the Windows LocalAlloc does set the last error value so we don't need that here.
LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);

// The Windows free functions can fail and set the last error value, but we don't need that error to override the current last error value,
// as we often will free things at function exit or error handlers, where a previous failure is almost always more important than a failure to free what is typically a very small amount of memory.
void HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
void LocalFree(HLOCAL hMem);

}
