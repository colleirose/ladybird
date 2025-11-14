/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/Windows/Windows.h>

namespace Core::Windows {

void HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
void HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
void LocalFree(HLOCAL hMem);

}
