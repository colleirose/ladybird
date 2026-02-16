/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/Windows/Windows.h>

#include <AK/Windows.h>

namespace Core::Windows {

// Similar to CreateFileMapping, but removes the WRITE_DAC, WRITE_OWNER, READ_CONTROL, and DELETE privileges.
// This is useful if we pass the handle into an unprivileged proces.
// Idea from https://github.com/chromium/chromium/blob/88c4bbd2cc6fadc08e929b54b9c1543b495d1641/base/memory/platform_shared_memory_region_win.cc#L62-L98
ErrorOr<HANDLE> CreateLowPrivilegedAnonFileMap(size_t max_size_high, size_t max_size_low, [[maybe_unused]] ByteString name)
{
    HANDLE source_handle = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        (DWORD)max_size_high,
        (DWORD)max_size_low,
        name ? reinterpret_cast<wchar_t const*> name.characters() : NULL);

    if (!source_handle)
        return Error::from_windows_error();

    HANDLE process = GetCurrentProcess();
    HANDLE new_handle;
    if (!DuplicateHandle(
            process,
            source_handle,
            process,
            &new_handle,
            FILE_MAP_READ | FILE_MAP_WRITE | SECTION_QUERY,
            FALSE,
            DUPLICATE_CLOSE_SOURCE))
        return Error::from_windows_error();

    return new_handle;
}

ErrorOr<void> SetCurrentProcessWindowStation(HWINSTA winstation)
{
    if (!SetProcessWindowStation(winstation))
        return Error::from_windows_error();

    return {};
}

}
