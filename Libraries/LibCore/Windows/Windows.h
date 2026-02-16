/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

// This folder is specifically for important Windows-only exported core code, not all LibCore Windows code.

#include <AK/Types.h>
#include <LibCore/Windows/OwnedHandle.h>
#include <LibCore/Windows/WindowsMemory.h>

#include <AK/Windows.h>

namespace Core::Windows {

ErrorOr<HANDLE> CreateLowPrivilegedAnonFileMap(size_t max_size_high, size_t max_size_low, [[maybe_unused]] ByteString name);
ErrorOr<void> SetCurrentProcessWindowStation(HWINSTA winstation);

// These must be valid SID strings
// They can be used with functions like ConvertStringSidToSid
class ProcessIntegrityLevel {
    static auto const SYSTEM = "S-1-16-16384";
    static auto const HIGH = "S-1-16-12288";
    static auto const MEDIUM = "S-1-16-8192";
    static auto const MEDIUM_LOW = "S-1-16-6144";
    static auto const LOW = "S-1-16-4096";
    static auto const BELOW_LOW = "S-1-16-2048";
    static auto const UNTRUSTED = "S-1-16-0";
}

}
