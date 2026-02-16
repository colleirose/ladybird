/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Memory.h>
#include <AK/StdLibExtras.h>
#include <Libraries/LibCore/Windows/AccessControl/SID.h>

#pragma comment(lib, "advapi32.lib")

namespace Core::Windows {

ErrorOr<SID_AND_ATTRIBUTES> GetAppContainerCapabilitySidFromName(ByteString capability_name)
{
    SidArray capability_sids;
    SidArray group_sids;
    // HANDLE heap = GetProcessHeap();
    // if (!heap)
    //     return Error::from_windows_error();

    if (!DeriveCapabilitySidsFromName(
            reinterpret_cast<wchar_t const*> capability_name.characters(),
            group_sids.sids_ptr(),
            group_sids.count_ptr(),
            capability_sids.sids_ptr(),
            capability_sids.count_ptr()))
        return Error::from_windows_error();

    if (capability_sids.count() < 1)
        return Error::from_string_literal("failed to derive capability sid");

    // values from DeriveCapabilitySidsFromName are allocated with LocalAlloc and we can get their size via LocalSize,
    // but sometimes LocalAlloc allocates more than is requested.
    // however, we can be sure that the actual SID data doesn't exceed SECURITY_MAX_SID_SIZE.
    auto sid_ptr = capability_sids.sids()[0];
    size_t actual_allocation_size = LocalSize(sid_ptr);
    VERIFY(actual_allocation_size != 0);
    size_t sid_size = min(actual_allocation_size, SECURITY_MAX_SID_SIZE);

    PSID new_sid = (PSID)kmalloc(sid_size); // PSID new_sid = (PSID)Core::Windows::HeapAlloc(heap, 0, sid_size);
    if (!new_sid)
        return Error::from_errno(ENOMEM);

    if (!CopySid(sid_size, new_sid, sid_ptr)) {
        // we can only free the value if this fails
        kfree_sized(new_sid, sid_size); // Core::Windows::HeapFree(heap, 0, new_sid);
        return Error::from_windows_error();
    }

    SID_AND_ATTRIBUTES ret {};
    ret.Sid = new_sid;
    ret.Attributes = SE_GROUP_ENABLED;
    return ret;
}

}
