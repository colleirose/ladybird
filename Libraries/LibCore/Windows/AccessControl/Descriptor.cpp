/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/Windows/AccessControl/Descriptor.h>

#include <AK/Windows.h>
#include <aclapi.h>

namespace Core::Windows {

#pragma comment(lib, "advapi32.lib")

// See Descriptor.h for comments about what functions are for

ErrorOr<void> MakeAbsoluteDescriptorDaclNotNull(PSECURITY_DESCRIPTOR descriptor)
{
    // this could also go in ACL.cpp, but whatever
    PACL current_descriptor_dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor, &dacl_present, &current_descriptor_dacl, &dacl_defaulted))
        return Error::from_windows_error();

    // Nothing to do in this case
    // (FIX-BEFORE-PR: See if we can make some test code to create a null dacl happen to test that everything works)
    if (dacl_present && current_descriptor_dacl != nullptr)
        return descriptor;

    PSID everyone_sid = nullptr;
    PSID allapps_sid = nullptr;
    PACL new_descriptor_dacl = nullptr;
    bool success = false;
    ScopeGuard guard = [&] {
        // FIX-BEFORE-PR: Is this safe to do?

        // if (everyone_sid)
        //     FreeSid(everyone_sid);

        // if (allapps_sid)
        //     FreeSid(allapps_sid);

        // We can only free new_descriptor_dacl if we fail to modify the security descriptor,
        // otherwise it'll be owned by the descriptor and can't be freed
        if (new_descriptor_dacl && !success)
            kfree_sized(new_descriptor_dacl);
    };

    // Build a barebones permissive DACL
    EXPLICIT_ACCESS_W ea[2] = {};
    SID_IDENTIFIER_AUTHORITY world_auth = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY apppkg_auth = SECURITY_APP_PACKAGE_AUTHORITY;

    if (!AllocateAndInitializeSid(&world_auth, 1, SECURITY_WORLD_RID,
            0, 0, 0, 0, 0, 0, 0, &everyone_sid))
        return Error::from_windows_error();

    if (!AllocateAndInitializeSid(&apppkg_auth, 2, SECURITY_APP_PACKAGE_BASE_RID,
            SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE, 0, 0, 0, 0, 0, 0, &allapps_sid))
        return Error::from_windows_error();

    // Everyone
    ea[0].grfAccessMode = GRANT_ACCESS;
    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPWSTR)everyone_sid;

    // All apps
    ea[1].grfAccessMode = GRANT_ACCESS;
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = (LPWSTR)allapps_sid;

    // Set the new DACL
    DWORD res = SetEntriesInAclW(2, ea, nullptr, &new_descriptor_dacl);
    if (res != ERROR_SUCCESS)
        return Error::from_windows_error(res);

    if (!SetSecurityDescriptorDacl(&descriptor, TRUE, new_descriptor_dacl, FALSE))
        return Error::from_windows_error();

    success = true;
    return {};
}

ErrorOr<PSECURITY_DESCRIPTOR> GetAbsoluteDescriptorFromRelative(PSECURITY_DESCRIPTOR relative_sd)
{
    DWORD sd_size = 0;
    DWORD dacl_size = 0;
    DWORD sacl_size = 0;
    DWORD owner_size = 0;
    DWORD group_size = 0;

    // Determine the required buffer size and allocate memory
    BOOL sd_success = MakeAbsoluteSD(relative_sd, nullptr, &sd_size, nullptr, &dacl_size, nullptr, &sacl_size,
        nullptr, &owner_size, nullptr, &group_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return Error::from_windows_error();

    PSECURITY_DESCRIPTOR absolute_sd_out = (PSECURITY_DESCRIPTOR)kmalloc(sd_size);
    PACL dacl = (PACL)kmalloc(dacl_size);
    PACL sacl = (PACL)kmalloc(sacl_size);
    PSID owner = (PSID)kmalloc(owner_size);
    PSID group = (PSID)kmalloc(group_size);
    if (!absolute_sd_out || !dacl || !sacl || !owner || !group)
        return Error::from_errno(ENOMEM);

    ArmedScopeGuard guard = [&] {
        // we can only free these if the function failed, otherwise they are going to be owned by the descriptor
        kfree_sized(absolute_sd_out, sd_size);
        kfree_sized(dacl, dacl_size);
        kfree_sized(sacl, sacl_size);
        kfree_sized(owner, owner_size);
        kfree_sized(group, group_size);
    };

    // Create and return the descriptor
    if (!MakeAbsoluteSD(relative_sd, &absolute_sd_out, &sd_size,
            dacl, &dacl_size, sacl, &sacl_size,
            owner, &owner_size, group, &group_size))
        return Error::from_windows_error();

    guard.disarm();
    return absolute_sd_out;
}

}
