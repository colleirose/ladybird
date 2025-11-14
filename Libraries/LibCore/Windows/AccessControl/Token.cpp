/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Error.h>
#include <AK/ScopeGuard.h>
#include <LibCore/Windows/AccessControl/Token.h>

#include <AK/Windows.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")

namespace Core::Windows {

// Note that the caller needs to free the return value.
ErrorOr<PTOKEN_DEFAULT_DACL> GetTokenDefaultDacl(HANDLE token)
{
    DWORD token_length = 0;
    PTOKEN_DEFAULT_DACL val = (PTOKEN_DEFAULT_DACL)LocalAlloc(LPTR, token_length);
    if (!val)
        return Error::from_windows_error();

    GetTokenInformation(token, TokenDefaultDacl, nullptr, 0, &token_length); // calculate required size
    if (!GetTokenInformation(token, TokenDefaultDacl, val, token_length, &token_length))
        return Error::from_windows_error();

    return val;
}

ErrorOr<size_t> AclAcesSize(PACL pacl)
{
    if (!pacl)
        return Error::from_string_literal("invalid pointer");

    size_t acl_size = 0;
    for (size_t i = 0; i < acl->AceCount; i++) {
        LPVOID ace;
        if (!GetAce(acl, i, &ace))
            return Error::from_windows_error();
        acl_size += ((PACE_HEADER)ace)->AceSize;
    }

    return acl_size;
}

ErrorOr<void> InsertAcesIntoAcl(PACL new_aces_acl, PACL target_acl)
{
    if (!new_aces_acl)
        return Error::from_string_literal("invalid new_aces_acl");

    if (!target_acl)
        return Error::from_string_literal("invalid target_acl");

    LPVOID ace;
    for (DWORD i = 0; i < acl->AceCount; i++) {
        if (!GetAce(new_aces_acl, i, &ace))
            return Error::from_windows_error();

        if (!AddAce(target_acl, ACL_REVISION, MAXDWORD, ace,
                ((PACE_HEADER)ace)->AceSize))
            return Error::from_windows_error();
    }

    return {};
}

// By default a NULL DACL grants all access *until* you modify it to add some restrictions, in which case nothing is allowed.
// So if we want to modify a DACL that might be null, we can use this function to convert a null DACL to a DACL without restrictions.
ErrorOr<PSECURITY_DESCRIPTOR> EnsureNonNullDaclOnAbsoluteDescriptor(PSECURITY_DESCRIPTOR descriptor)
{
    PACL old_dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor, &dacl_present, &old_dacl, &dacl_defaulted))
        return Error::from_windows_error();

    // Nothing to do in this case
    if (dacl_present && old_dacl != nullptr)
        return descriptor;

    PSID everyone_sid = nullptr;
    PSID allapps_sid = nullptr;
    PACL new_dacl = nullptr;
    bool success = false;
    ScopeGuard guard = [&] {
        if (everyone_sid)
            Core::Windows::LocalFree(everyone_sid);

        if (allapps_sid)
            Core::Windows::LocalFree(allapps_sid);

        // We can only free new_dacl if we fail to modify the security descriptor,
        // otherwise it'll be owned by the descriptor and can't be freed
        if (new_dacl && !success)
            Core::Windows::LocalFree(new_dacl);
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
    auto res = SetEntriesInAclW(2, ea, nullptr, &new_dacl);
    if (res != ERROR_SUCCESS)
        return Error::from_windows_error(res);

    if (!SetSecurityDescriptorDacl(&descriptor, TRUE, new_dacl, FALSE))
        return Error::from_windows_error();

    success = true;
    return descriptor;
}

ErrorOr<PSECURITY_DESCRIPTOR> AbsoluteDescriptorFromRelative(PSECURITY_DESCRIPTOR relative_sd)
{
    DWORD sd_size = 0;
    DWORD dacl_size = 0;
    DWORD sacl_size = 0;
    DWORD owner_size = 0;
    DWORD group_size = 0;

    // deterine the required buffer size
    BOOL sd_success = MakeAbsoluteSD(relative_sd, nullptr, &sd_size, nullptr, &dacl_size, nullptr, &sacl_size,
        nullptr, &owner_size, nullptr, &group_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return Error::from_windows_error();

    // allocate memory
    bool success = false;
    PSECURITY_DESCRIPTOR absolute_sd_out = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, sd_size);
    PACL dacl = (PACL)LocalAlloc(LPTR, dacl_size);
    PACL sacl = (PACL)LocalAlloc(LPTR, sacl_size);
    PSID owner = (PSID)LocalAlloc(LPTR, owner_size);
    PSID group = (PSID)LocalAlloc(LPTR, group_size);

    // it's possible these have different errors but it's almost certainly just an out-of-memory error
    // checking after each call is super ugly so this is a better idea
    if (!absolute_sd_out || !dacl || !sacl || !owner || !group)
        return Error::from_windows_error();

    ScopeGuard guard = [&] {
        // we only want to free these if the function failed, otherwise they are going to be owned by the descriptor
        if (success)
            return;

        Core::Windows::LocalFree(dacl);
        Core::Windows::LocalFree(sacl);
        Core::Windows::LocalFree(owner);
        Core::Windows::LocalFree(group);
    };

    // create absolute SD
    if (!MakeAbsoluteSD(relative_sd, &absolute_sd_out, &sd_size,
            dacl, &dacl_size, sacl, &sacl_size,
            owner, &owner_size, group, &group_size))
        return Error::from_windows_error();

    success = true;
    return absolute_sd_out;
}

}
