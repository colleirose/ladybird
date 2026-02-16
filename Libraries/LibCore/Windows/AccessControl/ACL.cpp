/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "ACL.h"
#pragma comment(lib, "advapi32.lib")

namespace Core::Windows {

// See ACL.h for information on what functions do

ErrorOr<size_t> AclAcesSize(PACL pacl)
{
    if (!pacl)
        return Error::from_string_literal("invalid pointer");

    size_t acl_size = 0;
    void* ace;
    for (size_t i = 0; i < pacl->AceCount; i++) {
        if (!GetAce(pacl, i, &ace))
            return Error::from_windows_error();
        acl_size += ((PACE_HEADER)ace)->AceSize;
    }

    return acl_size;
}

ErrorOr<void> InsertAcesIntoAcl(PACL aces_source_acl, PACL aces_insert_acl)
{
    if (!aces_source_acl)
        return Error::from_string_literal("invalid aces_source_acl");

    if (!aces_insert_acl)
        return Error::from_string_literal("invalid aces_insert_acl");

    void* ace;
    for (DWORD i = 0; i < aces_source_acl->AceCount; i++) {
        if (!GetAce(aces_source_acl, i, &ace))
            return Error::from_windows_error();

        if (!AddAce(aces_insert_acl, ACL_REVISION, MAXDWORD, ace,
                ((PACE_HEADER)ace)->AceSize))
            return Error::from_windows_error();
    }

    return {};
}

}
