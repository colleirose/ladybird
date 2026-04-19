/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

// These are functions for interacting with access control lists (ACLs) and access control entries (ACEs)
// See https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists

#include <AK/Error.h>
#include <AK/Types.h>

#include <AK/Windows.h>
#include <aclapi.h>

namespace Core::Windows {

// Get the combined size of each access control entry (ACE) in an access control list (ACL)
ErrorOr<size_t> AclAcesSize(PACL pacl);

// Modify the pointer to an ACL to add new ACEs
ErrorOr<void> InsertAcesIntoAcl(PACL aces_source_acl, PACL target_acl);

}
