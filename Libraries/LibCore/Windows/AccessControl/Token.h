/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Error.h>
#include <AK/Types.h>
#include <LibCore/Windows/Windows.h>

#include <AK/Windows.h>

namespace Core::Windows {

ErrorOr<PTOKEN_DEFAULT_DACL> GetTokenDefaultDacl(HANDLE token);
ErrorOr<size_t> AclAcesSize(PACL pacl);
ErrorOr<void> InsertAcesIntoAcl(PACL new_aces_acl, PACL target_acl);
ErrorOr<PSECURITY_DESCRIPTOR> AbsoluteDescriptorFromRelative(PSECURITY_DESCRIPTOR relative_sd);
ErrorOr<PSECURITY_DESCRIPTOR> EnsureNonNullDaclOnAbsoluteDescriptor(PSECURITY_DESCRIPTOR descriptor);

}
