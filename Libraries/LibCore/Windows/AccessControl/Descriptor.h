/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Error.h>

#include <AK/Windows.h>

// Functions for interacing with [security descriptors](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors)

namespace Core::Windows {

// By default a NULL DACL (discretionary access list) grants all access *until* you modify it to add some restrictions, in which case nothing is allowed.
// So if we want to modify a security descriptor's DACL and it might be null, we can use this function to convert a null DACL to an unrestricted non-null DACL.
ErrorOr<void> MakeAbsoluteDescriptorDaclNotNull(PSECURITY_DESCRIPTOR descriptor);

// Obtain an absolute security descriptor from a relative security descriptor
ErrorOr<PSECURITY_DESCRIPTOR> GetAbsoluteDescriptorFromRelative(PSECURITY_DESCRIPTOR relative_sd);

}
