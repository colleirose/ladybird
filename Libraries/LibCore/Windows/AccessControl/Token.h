/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Error.h>
#include <AK/Types.h>
#include <LibCore/Windows/Windows.h>

#include <AK/Windows.h>

// Functions for interacing with [access tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)

namespace Core::Windows {

// Get the default discretionary access list (DACL) for a token. Note that the caller needs to free the return value.
ErrorOr<PTOKEN_DEFAULT_DACL> GetTokenDefaultDacl(HANDLE token);

}
