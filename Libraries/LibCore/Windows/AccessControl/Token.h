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

// Wrapper around GetTokenInformation() that automatically determines the required size, does the memory allocation, and then calls the function
ErrorOr<void*> GetTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS token_info_class);

}
