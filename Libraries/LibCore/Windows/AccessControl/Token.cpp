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

// See Token.h for comments about what functions are for

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

}
