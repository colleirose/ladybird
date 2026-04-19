/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Error.h>
#include <AK/Memory.h>
#include <AK/ScopeGuard.h>
#include <LibCore/Windows/AccessControl/Token.h>

#include <AK/Windows.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")

namespace Core::Windows {

ErrorOr<void*> GetTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS token_info_class)
{
    // calculate required size
    DWORD token_length = 0;
    DWORD initial_res = GetTokenInformation(token, token_info_class, nullptr, 0, &token_length);
    VERIFY(initial_res != 0);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return Error::from_windows_error();

    // allocate memory and get token info
    void* ptr = kmalloc(token_length);
    if (!ptr)
        return Error::from_errno(ENOMEM);

    if (!GetTokenInformation(token, token_info_class, ptr, token_length, &token_length)) {
        kfree_sized(ptr, token_length);
        return Error::from_windows_error();
    }

    return ptr;
}

}
