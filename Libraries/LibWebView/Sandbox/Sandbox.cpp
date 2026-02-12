/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "Sandbox.h"
#include <AK/Format.h>
#include <AK/Platform.h>
#include <AK/String.h>
#include <LibCore/Process.h>

#if defined(AK_OS_WINDOWS)
    #include "./Windows/WindowsSandbox.h"
#elif defined(AK_OS_LINUX) && !defined(AK_OS_ANDROID) // FIX-BEFORE-PR: either allow android or add a comment explaining why we cant
    #include "./Linux/LinuxSandbox.h"
#endif

namespace WebView::Sandbox {

ErrorOr<void> ApplySyscallFiltersToCurrentProcess(WebView::ProcessType type)
{
    // This is as an abstraction around whatever functions we need to call to restrict the current process.
    // // On Windows this applies the process mitigation policy, on Linux this sets up seccomp, etc.
#if defined(AK_OS_WINDOWS)
    EnableWindowsProcessSecurityMitigations();
#elif defined(AK_OS_LINUX) && !defined(AK_OS_ANDROID)
    TRY(ApplySeccompToCurrentProcess(type));
#endif
    return {};
}

void LogGenericSandboxError(String failedAction, Error err)
{
    auto err_message = err.string_literal();
    warnln("Sandbox error: Failed to {}. This may lead to weakened security sandboxing. Error: {}", failedAction, err_message);
}

}
