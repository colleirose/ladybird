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
#    include "./Windows/WindowsSandbox.h"
#elif defined(AK_OS_LINUX)
#    include "./Linux/LinuxSandbox.h"
#endif

namespace WebView::Sandbox {

ErrorOr<void> ApplySyscallFiltersToCurrentProcess(WebView::ProcessType type)
{
    // This is as an abstraction around whatever functions we need to call to restrict the current process.
    // On Windows this applies the process mitigation policy, on Linux this sets up seccomp, etc.
#if defined(AK_OS_WINDOWS)
    EnableWindowsProcessSecurityMitigations();
#elif defined(AK_OS_LINUX)
    // Also covers Android
    TRY(ApplySeccompToCurrentProcess(type)); // FIX-BEFORE-PR: Test on Android
#endif
    return {};
}

void LogGenericSandboxError(String failedAction, Error err)
{
    auto err_message = err.string_literal();
    warnln("Sandbox error: Failed to {}. This may lead to weakened security sandboxing. Detailed error message: {}", failedAction, err_message);
}

}
