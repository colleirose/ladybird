/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Format.h>
#include <AK/Platform.h>
#include <AK/String.h>
#include <LibCore/Process.h>
#include <LibWebView/Sandbox/Sandbox.h>

namespace WebView::Sandbox {

ErrorOr<void> ApplySyscallFiltersToCurrentProcess(WebView::ProcessType type)
{
    // This is as an abstraction around whatever functions we need to call to restrict the current process.
    // // On Windows this applies the process mitigation policy, on Linux this sets up seccomp, etc.
#if defined(AK_OS_WINDOWS)
    TRY(EnableWindowsProcessSecurityMitigations());
    sandbox_primary_token = TRY(CreateSandboxedPrimaryToken());
#elif defined(AK_OS_LINUX) && !defined(AK_OS_ANDROID)
    TRY(ApplySeccompToCurrentProcess(type));
#endif
    return {};
}

void LogGenericSandboxFailureFromError(String failedAction, Error err)
{
    auto err_message = err.string_literal();
    warnln("Sandbox error: Failed to {}. This may lead to weakened security sandboxing. Error: {}", failedAction, err_message);
}

}
