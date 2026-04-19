/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Error.h>
#include <AK/Platform.h>
#include <AK/String.h>
#include <AK/Types.h>
#include <LibWebView/Process.h>

#if defined(AK_OS_WINDOWS)
#    include <LibWebView/Sandbox/Windows/WindowsSandbox.h>
#elif defined(AK_OS_LINUX)
#    include <LibWebView/Sandbox/Linux/LinuxSandbox.h>
#endif

namespace WebView::Sandbox {

ErrorOr<void> ApplySyscallFiltersToCurrentProcess(WebView::ProcessType type);
void LogGenericSandboxError(String failedAction, Error err);

}
