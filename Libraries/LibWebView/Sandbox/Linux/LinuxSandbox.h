/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "LinuxSandbox.h"
#include "SandboxPolicies.h"
#include "bubblewrap.h"
#include <AK/HashMap.h>
#include <LibWebView/Process.h>
#include <seccomp.h>

namespace WebView::Sandbox {

LinuxSandboxPolicy GetPolicyForProcessType(ProcessType type);
ErrorOr<ReadonlySpan<String>> GetAllowedSyscallsForPolicy(LinuxSandboxPolicy policy);
ErrorOr<scmp_filter_ctx> GetSeccompCtxForProcessType(ProcessType type);
ErrorOr<void> ApplySeccompToCurrentProcess(ProcessType type);

}
