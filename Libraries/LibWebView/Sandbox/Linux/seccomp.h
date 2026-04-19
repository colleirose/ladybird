/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "LinuxSandbox.h"
#include "SandboxPolicies.h"
#include "bubblewrap.h"
#include <LibWebView/ProcessType.h>
#include <seccomp.h>

namespace WebView::Sandbox {

ErrorOr<scmp_filter_ctx> GetSeccompCtxForProcessType(ProcessType type);
ErrorOr<void> ApplySeccompToCurrentProcess(ProcessType type);
ErrorOr<void> WriteSeccompCtxToFd(scmp_filter_ctx const ctx, int fd);

}
