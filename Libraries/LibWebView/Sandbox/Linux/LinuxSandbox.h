/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "SandboxPolicies.h"
#include "bubblewrap.h"
#include "seccomp.h"

#include <LibWebView/ProcessType.h>

namespace WebView::Sandbox {

LinuxSandboxPolicy GetPolicyForProcessType(ProcessType type);

}
