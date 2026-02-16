/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "AppContainer.h"
#include "ProcessMitigations.h"
#include "Token.h"
#include "WindowObject.h"
#include <AK/Span.h>
#include <AK/String.h>
#include <AK/Types.h>
#include <LibCore/Process.h>
#include <LibWebView/Sandbox/Sandbox.h>

#include <AK/Windows.h>

namespace WebView::Sandbox {

struct WindowsSandboxPolicy {
    bool use_appcontainer;
    Core::Windows::ProcessIntegrityLevel integrity;
    Vector<AppContainerCapability> app_container_capabilities;
};

ErrorOr<HANDLE> GetSandboxedPrimaryToken();
WindowsSandboxPolicy GetPolicyForProcessType(ProcessType type);
ErrorOr<void> SetStartupInfoForDesktopAndPolicy(
    STARTUPINFOEXW& si,
    String alt_desktop_name,
    WindowsSandboxPolicy const& policy);

}
