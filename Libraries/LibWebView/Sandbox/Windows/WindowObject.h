/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "SandboxWinows.h"
#include <AK/Utf16String.h>

namespace WebView::Sandbox {

struct DesktopObject {
    HDESK alt_desktop;
    Utf16String name;
};

ErrorOr<HWINSTA> GetSandboxedWindowStation();
ErrorOr<DesktopObject> GetSandboxedAltDesktop(HWINSTA winsta = nullptr);

private:
ErrorOr<void> FixTokenDefaultDaclForWindowObjects(HANDLE token, HWINSTA winsta, HDESK desktop);

}
