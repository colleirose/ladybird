/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "WindowsSandbox.h"
#include <AK/Error.h>
#include <AK/Types.h>
#include <LibCore/Windows/AccessControl/SID.h>

namespace WebView::Sandbox {

enum class AppContainerCapability : u8 {
    Networking,
    Filesystem,
    Location,
    UserCertificates,
};

struct AppContainer {
    PSID sid;
    Vector<AppContainerCapability> capabilities;
};

ErrorOr<AppContainer> Sandbox::CreateAppContainer(Vector<AppContainerCapability> capabilities);

}
