/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Error.h>
#include <AK/String.h>
#include <AK/Vector.h>
#include <LibCore/Process.h>
#include <LibWebView/Sandbox/Linux/SandboxPolicies.h>

namespace WebView::Sandbox {

bool IsBubblewrapSupported();
ErrorOr<Vector<ByteString>> CreateBwrapArguments(Core::ProcessSpawnOptions const& target_options);

}
