/**
 * Copyright (c) 2025-2026 Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "LinuxSandbox.h"

#include <AK/Assertions.h>

namespace WebView::Sandbox {

LinuxSandboxPolicy GetPolicyForProcessType(ProcessType type)
{
    // FIX-BEFORE-PR: unsure which of these restrictions work and what could maybe be removed
    switch (type) {
    case ProcessType::Unspecified:
        return {
            .use_bubblewrap = true,
            .allowed_capabilities = {},
        };
    case ProcessType::ImageDecoder:
        return {
            .use_bubblewrap = true,
            .allowed_capabilities = {
                LinuxCapability::FilesystemEmpty, // basic filesystem access is required for AnonymousBuffer to work correctly
            },
        };
    case ProcessType::RequestServer: {
        return
        {
            .use_bubblewrap = true,
            .allowed_capabilities = {
                LinuxCapability::Networking,
                LinuxCapability::FilesystemCacheFiles,
            }
        }
    }
    case ProcessType::WebContent:
    case ProcessType::WebWorker:
        return {
            .use_bubblewrap = true,
            .allowed_capabilities = {
                // LinuxCapability::Networking,
                // LinuxCapability::FilesystemUserFiles,
                LinuxCapability::FilesystemCacheFiles,
                LinuxCapability::ProcessManagement,
            },
        };
    case ProcessType::Browser:
        return {
            .use_bubblewrap = false,
            .allowed_capabilities = {
                LinuxCapability::Networking,
                LinuxCapability::FilesystemUserFiles,
                LinuxCapability::FilesystemCacheFiles,
                LinuxCapability::ProcessManagement,
            },
        };
    default:
        VERIFY_NOT_REACHED();
    }
}

}
