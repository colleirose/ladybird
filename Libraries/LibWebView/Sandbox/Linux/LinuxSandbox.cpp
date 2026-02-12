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
    switch (type) {
    case ProcessType::Unspecified:
        return {
            .use_bubblewrap = true,
            .allowed_capabilities = {},
        };
    case ProcessType::ImageDecoder:
        return {
            .use_bubblewrap = true,
            .allowed_capabilities = {},
        };
    case ProcessType::RequestServer: {
        return
        {
            .use_bubblewrap = true,
            .allowed_capabilities = {
                LinuxCapability::Networking,
                LinuxCapability::FilesystemCacheFiles, // http disk caching
            }
        }
    }
    case ProcessType::WebContent:
    case ProcessType::WebWorker:
        return {
            .use_bubblewrap = true,
            // FIX-BEFORE-PR: most of these can probably be restricted?
            .allowed_capabilities = {
                // LinuxCapability::Networking,
                LinuxCapability::FilesystemUserFiles, // FIX-BEFORE-PR: unsure?
                LinuxCapability::FilesystemCacheFiles,
                LinuxCapability::ProcessManagement, // FIX-BEFORE-PR: unsure?
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
