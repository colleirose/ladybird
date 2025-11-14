/*
 * Copyright (c) 2025-2026 Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Userenv.lib")

#include "AppContainer.h"
#include <AK/Error.h>
#include <AK/Hex.h>
#include <AK/ReadonlySpan.h>
#include <AK/ScopeGuard.h>
#include <AK/Span.h>
#include <AK/String.h>
#include <AK/StringBuilder.h>
#include <AK/StringView.h>
#include <AK/Try.h>

#include <AK/Windows.h>
#include <AclAPI.h>
#include <memory>
#include <sddl.h>
#include <userenv.h>
#include <winerror.h>

using InternalWindowsCapabilities = Vector<SID_AND_ATTRIBUTES>;

namespace WebView::Sandbox {

inline ErrorOr<InternalWindowsCapabilities> GetWindowsCapabilityData(Vector<AppContainerCapability> capabilities)
{
    // Create a list of capability nanmes
    Vector<ByteString> capability_names;
    if (capabilities.contains(AppContainerCapability::Networking)) {
        constexpr auto network_capabilities = Array {
            L"internetClient",
            L"privateNetworkClientServer", // Needed for accessing localhost and local network sites
        };

        for (size_t i = 0; i < network_capabilities.length; i++)
            TRY(capability_names.try_append(network_capabilities[i]));
    }

    if (capabilities.contains(AppContainerCapability::Filesystem)) {
        // FIXME: In the future we could use the file picker and other tools to avoid the need for broad filesystem access
        // For now we are in an earlier stage of sandboxing functionality and we're mostly looking at
        // making it more difficult for the browser to become an attack vector to gain persistent control of the system.
        // But these definitely need to be restricted more once everything else is stable.
        constexpr auto filesystem_capabilities = Array {
            L"documentsLibrary",
            L"musicLibrary",
            L"picturesLibrary",
            L"videosLibrary",
            L"removableStorage",
        };

        for (size_t i = 0; i < filesystem_capabilities.length; i++)
            TRY(capability_names.try_append(filesystem_capabilities[i]));
    }

    if (capabilities.contains(AppContainerCapability::Location)) {
        // For the web location API
        TRY(capability_names.try_append(L"location"));
    }

    if (capabilities.contains(AppContainerCapability::UserCertificates)) {
        // Needed for things like U2F authentication
        TRY(capability_names.try_append(L"sharedUserCertificates"));
    }

    // Construct the Windows data
    DWORD capability_count = capability_names.size();
    InternalWindowsCapabilities internal_caps;
    TRY(internal_caps.try_ensure_capacity(capability_count * sizeof(SID_AND_ATTRIBUTES)));

    // FIX-BEFORE-PR:
    // auto internal_caps = (PSID_AND_ATTRIBUTES)Core::Windows::HeapAlloc(GetProcessHeap(), 0, capability_count * sizeof(SID_AND_ATTRIBUTES));
    for (DWORD i = 0; i < capability_count; ++i) {
        auto sid = TRY(Core::Windows::GetAppContainerCapabilitySidFromName(capability_names[i]));
        TRY(internal_caps.try_append(sid));
    }

    return internal_caps;
}

// Either create the AppContainer profile or retrieve it if it's already available
// Note, please make sure we are not creating duplicate appcontainer profiles for the same thing
// and that the profiles have consistent names, because we are currently never deleting them.
// So to make sure this doesn't waste resources, make sure that the same capabilities always result in the same name.
ErrorOr<AppContainer> CreateAppContainer(Vector<AppContainerCapability> capabilities)
{
    // It's also possible to manually create the container to prevent it from automatically registering with the system firewall service, but that doesn't seem necessary right now:
    // https://github.com/chromium/chromium/commit/d496c863762a0d19cfaacb59aa1a22f749a22016#diff-d46aa9dde3ef2d0f8a118828b075bfb57afd88f5a3e3481ca1fe504630c95d47
    auto windows_capabilities = TRY(GetWindowsCapabilityData(capabilities));

    // We need to generate a new ID for each unique app container configuration.
    //
    // Per https://github.com/chromium/chromium/blob/5063a0792a5b0b89f2a1d38ff52c9acc9c08d6a3/sandbox/policy/win/sandbox_win.cc#L336-L371,
    // on most systems the maximum profile name length is 64, but on obscure [WCOS](https://betawiki.net/wiki/Windows_Core_OS) systems, it is 50.
    //
    // So this generates a unique ID for each container that is always under 50 characters.
    ByteBuffer cap_bytes;
    for (DWORD i = 0; i < windows_capabilities.size(); ++i) {
        auto cap = windows_capabilities[i];
        wchar_t* sid_string_buf = NULL;

        if (!ConvertSidToStringSidW(cap.sid, &sid_string_buf))
            return Error::from_windows_error();

        // FIX-BEFORE-PR: this might just be wrong but im too tired to test right now
        TRY(cap_bytes.try_append(*sid_string_buf));
        Core::Windows::LocalFree(sid_string_buf);
    }

    u32 hash = cap_bytes.hash();
    ByteString container_name = ByteString::formatted("ladybird{}", encode_hex(hash));
    // sanity check so that changes that accidentally increase the length beyond 50 are immediately apparent
    if (container_name.length() > 50)
        return Error::from_string_literal("AppContainer name is too long");

    // Now we can actually get the profile
    PSID local_sid = nullptr;
    HRESULT hr = CreateAppContainerProfile(
        (PCWSTR)container_name.characters(),
        L"Ladybird",
        L"Ladybird web browser",
        // FIX-BEFORE-PR: this doesnt feel like itd really work
        (windows_capabilities.is_empty() ? NULL : &windows_capabilities.data()),
        (DWORD)windows_capabilities.size(),
        &local_sid);

    if (FAILED(hr)) {
        if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
            // seems like this function can only fail for invalid arguments, so it is likely mostly infallible with our usage
            hr = DeriveAppContainerSidFromAppContainerName((PCWSTR)container_name.characters(), &local_sid);
            if (hr != S_OK)
                return Error::from_windows_error();
        } else {
            return Error::from_windows_error();
        }
    }

    return {
        .sid = local_sid,
        .capabilities = capabilities,
    };
}

}
