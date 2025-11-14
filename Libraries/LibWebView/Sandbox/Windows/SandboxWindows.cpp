/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Assertions.h>
#include <AK/Error.h>
#include <AK/ScopeGuard.h>
#include <LibWebView/Sandbox/Windows/SandboxWindows.h>

#include <AK/Windows.h>

static Optional<HANDLE> s_sandbox_token;

namespace WebView::Sandbox {

// FIX-BEFORE-PR: need to fix my vm and all the other code before i can possibly finish working on this
ErrorOr<HANDLE> GetSandboxedPrimaryToken()
{
    if (s_sandbox_token.has_value())
        return *s_sandbox_token;

    HANDLE previous_token = NULL;
    HANDLE new_token = NULL;
    DWORD group_count = 0;

    HANDLE process_heap = GetProcessHeap();
    if (!process_heap)
        return Error::from_windows_error();

    // open token
    constexpr DWORD token_access
        = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

    if (!OpenProcessToken(GetCurrentProcess(), token_access, &previous_token))
        return Error::from_windows_error();

    // duplicate the token
    if (!DuplicateTokenEx(previous_token, token_access, NULL, SecurityImpersonation, TokenPrimary, &new_token))
        return Error::from_windows_error();

    PSID integrity_sid = NULL;
    PTOKEN_GROUPS* groups = nullptr;
    ScopeGuard guard = [&] {
        if (groups)
            Core::Windows::HeapFree(process_heap, 0, groups);

        if (integrity_sid)
            Core::Windows::LocalFree(integrity_sid);
    }

    // restrict token groups
    // FIX-BEFORE-PR: this obviously doesnt work but i dont remember what the original reason for it was
    // there has to be some purpose for this though, i need to figure it out

    // if (!GetTokenInformation(new_token, TokenGroups, nullptr, 0, &group_count))
    //     return Error::from_windows_error();

    // groups = (PTOKEN_GROUPS)Core::Windows::HeapAlloc(process_heap, 0, group_count);
    // if (!GetTokenInformation(new_token, TokenGroups, groups, group_count, &group_count))
    //     return Error::from_windows_error();

    // for (DWORD i = 0; i < groups->GroupCount; ++i) {
    //     groups->Groups[i].Attributes &= ~SE_GROUP_ENABLED;
    //     groups->Groups[i].Attributes |= SE_GROUP_USE_FOR_DENY_ONLY;
    // }

    // if (!SetTokenInformation(new_token, TokenGroups, groups, group_count))
    //     return Error::from_windows_error();

    // set integrity_sid to a low privileged SID
    auto process_integrity_level
        = Core::Windows::ProcessIntegrityLevel::LOW;
    if (!ConvertStringSidToSidW(process_integrity_level, &integrity_sid))
        return Error::from_windows_error();

    // sanity check; the GetLengthSid() documentation encourages you to verify the SID before calling GetLengthSid()
    if (!IsValidSid(integrity_sid))
        return Error::from_string_literal("integrity_sid is invalid");

    // set the process integrity level to a low integrity level to restrict permissions
    TOKEN_MANDATORY_LABEL label = { 0 };
    label.Label.Attributes = SE_GROUP_INTEGRITY;
    label.Label.Sid = integrity_sid;

    if (!SetTokenInformation(new_token, TokenIntegrityLevel, &label,
            sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(integrity_sid)))
        return Error::from_windows_error();

    // FIX-BEFORE-PR: we still need to set SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP but that isnt done yet

    // set some extra restrictions for the token
    // TOKEN_MANDATORY_POLICY policy = { 0 };
    // policy.Policy = TOKEN_MANDATORY_POLICY_NO_WRITE_UP | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN;

    // if (!SetTokenInformation(new_token, TokenMandatoryPolicy, &policy, sizeof(TOKEN_MANDATORY_POLICY)))
    //     return Error::from_windows_error();

    // FIX-BEFORE-PR: this just seems wrong
    TRY(FixTokenDefaultDaclForWindowObjects(new_token, alt_winsta, alt_desktop));

    s_sandbox_token = new_token;
    return new_token;
}

// FIX-BEFORE-PR: move to AppContainer.cpp
ErrorOr<void> CreateAppContainerAttributesForPolicy(WindowsSandboxPolicy const& policy)
{
    if (!policy.use_appcontainer)
        return Error::from_string_literal("tried to create AppContainer attributes for a policy that doesn't support AppContainer");

    bool success = false;
    HANDLE heap = GetProcessHeap();
    if (!heap)
        return Error::from_windows_error();

    // determine buffer size and allocate buffer
    size_t size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    auto* attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)Core::Windows::HeapAlloc(heap, 0, size);
    if (!attrs)
        return Error::from_windows_error();

    ScopeGuard guard = [&] {
        // we can only free attrs if the function was unsuccesful, because on success it is going to be used by the startupinfo
        if (!success) {
            DeleteProcThreadAttributeList(attrs);
            Core::Windows::HeapFree(heap, 0, attrs);
        }
    };

    // initialize the attribute list and add appcontainer
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &size))
        return Error::from_windows_error();

    AppContainer appcontainer = TRY(CreateAppContainer(policy.app_container_capabilities));

    SECURITY_CAPABILITIES caps = {};
    auto internal_caps = appcontainer.internal_windows_capabilities;
    caps.AppContainerSid = appcontainer.sid;
    // it feels like this might not work
    caps.Capabilities = (internal_caps.is_empty() ? NULL : internal_caps.data());
    caps.CapabilityCount = static_cast<DWORD>(internal_caps.count());

    if (!UpdateProcThreadAttribute(
            attrs,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &caps,
            sizeof(caps),
            nullptr,
            nullptr)) {
        return Error::from_windows_error();
    }

    success = true;
    return attrs;
}

WindowsSandboxPolicy GetPolicyForProcessType(ProcessType type)
{
    switch (type) {
    case ProcessType::ImageDecoder:
        return
        {
            .use_appcontainer = true,
            .app_container_capabilities = {},
        }
    case ProcessType::RequestServer: {
        .use_appcontainer = true,
        .app_container_capabilities = {
            AppContainerCapability::Networking
        },
    }
    case ProcessType::WebContent:
    case ProcessType::WebWorker:
        return
        {
            // FIXME: These capabilities could probably be made more restrictive, eg we could possibly use the file picker instead of needing access to all of the home folder,
            // and we likely don't need to grant the location and certificate access to all these processes
            .use_appcontainer = true,
            .app_container_capabilities = {
                // AppContainerCapability::Networking, // (will it work to restrict this right now?)
                AppContainerCapability::Filesystem,
                AppContainerCapability::Location,
                AppContainerCapability::UserCertificates
            },
        }
    case ProcessType::Browser:
        return
        {
            .use_appcontainer = false,
            .app_container_capabilities = {},
        }
    default:
        VERIFY_NOT_REACHED();
    }
}

}
