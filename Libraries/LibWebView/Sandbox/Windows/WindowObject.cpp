/**
 * Copyright (c) 2025-2026 Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

// FIX-BEFORE-PR: add back experimentally if this breaks later
// #define _WIN32_WINNT 0x0500

#include "WindowObject.h"
#include <AK/Assertions.h>
#include <AK/Error.h>
#include <AK/Platform.h>
#include <AK/ScopeGuard.h>
#include <AK/Try.h>
#include <LibCore/Windows/AccessControl/ACL.h>
#include <LibCore/Windows/AccessControl/Token.h>

#include <AK/Windows.h>
#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

/**
 * By default, Windows applications running with the same desktop object are able to send and receive messages to each other,
 * which would possibly allow a malicious unprivileged process to interact with the browser, or a compromised browser to interfere with other processes.
 *
 * This is the source of the "shatter attacks" that have affected Windows, see:
 * https://en.wikipedia.org/wiki/Shatter_attack
 *
 * Creating our own desktop and window station object prevents other applications from interacting with the browser,
 * and prevents a compromised browser from interacting with other applications.
 *
 * See:
 * https://chromium.googlesource.com/chromium/src/+/master/docs/design/sandbox.md#The-alternate-desktop
 */

static Optional<DesktopObject> s_alt_desktop;
static Optional<HWINSTA> s_alt_winsta;

// This idea is based on Chromium, but the code isn't directly copied from there.
namespace WebView::Sandbox {

static ALWAYS_INLINE ErrorOr<void> SetCurrentProcessWindowStation(HWINSTA winstation)
{
    if (!SetProcessWindowStation(winstation))
        return Error::from_windows_error();

    return {};
}

// FIX-BEFORE-PR: this is wrong
ErrorOr<void> FixTokenDefaultDaclForWindowObjects(HANDLE token, HWINSTA winsta, HDESK desktop)
{
    DWORD token_length = 0;
    PSECURITY_DESCRIPTOR winsta_sd = nullptr;
    PSECURITY_DESCRIPTOR desktop_sd = nullptr;
    PTOKEN_DEFAULT_DACL old_token_default = TRY((PTOKEN_DEFAULT_DACL)Core::Windows::GetTokenInfo(token, TokenDefaultDacl));

    ScopeGuard guard = [&] {
        if (winsta_sd)
            LocalFree(winsta_sd);

        if (desktop_sd)
            LocalFree(desktop_sd);

        if (old_token_default)
            LocalFree(old_token_default);
    };

    // Get information about the window station and desktop
    PACL winsta_dacl = nullptr;
    PACL desktop_dacl = nullptr;
    DWORD result;

    result = GetSecurityInfo(
        winsta,
        SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &winsta_dacl,
        nullptr,
        &winsta_sd);
    if (result != ERROR_SUCCESS)
        return Error::from_windows_error();

    result = GetSecurityInfo(
        desktop,
        SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &desktop_dacl,
        nullptr,
        &desktop_sd);
    if (result != ERROR_SUCCESS)
        return Error::from_windows_error(result);

    if (!GetTokenInformation(token, TokenDefaultDacl,
            old_default, token_length, &token_length))
        return Error::from_windows_error();

    // Calculate the total size needed
    DWORD new_acl_size = sizeof(ACL);
    new_acl_size += TRY(Core::Windows::AclAcesSize(old_default->DefaultDacl));
    new_acl_size += TRY(Core::Windows::AclAcesSize(winsta_dacl));
    new_acl_size += TRY(Core::Windows::AclAcesSize(desktop_dacl));

    // Allocate the new ACL
    PACL new_acl = (PACL)LocalAlloc(LPTR, new_acl_size);
    if (!InitializeAcl(new_acl, new_acl_size, ACL_REVISION))
        return Error::from_windows_error();

    TRY(Core::Windows::InsertAcesIntoAcl(old_default->DefaultDacl, new_acl));
    TRY(Core::Windows::InsertAcesIntoAcl(winsta_dacl, new_acl));
    TRY(Core::Windows::InsertAcesIntoAcl(desktop_dacl, new_acl));

    // Apply the new merged ACL
    TOKEN_DEFAULT_DACL new_default = {};
    new_default.DefaultDacl = new_acl;

    if (!SetTokenInformation(token, TokenDefaultDacl,
            &new_default, sizeof(new_default))) {
        // this is the only case where the token will not have ownership of the ACL and therefore we can free it
        // otherwise it must not be freed
        LocalFree(new_acl);
        return Error::from_windows_error();
    }

    return {};
}

ErrorOr<HWINSTA> GetSandboxedWindowStation()
{
    if (s_alt_winsta.has_value())
        return *s_alt_winsta;

    PSECURITY_DESCRIPTOR sec_descriptor_relative = nullptr;
    PSECURITY_DESCRIPTOR sec_descriptor_absolute = nullptr;

    // is it actually safe to free these here?
    // uncomment and test once stuff is working
    // ScopeGuard guard = [&] {
    //     if (sec_descriptor_absolute)
    //         LocalFree(sec_descriptor_absolute);

    //     if (sec_descriptor_relative)
    //         LocalFree(sec_descriptor_relative);
    // };

    HWINSTA current_win_station = GetProcessWindowStation();
    if (!current_win_station)
        return Error::from_windows_error();

    if (GetSecurityInfo(current_win_station, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr, &sec_descriptor_relative)
        != ERROR_SUCCESS) {
        return Error::from_windows_error(result);
    }

    sec_descriptor_absolute = TRY(GetAbsoluteDescriptorFromRelative(sec_descriptor_relative));
    SECURITY_ATTRIBUTES sec_attributes = { sizeof(SECURITY_ATTRIBUTES), sec_descriptor_absolute, FALSE };

    HWINSTA new_window_station = CreateWindowStation(nullptr, 0, GENERIC_READ | WINSTA_CREATEDESKTOP, &sec_attributes);
    if (!new_window_station && GetLastError() == ERROR_ACCESS_DENIED)
        new_window_station = CreateWindowStation(nullptr, 0, WINSTA_READATTRIBUTES | WINSTA_CREATEDESKTOP, &sec_attributes);

    if (!new_window_station)
        return Error::from_windows_error();

    s_alt_winsta = new_window_station;
    return new_window_station;
}

ErrorOr<DesktopObject> GetSandboxedAltDesktop(HWINSTA winsta = nullptr)
{
    if (s_alt_desktop.has_value())
        return *s_alt_desktop;

    // Generate the name, we use it at the end
    auto name_builder = StringBuilder(Mode::UTF16, 64);
    auto id = GetCurrentProcessId();
    name_builder.append(winsta ? "desktop_alt_" : "desktop_alt_winstation_");
    name_builder.append(Utf16String::number(id)); // FIX-BEFORE-PR: do we need to do .utf16_view() ?
    auto alt_desktop_name = name_builder.to_utf16_string();

    // We will use the current desktop privileges as the base for the new desktop privileges
    HDESK current_desktop = GetThreadDesktop(GetCurrentThreadId());
    if (!current_desktop)
        return Error::from_windows_error();

    PACL new_dacl = nullptr;
    PSECURITY_DESCRIPTOR desktop_absolute_descriptor = nullptr;
    PSECURITY_DESCRIPTOR desktop_relative_descriptor = nullptr;
    ArmedScopeGuard guard = [&] {
        if (desktop_absolute_descriptor)
            free(desktop_absolute_descriptor);

        if (desktop_relative_descriptor)
            free(desktop_relative_descriptor);

        if (new_dacl)
            free(new_dacl);
    };

    auto get_sec_info_res = GetSecurityInfo(current_desktop, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &desktop_relative_descriptor);
    if (get_sec_info_res != ERROR_SUCCESS)
        return Error::from_windows_error(get_sec_info_res);

    desktop_absolute_descriptor = TRY(Core::Windows::GetAbsoluteDescriptorFromRelative(desktop_relative_descriptor));

    // If the DACL is NULL, the desktop would currently have no restrictions, but become inaccessible after any changes are applied.
    // Therefore, if it is NULL, we'll first apply a policy that allows access, and then apply the restrictions
    TRY(Core::Windows::MakeAbsoluteDescriptorDaclNotNull(desktop_absolute_descriptor));

    // get the security descriptor DACL into desktop_absolute descriptor
    // we have to provide a pointer to receive dacl_present and dacl_defaulted even though we don't check them here
    PACL old_dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(desktop_absolute_descriptor, &dacl_present, &old_dacl, &dacl_defaulted))
        return Error::from_windows_error();

    // Deny unnecessary permissions to the restricted group as an extra mitigation
    // It's okay for this to fail because it's only extra hardening
    SID_IDENTIFIER_AUTHORITY nt_authority_sid = SECURITY_NT_AUTHORITY;
    PSID restricted_group_sid = nullptr;
    auto init_sid_res = AllocateAndInitializeSid(
        &nt_authority_sid,
        1,
        SECURITY_RESTRICTED_CODE_RID,
        0, 0, 0, 0, 0, 0, 0,
        &restricted_group_sid);

    // restricted_group_sid is still used but nt_authority_sid is not
    // (this might be incorrect so uncomment and test it once other things are working)
    // if (nt_authority_sid)
    //     FreeSid(&nt_authority_sid);

    if (!init_sid_res) {
        LogGenericSandboxError("initialize SECURITY_RESTRICTED_CODE_RID (continuing anyway)", Error::from_windows_error());
    } else {
        EXPLICIT_ACCESS_W deny_ea = {};
        deny_ea.grfAccessMode = DENY_ACCESS;
        deny_ea.grfAccessPermissions = WRITE_DAC | WRITE_OWNER | DELETE | DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW | DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK | DESKTOP_JOURNALRECORD | DESKTOP_SWITCHDESKTOP;
        deny_ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        deny_ea.Trustee.ptstrName = (LPWSTR)restricted_group_sid;

        if (SetEntriesInAclW(1, &deny_ea, old_dacl, &new_dacl) == ERROR_SUCCESS) {
            if (!SetSecurityDescriptorDacl(desktop_absolute_descriptor, TRUE, new_dacl, FALSE))
                LogGenericSandboxError("set desktop security descriptor (continuing anyway)", Error::from_windows_error());
        } else {
            LogGenericSandboxError("modify new_dacl to add deny_ea (continuing anyway)", Error::from_windows_error());
        }
    }

    // Now start creating the desktop
    HWINSTA old_winsta = GetProcessWindowStation();
    if (winsta) {
        // If we've been provided a window station, we need to temporarily change to that window station to work with it
        if (!old_winsta)
            return Error::from_windows_error();

        if (winsta != old_winsta)
            TRY(SetCurrentProcessWindowStation(winsta));
    }

    auto name_bytestring = alt_desktop_name.to_byte_string();
    SECURITY_ATTRIBUTES attributes = { sizeof(SECURITY_ATTRIBUTES), desktop_absolute_descriptor, FALSE };
    HDESK desktop = CreateDesktopW(
        reinterpret_cast<wchar_t const*> name_bytestring.characters(), NULL, NULL, 0,
        DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
        &attributes);

    // per https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror,
    // we should store the last error value if we're going to call more windows functions before using it
    // even successful results can overwrite the last error value
    auto desktop_lasterror_value = GetLastError();

    if (winsta && winsta != old_winsta) {
        // Restore previous window station now that we're done working with it
        if (auto res = SetCurrentProcessWindowStation(old_winsta); res.is_error()) {
            if (!desktop) {
                // properly log a scenario where both CreateDesktop and SetProcessWindowStation fail
                auto desktop_err = Error::from_windows_error(desktop_lasterror_value);
                LogGenericSandboxError("create a valid desktop object", desktop_err);
            }

            return res.error();
        }
    }

    if (desktop == NULL)
        return Error::from_windows_error(desktop_lasterror_value);

    guard.disarm();
    // FIX-BEFORE-PR: should this have the * or no
    *s_alt_desktop = {
        .alt_desktop = desktop,
        .name = alt_desktop_name,
    };
    return *s_alt_desktop;
}

}
