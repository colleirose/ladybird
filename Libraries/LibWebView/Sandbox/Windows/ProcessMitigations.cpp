/*
 * Copyright (c) 2025, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "ProcessMitigations.h"
#include <AK/Error.h>

#include <AK/Windows.h>
#include <sddl.h>

// This code takes some inspiration from the Chromium source code, but no code is copied from there.
namespace WebView::Sandbox {

void EnableWindowsProcessSecurityMitigations()
{
    // Tries to limit which directories are searched for DLLs
    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS))
        LogGenericSandboxError("set default DLL directories", Error::from_windows_error());

    // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapsetinformation
    // Makes the Windows heap memory allocator terminate on corruption
    HANDLE process_heap = GetProcessHeap();
    if (!process_heap)
        LogGenericSandboxError("get heap information", Error::from_windows_error());

    if (!HeapSetInformation(process_heap, HeapEnableTerminationOnCorruption, NULL, 0))
        LogGenericSandboxError("set heap information", Error::from_windows_error());

    // This has its own helper function below due to being fairly long
    ApplyWindowsMitigationPolicies();

    return {};
}

static inline void SetMitigation(PROCESS_MITIGATION_POLICY policy,
    PVOID lpBuffer,
    SIZE_T dwLength)
{
    // Some of these mitigations require the user to be using specific versions of Windows, and some require hardware support.
    // If a mitigation fails to apply, this can be ignored for now.
    // See the various comments in https://github.com/chromium/chromium/blob/749811b9ce962b690ad3171633de72da822aedb8/sandbox/win/src/process_mitigations.cc
    // for more information on how this works
    // FIXME: Detect the user's specific Windows release and only apply mitigations that support their current Windows version
    if (!SetProcessMitigationPolicy(policy, lpBuffer, dwLength))
        LogGenericSandboxError("set mitigation policy", Error::from_windows_error());
}

// For more information on available mitigation policies, see:
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-SetMitigation
// https://blogs.windows.com/msedgedev/2017/02/23/mitigating-arbitrary-native-code-execution/
static inline void ApplyWindowsMitigationPolicies()
{
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_dep_policy
    // Usually this is enabled by default but some of the options like Permanent and DisableAtlThunkEmulation might not be
    PROCESS_MITIGATION_DEP_POLICY dep_policy = {};
    dep_policy.Enable = 1;
    dep_policy.DisableAtlThunkEmulation = 1;
    dep_policy.Permanent = 1;
    SetMitigation(ProcessDEPPolicy,
        &dep_policy, sizeof(dep_policy));

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_aslr_policy
    // ASLR is usually enabled by default but extra options like high entropy, force relocate, etc. are generally disabled by default
    PROCESS_MITIGATION_ASLR_POLICY aslr_policy = {};
    aslr_policy.EnableForceRelocateImages = 1;
    aslr_policy.EnableBottomUpRandomization = 1;
    aslr_policy.EnableHighEntropy = 1;
    aslr_policy.DisallowStrippedImages = 1;
    SetMitigation(ProcessASLRPolicy,
        &aslr_policy, sizeof(aslr_policy));

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_side_channel_isolation_policy
    PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY side_channel_policy = {};
    side_channel_policy.SmtBranchTargetIsolation = 1;
    side_channel_policy.IsolateSecurityDomain = 1;
    side_channel_policy.DisablePageCombine = 1;
    side_channel_policy.SpeculativeStoreBypassDisable = 1;
    side_channel_policy.RestrictCoreSharing = 1;
    SetMitigation(ProcessSideChannelIsolationPolicy,
        &side_channel_policy, sizeof(side_channel_policy));

    // https://learn.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-process_mitigation_image_load_policy
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY image_load_policy = {};
    image_load_policy.NoRemoteImages = 1;
    image_load_policy.PreferSystem32Images = 1;
    SetMitigation(ProcessImageLoadPolicy,
        &image_load_policy, sizeof(image_load_policy));

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_extension_point_disable_policy
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extension_point_policy = {};
    extension_point_policy.DisableExtensionPoints = 1;
    SetMitigation(ProcessStrictHandleCheckPolicy,
        &extension_point_policy, sizeof(extension_point_policy));

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process-mitigation-redirection-trust-policy
    PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY redirection_trust_policy = {};
    redirection_trust_policy.EnforceRedirectionTrust = 1;
    SetMitigation(ProcessRedirectionTrustPolicy,
        &redirection_trust_policy, sizeof(redirection_trust_policy));

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_system_call_disable_policy
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscall_disable_policy = {};
    // Fsctl performs various filesystem operations that we don't use
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-fsctls
    syscall_disable_policy.DisallowFsctlSystemCalls = 1;
    // FIXME: Support disabling Win32k syscalls
    // See https://projectzero.google/2016/11/breaking-chain.html
    // syscall_disable_policy.DisallowWin32kSystemCalls = 1;
    SetMitigation(ProcessSystemCallDisablePolicy,
        &syscall_disable_policy, sizeof(syscall_disable_policy));

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_strict_handle_check_policy
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handle_policy = {};
    handle_policy.HandleExceptionsPermanentlyEnabled = 1;
    handle_policy.RaiseExceptionOnInvalidHandleReference = 1;
    SetMitigation(ProcessStrictHandleCheckPolicy,
        &handle_policy, sizeof(handle_policy));
}

}
