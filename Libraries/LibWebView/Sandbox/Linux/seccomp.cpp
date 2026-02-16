/**
 * Copyright (c) 2025-2026 Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "seccomp.h"

#include <AK/Assertions.h>
#include <AK/ByteString.h>
#include <AK/Error.h>
#include <AK/HashMap.h>
#include <AK/Platform.h>
#include <AK/StringBuilder.h>
#include <AK/StringView.h>
#include <AK/Types.h>
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

static HashMap<WebView::ProcessType, scmp_filter_ctx> proc_type_to_seccomp_ctx {};

namespace WebView::Sandbox {

static ErrorOr<void> AddDenyRule(scmp_filter_ctx ctx, int syscall_nr, int errno_val, int arg_count = 0, scmp_arg_cmp args = NULL)
{
    int rc;
    if (args) {
        rc = seccomp_rule_add(
            ctx,
            SCMP_ACT_ERRNO(errno_val),
            syscall_nr,
            arg_count,
            args);
    } else {
        rc = seccomp_rule_add(
            ctx,
            SCMP_ACT_ERRNO(errno_val),
            syscall_nr,
            0);
    }

    if (rc != 0)
        return Error::from_errno(rc);

    return {};
}

static ErrorOr<void> AddAllowRule(scmp_filter_ctx ctx, int syscall_nr, ByteString name)
{
    // Add parameter restrictions for a generally allowed syscall if needed, otherwise just allow the syscall
    // FIXME: This is rather messy; we need to rework this, especially once there's more to add here.
    auto add_restrictions_and_otherwise_allow = [&](int errno_val, int arg_count, scmp_arg_cmp args) -> ErrorOr<void> {
        TRY(AddDenyRule(ctx, syscall_nr, errno_val, arg_count, args));

        int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 0);
        if (rc != 0)
            return Error::from_errno(rc);

        return {};
    };

    if (name == "mmap") {
        // hugetlb is generally useless in a browser and has had security issues in the past
        // https://github.com/mozilla-firefox/firefox/blob/e378f44562245e675730580d935069112efe6864/security/sandbox/linux/SandboxFilter.cpp#L1147-L1170
        constexpr int forbid = MAP_HUGETLB | (MAP_HUGE_MASK << MAP_HUGE_SHIFT);

        // FIX-BEFORE-PR: wrong args?
        TRY(add_restrictions_and_otherwise_allow(ENOSYS, 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, forbid, forbid)));
        return {};
    }

    if (name == "memfd_create") {
        // See above
        constexpr int forbid = MFD_HUGETLB | (MFD_HUGE_MASK << MFD_HUGE_SHIFT);

        TRY(add_restrictions_and_otherwise_allow(ENOSYS, 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, forbid, forbid)));
        return {};
    }

    if (name == "ioctl") {
        // see, e.g., https://github.com/flatpak/flatpak/blob/b37f739721e219159cad4791a894ae4e7f1daa2a/common/flatpak-run.c#L1954-L1959
        TRY(add_restrictions_and_otherwise_allow(EPERM, 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, (int)TIOCSTI)));
        TRY(add_restrictions_and_otherwise_allow(EPERM, 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, (int)TIOCLINUX)));
        return {};
    }

    // Default: allow all
    int rule_add_res = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 0);
    if (rule_add_res != 0)
        return Error::from_errno(rule_add_res);

    return {};
}

static Vector<ByteString> GetAllowedSyscallsForPolicy(LinuxSandboxPolicy policy)
{
    Vector<ByteString> allowed = always_allowed_syscalls;

    if (policy.allowed_capabilities.contains(LinuxCapability::Networking))
        allowed.extend(SyscallNameLists::networking);

    if (policy.allowed_capabilities.contains(LinuxCapability::ProcessManagement))
        allowed.extend(SyscallNameLists::process_management);

    // bubblewrap will provide specific restrictions on what files can be accessed
    if (policy.allowed_capabilities.contains(LinuxCapability::FilesystemEmpty)) {
        allowed.extend(SyscallNameLists::filesystem_basic);
    }

    if (policy.allowed_capabilities.contains(LinuxCapability::FilesystemUserFiles) || policy.allowed_capabilities.contains(LinuxCapability::FilesystemCacheFiles)) {
        if (!policy.allowed_capabilities.contains(LinuxCapability::FilesystemEmpty))
            allowed.extend(SyscallNameLists::filesystem_basic);
        allowed.extend(SyscallNameLists::filesystem_additional);
    }

    return allowed;
}

ErrorOr<scmp_filter_ctx> GetSeccompCtxForProcessType(ProcessType type)
{
    // NOTE: Don't free the seccomp context with seccomp_release() unless it's a browser process, the same context is reusable for different processes of the same type.
    if (proc_type_to_seccomp_ctx.contains(type))
        return proc_type_to_seccomp_ctx.find(type);

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    // The libseccomp manual doesn't seem to indicate how to get information on why seccomp_init failed, but from reading the source code it seems to be mainly an OOM error.
    if (ctx == NULL)
        return Error::from_string_literal("Failed to initialize seccomp context, the system is likely out of memory.");

    auto policy = GetPolicyForProcessType(type);
    auto allowed_syscalls = GetAllowedSyscallsForPolicy(policy);

    // Add allowed syscalls
    for (ByteString const name : allowed_syscalls) {
        int syscall_nr = seccomp_syscall_resolve_name(name.characters());
        if (syscall_nr == __NR_SCMP_ERROR) {
            // we shouldn't have invalid syscalls here, but a failure at this point isn't fatal on its own
            warnln("An error occurred adding the {} syscall to seccomp, this is likely an invalid syscall for this platform (maybe an outdated kernel?), skipping this syscall.", name);
            continue;
        }

        TRY(AddAllowRule(ctx, syscall_nr, name));
    }

    // Change the errno for denied syscalls where EPERM is invalid or undesired
    for (ByteString const name : errno_override_if_denied) {
        if (!allowed_syscalls.contains(name)) {
            int syscall_nr = seccomp_syscall_resolve_name(name.characters());
            // a lot of these are arch specific, so just skip anything that's invalid
            if (syscall_nr == __NR_SCMP_ERROR)
                continue;

            auto errno_val = errno_override_if_denied.find(name);
            TRY(AddDenyRule(ctx, syscall_nr, errno_val));
        }
    }

    if (!(policy.allowed_capabilities.contains(LinuxCapability::FilesystemUserFiles) || policy.allowed_capabilities.contains(LinuxCapability::FilesystemCacheFiles))) {
        // Prefer errors of the file not existing when filesystem perms are denied if that's not overriden for the syscall
        for (ByteString const name : SyscallNameLists::filesystem) {
            if (!errno_override_if_denied.includes(name)) {
                int syscall_nr = seccomp_syscall_resolve_name(name.characters());
                if (syscall_nr == __NR_SCMP_ERROR)
                    continue;

                TRY(AddDenyRule(ctx, syscall_nr, ENOENT));
            }
        }
    }

    // Done
    if (type != ProcessType::Browser)
        TRY(proc_type_to_seccomp_ctx.try_set(type, ctx));

    return ctx;
}

ErrorOr<void> WriteSeccompCtxToFd(scmp_filter_ctx const ctx, int fd)
{
    int res = seccomp_export_bpf(ctx, fd);
    if (res != 0)
        return Error::from_errno(res);

    return {};
}

ErrorOr<void> ApplySeccompToCurrentProcess(ProcessType type)
{
    scmp_filter_ctx ctx = TRY(GetSeccompCtxForProcessType(type));
    int load_result = seccomp_load(ctx);

    if (type == ProcessType::Browser)
        seccomp_release(ctx);

    if (load_result != 0)
        return Error::from_errno(load_result);

    return {};
}

}
