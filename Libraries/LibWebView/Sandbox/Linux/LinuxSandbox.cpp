/**
 * Copyright (c) 2025-2026 Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "LinuxSandbox.h"

#include <AK/Assertions.h>
#include <AK/Error.h>
#include <AK/HashMap.h>
#include <AK/Platform.h>
#include <AK/ScopeGuard.h>
#include <AK/Span.h>
#include <AK/String.h>
#include <AK/StringBuilder.h>
#include <AK/StringView.h>
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

static HashMap<ProcessType, scmp_filter_ctx> type_to_filter_map {};

static inline ErrorOr<void> AddDenyRule(scmp_filter_ctx ctx, int syscall_nr, int errno_val, int arg_count, [[maybe_unused]] scmp_arg_cmp args)
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
        VERIFY(arg_count == 0);
        rc = seccomp_rule_add(
            ctx,
            SCMP_ACT_ERRNO(errno_val),
            syscall_nr,
            arg_count);
    }

    if (rc != 0)
        return Error::from_errno(rc);

    return {};
}

static inline ErrorOr<void> AddAllowRule(scmp_filter_ctx ctx, int syscall_nr, String name)
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

    // FIX-BEFORE-PR: one of these might have incorrect parameters because of the mismatch between args count and whats in SCMP_CMP? im not sure
    if (name == "mmap") {
        // hugetlb is generally useless in a browser and has had security issues in the past
        // https://github.com/mozilla-firefox/firefox/blob/e378f44562245e675730580d935069112efe6864/security/sandbox/linux/SandboxFilter.cpp#L1147-L1170
        constexpr int forbid = MAP_HUGETLB | (MAP_HUGE_MASK << MAP_HUGE_SHIFT);
        TRY(add_restrictions_and_otherwise_allow(ENOSYS, 1, SCMP_CMP(3, SCMP_CMP_MASKED_EQ, forbid, forbid)));
        return {};
    }

    if (name == "memfd_create") {
        // See above
        constexpr int forbid = MFD_HUGETLB | (MFD_HUGE_MASK << MFD_HUGE_SHIFT);
        TRY(add_restrictions_and_otherwise_allow(ENOSYS, 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, forbid, forbid)));
        return {};
    }

    // Default: allow all
    int rule_add_res = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 0);
    if (rule_add_res != 0)
        return Error::from_errno(rule_add_res);

    return {};
}

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

ErrorOr<Vector<String>> GetAllowedSyscallsForPolicy(LinuxSandboxPolicy policy)
{
    Vector<String> allowed = base_syscalls;

    if (policy.allowed_capabilities.contains(LinuxCapability::Networking)) {
        auto networking_syscalls = SyscallNameLists::networking_syscalls;
        for (i = 0; i < networking_syscalls.size(); i++)
            TRY(allowed.try_append(networking_syscalls[i]));
    }

    // bubblewrap.cpp will provide particular restrictions based on the file location
    if (policy.allowed_capabilities.contains(LinuxCapability::FilesystemUserFiles) || policy.allowed_capabilities.contains(LinuxCapability::FilesystemCacheFiles)) {
        auto filesystem_syscalls = SyscallNameLists::filesystem_syscalls;
        for (i = 0; i < filesystem_syscalls.size(); i++)
            TRY(allowed.try_append(filesystem_syscalls[i]));
    }

    if (policy.allowed_capabilities.contains(LinuxCapability::ProcessManagement)) {
        auto process_management_syscalls = SyscallNameLists::process_management_syscalls;
        for (i = 0; i < process_management_syscalls.size(); i++)
            TRY(allowed.try_append(process_management_syscalls[i]));
    }

    return allowed;
}

ErrorOr<scmp_filter_ctx> GetSeccompCtxForProcessType(ProcessType type)
{
    // NOTE: Don't free the seccomp context with seccomp_release() unless it's a browser process, the same context is reusable for different processes of the same type.
    if (type_to_filter_map.contains(type))
        return type_to_filter_map.find(type);

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    // The libseccomp manual doesn't seem to indicate how to get information on why seccomp_init failed.
    if (ctx == NULL)
        return Error::from_string_literal("Failed to initialize seccomp context");

    auto policy = GetPolicyForProcessType(type);
    auto allowed_syscalls = TRY(GetAllowedSyscallsForPolicy(policy));

    // Add allowed syscalls
    for (auto const* name : allowed_syscalls) {
        int syscall_nr = seccomp_syscall_resolve_name(name);
        if (syscall_nr == __NR_SCMP_ERROR) {
            // we're supposed to not have invalid syscalls here but a failure at this point isn't fatal on its own
            warnln("An error occurred adding the {} syscall to seccomp, this is likely an invalid syscall for this platform. Skipping.", name);
            continue;
        }

        TRY(AddAllowRule(ctx, syscall_nr, name));
    }

    // Change the errno for denied syscalls where EPERM isn't valid
    for (auto const& name : SyscallNameLists::errno_override) {
        if (!allowed_syscalls.contains(name)) {
            auto chars = name.characters_without_null_termination();
            int syscall_nr = seccomp_syscall_resolve_name(chars);
            // a lot of these are arch specific, so just skip anything that's invalid
            if (syscall_nr == __NR_SCMP_ERROR)
                continue;

            auto errno_val = type_to_filter_map.find(name);
            TRY(AddDenyRule(ctx, syscall_nr, errno_val, 0));
        }
    }

    // Done
    if (type != ProcessType::Browser)
        TRY(type_to_filter_map.try_set(type, ctx));

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
