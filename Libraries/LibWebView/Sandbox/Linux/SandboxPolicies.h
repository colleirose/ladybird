/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Types.h>
#include <AK/Vector.h>

namespace WebView::Sandbox {

enum class LinuxCapability : u8 {
    Networking,
    FilesystemUserFiles,
    FilesystemCacheFiles,
    ProcessManagement,
};

struct LinuxSandboxPolicy {
    bool use_bubblewrap;
    Vector<LinuxCapability> allowed_capabilities;
};

// Override errno to something other than EPERM for denied syscalls where EPERM isn't valid
HashMap<StringView, int> errno_override = {
    // Filesystem
    // Prefer errors of the file not existing where that's valid because that's the most likely to be handled
    { "uselib"sv, EACCES },
    { "ustat"sv, EINVAL },
    { "stat"sv, ENOENT },
    { "newfstatat"sv, ENOENT },
    { "fstatat64"sv, ENOENT },
    { "statfs"sv, ENOENT },
    { "access"sv, ENOENT },
    { "lstat"sv, ENOENT },
    { "readlink"sv, ENOENT },
    { "faccessat"sv, ENOENT },
    { "faccessat2"sv, ENOENT },
};

class SyscallNameLists {
    // Some of the research into available syscall restrictions and attack surface is based on some code from Chromium and Firefox,
    // but nothing is directly copied from there:
    // https://github.com/mozilla-firefox/firefox/blob/e378f44562245e675730580d935069112efe6864/security/sandbox/linux/SandboxFilter.cpp
    // https://github.com/chromium/chromium/tree/17d6154909794b987c0726e45aad332439e4e7dd/sandbox/policy/linux
    //
    // This isn't enough on its own to be useful as complete sandboxing, rather it's just a starting point for attack surface reduction;
    // bubblewrap is used for more complete sandboxing to allow more restricted access.
    // See `Documentation/Sandboxing.md` for more information.
    //
    // FIXME: We should directly use namespaces and chroot so that sandboxing works even if bubblewrap isn't available.
    static constexpr auto base_syscalls = {
        // Basic info about the system and process
        "uname",
        "sysconf",
        "getrlimit",
        "setrlimit",
        "getcpu",
        "getenv",
#if ARCH(AARCH64)
        "getauxval", // Used on ARM by OpenSSL to check for several system features and in LibCore/System.cpp to check for MTE support
#endif
        "getuid",
        "getgid",
        "geteuid",
        "geteguid",
        "getpid",
        "gettid",
        "getcwd", // Maybe this could be restricted?
        // Simple process management that isn't restricted, like closing or restarting the process
        "restart",
        "futex", // FIXME: Futex should be more restrictive, see https://bugzilla.mozilla.org/show_bug.cgi?id=1441993 and https://github.com/chromium/chromium/blob/f2d2cad7697c941615847ae503eb9b3b64773cce/sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions.cc#L361-L383
        "exit",
        "exit_group",
        // Epoll
        "epoll_create",
        "epoll_wait",
        "epoll_pwait",
        "epoll_create1",
        "epoll_ctl",
        // Time
        "clock_nanosleep",
        "clock_gettime",
        "time",
        "gettimeofday",
        "usleep",
        // CSPRNG
        "getrandom",
        "getentropy", // Although AK/Random doesn't use getentropy(), some dependencies might, like OpenSSL. It exposes basically the same attack surface as getrandom(), so it's fine.
        // Memory management
        "madvise",
        "mmap",
        "munmap",
        "mremap",
        "mlock",
        "munlock",
        "mlockall",
        "munlockall",
        "mprotect",
        "pkey_alloc",
        "pkey_mprotect",
        "mseal",
        "munseal",
        "msync",
        "fsync",
        "membarrier",
        "brk",          // not called by us directly but may be invoked by a system allocator like glibc
        "memfd_create", // FIXME: Currently memfd_create is assumed to be available in most of the process, however we may be able to make this more restrictive
        // Used by IPC and also for networking.
        // FIXME: Almost all of these can be made more restrictive.
        // FIX-BEFORE-PR: not full list and some of these names are just wrong
        // also its not very well organized; also maybe i can add some restrictions myself too before pr
        "recvmsg",
        "sendmsg",
        "recvfrom",
        "sendto",
        "recv",
        "send",
        "recvfrom",
        "socketpair",
        "getsockopt",
        "getsockname",
        "getpername",
        "setsockopt",
        "socket",
        "connect",
        "accept",
        "accept4",
        "bind",
        // Misc things
        "mincore", // see https://bugzilla.mozilla.org/show_bug.cgi?id=1462640. FIX-BEFORE-PR: Might not be needed here but needs more testing.
        "ioctl",   // FIXME: Should be restricted to specific parameters, but currently used for IPC and networking.
        "fcntl",   // Used for IPC, maybe this could be more restricted?
        // FIX-BEFORE-PR: Some of the IPC stuff I should figure out during testing because I don't think all processes use the same IPC calls
        // FIX-BEFORE-PR: actually restrict ioctl more
    };

    static constexpr auto networking_syscalls = {
        // FIXME: These are *very* permissive and should be restricted much more than they are now,
        // according to Chromium and Firefox code comments it is "impossible" to effectively sandbox getaddrinfo
        // and some of the other syscalls listed here. However, a lot of work has to be done to further restrict this.
        "getaddrinfo", // FIX-BEFORE-PR: apparently x11 uses getaddrinfo locally
        "socketcall",  // FIX-BEFORE-PR: unsure if even used for anything
    };

    // Allows spawning/terminating processes
    static constexpr auto process_management_syscalls = {
        "fork",
        "clone",
        "kcmp",
        "unshare",
        "pthread_atfork",
        "set_robust_list",
        "get_robust_list",
        "posix_spawn",
        "posix_spawnattr_init",
        "posix_spawnattr_setflags",
        "posix_spawnattr_setpgroup",
        "posix_spawnattr_setsigdefault",
        "posix_spawnattr_setsigmask",
        "posix_spawnattr_destroy",
        "posix_spawnattr_getflags",
        "posix_spawnattr_getpgroup",
        "posix_spawn_file_actions_init",
        "posix_spawn_file_actions_addclose",
        "posix_spawn_file_actions_adddup",
        "posix_spawn_file_actions_adddup2",
        "posix_spawn_file_actions_addopen",
        "posix_spawn_file_actions_destroy",
    };

    static constexpr auto filesystem_syscalls = {
    // FIX-BEFORE-PR: some of these are clearly unused
#if !ARCH(AARCH64)
        "access",
        "chmod",
        "chown",
#    if ARCH(I386)
        "chown32",
#    endif
        "creat",
        "utimensat",
        "lchown",
        "link",
        "lstat",
        "mkdir",
        "mknod",
        "open",
        "readlink",
        "rename",
        "rmdir",
        "stat",
        "symlink",
        "unlink",
#    if defined(AK_ARCH_64_BIT)
        "uselib",
#    endif
        "ustat",
        "utimes",
#endif // !ARCH(AARCH64)
        "execve",
        "faccessat",
        "faccessat2",
        "fchmodat",
        "fchownat",
#if ARCH(X86_64) || ARCH(AARCH64)
        "newfstatat", // fstatat()
#elif ARCH(I386)
        "fstatat64",
#endif
#if ARCH(I386)
        "lchown32",
#endif
        "linkat",
#if defined(AK_ARCH_32_BIT)
        "lstat64",
#endif
        "memfd_create",
        "mkdirat",
        "mknodat",
#if ARCH(I386)
        "oldlstat",
        "oldstat",
#endif
        "openat",
        "readlinkat",
        "renameat",
        "renameat2",
#if defined(AK_ARCH_32_BIT)
        "stat64",
#endif
        "statfs",
#if defined(AK_ARCH_32_BIT)
        "statfs64",
#endif
        "statx",
        "symlinkat",
        "truncate",
#if defined(AK_ARCH_32_BIT)
        "truncate64",
#endif
        "unlinkat",
#if ARCH(I386) || ARCH(X86_64)
        "utime",
#endif
        "utimensat",
#if AK_ARCH_32_BIT
        "utimensat_time64",
#endif
    };
};

}
