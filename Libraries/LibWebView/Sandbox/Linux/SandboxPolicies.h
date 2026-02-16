/*
 * Copyright (c) 2025-2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/HashMap.h>
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

// Override errno for syscalls where the default errno is invalid or undesired (default is ENOENT for filesystem and EPERM for everything else)
static HashMap<ByteString, int> errno_override_if_denied = {
    // see https://github.com/flatpak/flatpak/blob/b37f739721e219159cad4791a894ae4e7f1daa2a/common/flatpak-run.c#L1961-L1965
    // clone3() shouldn't be allowed, returning ENOSYS should usually encourage the caller to use clone() instead if it's allowed
    { "clone3", ENOSYS },

    // Filesystem
    { "ustat", EINVAL },

    // Proces management
    // EPERM is invalid for a lot of process management and we'd prefer ENOMEM where EPERM is invalid
    // but there's too much variation in where ENOMEM is allowed so we'll just manually list each EPERM override instead of changing the process management default
    { "pthread_atfork", ENOMEM },

    { "posix_spawn_file_actions_init", ENOMEM },
    { "posix_spawn_file_actions_destroy", EINVAL },
    { "posix_spawn_file_actions_addopen", ENOMEM },
    { "posix_spawn_file_actions_addclose", ENOMEM },
    { "posix_spawn_file_actions_adddup2", ENOMEM },

    { "posix_spawnattr_init", ENOMEM },
    { "posix_spawnattr_destroy", ENOMEM },

    { "posix_spawnattr_setflags", EINVAL },
    { "posix_spawnattr_getflags", EINVAL },

    { "posix_spawnattr_setpgroup", EINVAL },
    { "posix_spawnattr_getpgroup", EINVAL },

    { "posix_spawnattr_setsigdefault", EINVAL },
    { "posix_spawnattr_getsigdefault", EINVAL },

    { "posix_spawnattr_setsigmask", EINVAL },
    { "posix_spawnattr_getsigmask", EINVAL },

    { "posix_spawnattr_setflags", EINVAL },
    { "posix_spawnattr_getflags", EINVAL },
};

static constexpr auto always_allowed_syscalls = {
    // Basic info about the system and process
    "uname", "sysconf", "getrlimit", "setrlimit", "getcpu", "getenv",
#if ARCH(AARCH64)
    "getauxval", // On ARM, this is used by OpenSSL to check for several system features and in LibCore/System.cpp to check for MTE support
#endif
    "getuid", "getgid", "geteuid", "geteguid", "getpid", "gettid",
    "getcwd", // Maybe this could be restricted?

    // Simple process management that isn't restricted, like closing or restarting the process
    "restart", "atexit", "exit", "exit_group",
    "futex", // FIXME: Futex should be more restrictive, see https://bugzilla.mozilla.org/show_bug.cgi?id=1441993 and https://github.com/chromium/chromium/blob/f2d2cad7697c941615847ae503eb9b3b64773cce/sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions.cc#L361-L383

    // Epoll
    "epoll_create", "epoll_wait", "epoll_pwait", "epoll_create1", "epoll_ctl",

    // Time
    "clock_nanosleep", "clock_gettime", "time", "gettimeofday", "usleep",

    // CSPRNG
    "getrandom",
    "getentropy", // Although AK/Random doesn't use getentropy(), some dependencies might, like OpenSSL. It exposes basically the same attack surface as getrandom(), so it's fine.

    // Memory management
    "madvise", "mmap", "munmap", "mremap", "mlock", "munlock", "mlockall", "munlockall", "mprotect", "pkey_alloc", "pkey_mprotect", "mseal", "munseal", "msync", "fsync", "membarrier",
    "brk", // not called by us directly but may be invoked by a system allocator like glibc

    // Used by IPC and also for networking.
    // FIXME: Almost all of these can be made more restrictive.
    // FIX-BEFORE-PR: not full list and some of these names are just wrong; its not very well organized; maybe i can add some restrictions before pr for working network restrictions
    "recvmsg", "sendmsg", "recvfrom", "sendto", "recv", "send", "recvfrom", "socketpair", "getsockopt", "getsockname", "getpername", "setsockopt", "socket", "connect", "accept", "accept4", "bind",

    // Misc things
    "mincore", // see https://bugzilla.mozilla.org/show_bug.cgi?id=1462640. FIX-BEFORE-PR: Might not be needed here but needs more testing.
    "ioctl",   // Has some restrictions set in AddAllowRule(), might be able to be restricted further.
    "fcntl",   // Used for IPC, maybe this could be more restricted?
               // FIX-BEFORE-PR: Some of the IPC stuff I should figure out during testing because I don't think all processes use the same IPC calls
};

class SyscallNameLists {
    static constexpr auto networking = {
        // FIX-BEFORE-PR: reworking networking as much as possible (2nd comment below isnt even accurate yet)

        // FIXME: These are very permissive and should be restricted much more than they are now.
        // We apply some restrictions in seccomp.cpp, but we should probably do more soon.
        // Note that according to Chromium and Firefox code comments it is "impossible" to effectively sandbox getaddrinfo
        // and some of the other syscalls listed here. However, a lot of work has to be done to further restrict this.
        "getaddrinfo", // FIX-BEFORE-PR: apparently x11 uses getaddrinfo locally
        "socketcall",  // FIX-BEFORE-PR: unsure if even used for anything
    };

    static constexpr auto process_management = {
        "kcmp",
        "unshare",

        "set_robust_list",
        "get_robust_list",

        // spawn a process
        "posix_spawn",
        "pthread_atfork",
        "fork",
        "clone",

        // file_actions
        "posix_spawn_file_actions_init",
        "posix_spawn_file_actions_destroy",
        "posix_spawn_file_actions_addopen",
        "posix_spawn_file_actions_addclose",
        "posix_spawn_file_actions_adddup2",

        // spawnattr
        "posix_spawnattr_init",
        "posix_spawnattr_destroy",

        "posix_spawnattr_setflags",
        "posix_spawnattr_getflags",

        "posix_spawnattr_setpgroup",
        "posix_spawnattr_getpgroup",

        "posix_spawnattr_setsigdefault",
        "posix_spawnattr_getsigdefault",

        "posix_spawnattr_setsigmask",
        "posix_spawnattr_getsigmask",

        "posix_spawnattr_getflags",
    };

    // Based on https://github.com/chromium/chromium/blob/16d6196943529ac4379678dbd75add87110273e6/sandbox/linux/seccomp-bpf-helpers/syscall_sets.cc#L104-L195
    // Removed everything we don't use
    static constexpr auto filesystem = {
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
    },
};

};
