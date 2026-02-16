/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "bubblewrap.h"
#include "SandboxPolicies.h"
#include <AK/Assertions.h>
#include <AK/ScopeGuard.h>
#include <AK/Span.h>
#include <AK/String.h>
#include <AK/StringView.h>
#include <AK/Vector.h>
#include <LibCore/Environment.h>
#include <LibCore/Process.h>
#include <LibCore/StandardPaths.h>
#include <LibCore/System.h>
#include <seccomp.h>
#include <spawn.h>

static enum BwrapCacheValue {
    Supported,
    Unsupported,
    NotChecked,
};

static BwrapCacheValue bwrap_support_cache = BwrapCacheValue::NotChecked;

static inline bool IsFlatpak()
{
    // https://stackoverflow.com/a/75284996
    return Core::Environment::get("container").has_value();
}

static HashMap<ProcessType, int> seccomp_file_descriptors {};

namespace WebView::Sandbox {

bool IsBubblewrapSupported()
{
    if (bwrap_support_cache != BwrapCacheValue::NotChecked)
        return bwrap_support_cache == BwrapCacheValue::Supported;

    // FIXME: When the application is running under Flatpak, use `flatpak-spawn --sandbox` to create sandboxed child processes
    if (IsFlatpak()) {
        dbgln("bubblewrap is unavailable because the program is running under Flatpak. This is not an error and the program will safely continue.");
        bwrap_support_cache = BwrapCacheValue::Unsupported;
        return false;
    }

    Core::ProcessSpawnOptions process_options = {
        .name = "bubblewrap"sv,
        .executable = "/usr/bin/true"sv,
        .search_for_executable_in_path = false,
        .arguments = {},
        .file_actions = {},
    };

    // note that we don't need to set the cache to false for out-of-memory errors or other errors that have nothing to do with bubblewrap itself
    // unless the errors in question would clearly preclude this function ever succeeding
    Vector<ByteString> generated_bwrap_args;
    if (auto args_res = CreateBwrapArguments(process_options); args_res.is_error()) {
        LogGenericSandboxError("generate bubblewrap arguments", args_res.error());
        if (res.release_error() != Error::from_errno(ENOMEM))
            bwrap_support_cache = BwrapCacheValue::Unsupported;

        return false;
    }

    generated_bwrap_args = args_res.value();

    posix_spawn_file_actions_t spawn_actions;
    if (int ret = posix_spawn_file_actions_init(&spawn_actions); ret != 0) {
        // usually out of memory
        auto actions_err = Error::from_syscall("posix_spawn_file_actions_init"sv, ret);
        LogGenericSandboxError("initialize spawn actions for the bubblewrap test", actions_err);
        return false;
    }

    auto args = generated_bwrap_args.span();
    auto spawn_res = Core::System::posix_spawn("/usr/bin/bwrap"sv, &spawn_actions, nullptr, const_cast<char**>(args.data()), Core::Environment::raw_environ);
    posix_spawn_file_actions_destroy(&spawn_actions);
    if (spawn_res.is_error()) {
        auto spawn_error = spawn_res.error();
        if (spawn_error.code == ENOMEM) {
            LogGenericSandboxError("spawn process to test bubblewrap because the system is out of memory", spawn_error);
            return false;
        }

        if (spawn_error.code == EAGAIN) {
            LogGenericSandboxError("spawn process to test bubblewrap because too many processes are running", spawn_error);
            return false;
        }

        LogGenericSandboxError("spawn process to test bubblewrap, bubblewrap is likely unavailable or broken", spawn_error);
        bwrap_support_cache = BwrapCacheValue::Unsupported;
        return false;
    }

    auto process = Core::System::Process(spawn_res.value());
    if (auto wait_for_term_res = process.wait_for_termination(); wait_for_term_res.is_error()) {
        LogGenericSandboxError("terminate bubblewrap test process", wait_for_term_res.error());
        bwrap_support_cache = BwrapCacheValue::Unsupported;
        return false;
    } else {
        int val = wait_for_term_res.release_value();
        if (val != 0) {
            if (val == ENOMEM) {
                LogGenericSandboxError("run bubblewrap test because the system is out of memory", Error::from_errno(val));
                return false;
            }

            LogGenericSandboxError("run bubblewrap test, bubblewrap is likely unavailable or broken", Error::from_errno(val));
            bwrap_support_cache = BwrapCacheValue::Unsupported;
            return false;
        }
    }

    bwrap_support_cache = BwrapCacheValue::Supported;
    return true;
}

ErrorOr<Vector<ByteString>> CreateBwrapArguments(WebView::ProcessType type, [[maybe_unused]] int seccomp_memfd)
{
    VERIFY(GetPolicyForProcessType(type).use_bubblewrap);
    // this code is partially based on:
    // https://gitlab.gnome.org/GNOME/glycin/-/blob/764672a14c5ac63a94619882ef6e75e0cd916891/glycin/src/sandbox.rs#L285-488
    // https://github.com/containers/bubblewrap/blob/b8e6e1159e63045679ae57b8b379b39eae7798a6/demos/bubblewrap-shell.sh
    Vector<ByteString> command = {
        "bwrap"
        "--unshare-all"
        "--die-with-parent"
        // change to a valid working directory
        "--chdir",
        "/",
        // readonly /usr binding
        // FIX-BEFORE-PR: could this be removed?
        "--ro-bind",
        "/usr",
        "/usr",
        // /tmp and /var/tmp
        "--dir",
        "/tmp",
        "--dir",
        "/var",
        "--symlink",
        "../tmp",
        "var/tmp",
        // /dev and /proc
        "--dev",
        "/dev",
        "--proc"
        "/proc",
        // basic symlinks
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64"
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        // Add /nix/store on systems with Nix
        "--ro-bind-try",
        "/nix/store",
        "/nix/store",
    };

    // Setup seccomp filters
    int seccomp_memfd = 0;
    if (seccomp_file_descriptors.contains(type)) {
        seccomp_memfd = seccomp_file_descriptors.find(type);
    } else {
        seccomp_memfd = TRY(Core::System::anon_create());

        ArmedScopeGuard guard = [&] {
            if (seccomp_memfd > 0)
                close(seccomp_memfd);
        };

        scmp_filter_ctx seccomp_ctx = TRY(GetSeccompCtxForProcessType(type));
        TRY(WriteSeccompCtxToFd(seccomp_ctx, seccomp_memfd));
        TRY(seccomp_file_descriptors.try_set(type, seccomp_memfd));

        guard.disarm();
    }
    VERIFY(seccomp_memfd > 0);

    command.extend({ "--seccomp", ByteString::number(seccomp_memfd) });

    // Append initial options based on process type
    auto policy = GetPolicyForProcessType(type);

    if (policy.allowed_capabilities.contains(LinuxCapability::Networking)) {
        command.extend({
            // this only looks like 2 of the same argument because we are binding the host resolv.conf to the sandbox resolv.conf
            // but it is not an issue
            "--ro-bind",
            "/etc/resolv.conf",
            "/etc/resolv.conf",
            "--share-net",
        });
    }

    // if we have user file permissions then we bind the host home directory to the application
    // the value of the `home` variable will also be set as the HOME env var down bleow
    ByteString home = "/tmp-home";
    if (policy.allowed_capabilities.contains(LinuxCapability::FilesystemUserFiles)) {
        home = Core::StandardPaths::home_directory();
        command.extend({
            "--bind",
            home, // same as with /etc/resolv.conf, we are binding ~/ to ~/
            home,
        });
    } else {
        command.extend({
            // Create a fake HOME for glib to not throw warnings
            "--tmpfs",
            home,
        })
    }

    if (policy.allowed_capabilities.contains(LinuxCapability::FilesystemCacheFiles)) {
        ByteString cache_dir = Core::StandardPaths::cache_directory();
        auto cache_sv = cache_dir.view();
        auto home_sv = home.view();
        if (!policy.allowed_capabilities.contains(LinuxCapability::FilesystemUserFiles) || !cache_sv.starts_with(home_sv)) {
            // only bind if it isn't already added as a subdirectory of user files
            command.extend({
                "--bind",
                cache_dir,
                cache_dir,
            });
        }
    }

    // Add remaining options
    command.extend({
        // Create a fake runtime directory for glib to not throw warnings
        "--tmpfs",
        "/tmp-run",
        // setup clean environment
        "--clearenv",
        "--setenv",
        "XDG_RUNTIME_DIR",
        "/tmp-run",
        // home directory
        "--setenv",
        "HOME",
        home,
    });

    // Add the original executable and its arguments as the bwrap target
    command.append(target_options.executable);
    for (ByteString arg : target_options.arguments)
        command.append(arg);

    return command;
}

}
