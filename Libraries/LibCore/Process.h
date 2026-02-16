/*
 * Copyright (c) 2021, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2022, MacDue <macdue@dueutil.tech>
 * Copyright (c) 2023, Sam Atkins <atkinssj@serenityos.org>
 * Copyright (c) 2024, Tim Flynn <trflynn89@serenityos.org>
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteString.h>
#include <AK/Forward.h>
#include <AK/Platform.h>
#include <AK/String.h>
#include <AK/Variant.h>
#include <LibCore/File.h>

namespace Core {

namespace FileAction {

struct OpenFile {
    ByteString path;
    File::OpenMode mode = File::OpenMode::NotOpen;
    int fd = -1;
    mode_t permissions = 0600;
};

struct CloseFile {
    int fd { -1 };
};

struct DupFd {
    int write_fd { -1 };
    int fd { -1 };
};

}

#ifdef AK_OS_WINDOWS
enum WindowsStartupOptionsType {
    Unspecified,
    Token,
    AttributeList,
}

struct ProcessWindowsOptions {
    WindowsStartupOptionsType startup_type { WindowsStartupOptionsType::Unspecified };
    Variant<HANDLE, LPPROC_THREAD_ATTRIBUTE_LIST> startup_val { NULL };
    Utf16String alt_desktop_name { "" };
}
#endif

struct ProcessSpawnOptions {
    StringView name {};
    ByteString executable {};
    bool search_for_executable_in_path { false };
    Vector<ByteString> const& arguments {};

    using FileActionType = Variant<FileAction::OpenFile, FileAction::CloseFile, FileAction::DupFd>;
    Vector<FileActionType> file_actions {};
#ifdef AK_OS_WINDOWS
    ProcessWindowsOptions windows_options {};
#endif
};

class Process {
    AK_MAKE_NONCOPYABLE(Process);

public:
    Process(Process&& other);
    Process& operator=(Process&& other);
    ~Process();

    static ErrorOr<Process> spawn(ProcessSpawnOptions const& options);
    static Process current();

    static ErrorOr<Process> spawn(StringView path, ReadonlySpan<ByteString> arguments);
    static ErrorOr<Process> spawn(StringView path, ReadonlySpan<StringView> arguments);

    static ErrorOr<String> get_name();

    static void wait_for_debugger_and_break();
    static ErrorOr<bool> is_being_debugged();

    pid_t pid() const;

    ErrorOr<int> wait_for_termination() const;

private:
#ifndef AK_OS_WINDOWS
    Process(pid_t pid = -1)
        : m_pid(pid)
    {
    }

    pid_t m_pid;
#else
    Process(void* handle = 0)
        : m_handle(handle)
    {
    }

    void* m_handle;
#endif
};

}
