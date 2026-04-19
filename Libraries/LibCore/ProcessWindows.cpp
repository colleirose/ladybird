/*
 * Copyright (c) 2021, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2022-2023, MacDue <macdue@dueutil.tech>
 * Copyright (c) 2023-2024, Sam Atkins <atkinssj@serenityos.org>
 * Copyright (c) 2024, Tim Flynn <trflynn89@serenityos.org>
 * Copyright (c) 2024, stasoid <stasoid@yahoo.com>
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Format.h>
#include <AK/ScopeGuard.h>
#include <AK/String.h>
#include <AK/StringView.h>
#include <AK/Try.h>
#include <AK/Utf16View.h>
#include <AK/Vector.h>
#include <AK/Windows.h>
#include <LibCore/Process.h>

namespace Core {

Process::Process(Process&& other)
    : m_handle(exchange(other.m_handle, nullptr))
{
}

Process& Process::operator=(Process&& other)
{
    m_handle = exchange(other.m_handle, nullptr);
    return *this;
}

Process::~Process()
{
    if (m_handle)
        CloseHandle(m_handle);
}

Process Process::current()
{
    return GetCurrentProcess();
}

ErrorOr<Process> Process::spawn(ProcessSpawnOptions const& options)
{
    if (!options.file_actions.is_empty())
        return Error::from_string_literal("file actions are not supported");

    auto windows_options = options.windows_options;

    if (windows_options.startup_type == WindowsStartupOptionsType::Unspecified)
        return Error::from_string_literal("invalid startup type provided");

    if (windows_options.alt_desktop_name == "")
        return Error::from_string_literal("invalid desktop name provided");

    StringBuilder builder;
    if (!options.search_for_executable_in_path && !options.executable.find_any_of("\\/:"sv).has_value())
        builder.appendff("\"./{}\" ", options.executable);
    else
        builder.appendff("\"{}\" ", options.executable);

    for (auto arg : options.arguments)
        builder.appendff("\"{}\" ", arg);

    builder.append('\0');
    ByteBuffer command_line = TRY(builder.to_byte_buffer());

    // Actual process spawn
    PROCESS_INFORMATION process_info = {};
    ScopeGuard guard = [&] {
        if (process_info.hThread)
            CloseHandle(process_info.hThread);
    };

    DWORD creation_flags = CREATE_UNICODE_ENVIRONMENT;
    BOOL result;
    auto last_error;
    if (windows_options.startup_type == WindowsStartupOptionsType::AttributeList) {
        creation_flags &= EXTENDED_STARTUPINFO_PRESENT;
        STARTUPINFOEXW startup_info_ex {};
        startup_info_ex.cb = sizeof(STARTUPINFOEXW);
        startup_info_ex.StartupInfo.lpDesktop = const_cast<LPWSTR>(windows_options.alt_desktop_name);
        startup_info_ex.lpAttributeList = windows_options.startup_val;
        result = CreateProcessW(
            NULL,                                               // application name
            (char*)command_line.data(),                         // process to run
            NULL,                                               // process security attributes
            NULL,                                               // primary thread security attributes
            TRUE,                                               // handles are inherited
            creation_flags,                                     // creation flags
            NULL,                                               // use parent's environment
            NULL,                                               // working directory
            reinterpret_cast<LPSTARTUPINFOW>(&startup_info_ex), // startup info
            &process_info                                       // process info
        );
        last_error = GetLastError();
        DeleteProcThreadAttributeList(startup_info_ex.lpAttributeList);
        free(startup_info_ex.lpAttributeList);
    } else {
        STARTUPINFOW startup_info = {};
        startup_info.lpDesktop = const_cast<LPWSTR>(windows_options.alt_desktop_name);
        result = CreateProcessAsUserW(
            windows_options.startup_val, // low-privileged token to run as
            NULL,                        // application name
            (char*)command_line.data(),  // process to run
            NULL,                        // process security attributes
            NULL,                        // primary thread security attributes
            TRUE,                        // handles are inherited
            creation_flags,              // creation flags
            NULL,                        // use parent's environment
            NULL,                        // working directory
            &startup_info,               // startup info
            &process_info                // process info
        );
        last_error = GetLastError();
    }

    if (!result)
        return Error::from_windows_error(last_error);

    return Process(process_info.hProcess);
}

ErrorOr<Process> Process::spawn(StringView path, ReadonlySpan<ByteString> arguments)
{
    return spawn({
        .process_type = type,
        .executable = path,
        .arguments = Vector<ByteString> { arguments },
    });
}

ErrorOr<Process> Process::spawn(StringView path, ReadonlySpan<StringView> arguments)
{
    Vector<ByteString> backing_strings;
    backing_strings.ensure_capacity(arguments.size());
    for (auto argument : arguments)
        backing_strings.append(argument);

    return spawn({
        .process_type = type,
        .executable = path,
        .arguments = backing_strings,
    });
}

// Get the full path of the executable file of the current process
ErrorOr<String> Process::get_name()
{
    Vector<wchar_t, MAX_PATH> path;
    path.resize(MAX_PATH);

    DWORD length = GetModuleFileNameW(NULL, path.data(), MAX_PATH);

    if (length == path.size() && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        path.resize(UNICODE_STRING_MAX_CHARS);
        length = GetModuleFileNameW(NULL, path.data(), UNICODE_STRING_MAX_CHARS);
    }

    if (!length)
        return Error::from_windows_error();

    return MUST(Utf16View { reinterpret_cast<char16_t const*>(path.data()), length }.to_utf8());
}

ErrorOr<bool> Process::is_being_debugged()
{
    return IsDebuggerPresent();
}

// Forces the process to sleep until a debugger is attached, then breaks.
void Process::wait_for_debugger_and_break()
{
    bool print_message = true;
    for (;;) {
        if (IsDebuggerPresent()) {
            DebugBreak();
            return;
        }
        if (print_message) {
            dbgln("Process {} with pid {} is sleeping, waiting for debugger.", Process::get_name(), GetCurrentProcessId());
            print_message = false;
        }
        Sleep(100);
    }
}

pid_t Process::pid() const
{
    return GetProcessId(m_handle);
}

ErrorOr<int> Process::wait_for_termination() const
{
    auto result = WaitForSingleObject(m_handle, INFINITE);
    if (result == WAIT_FAILED)
        return Error::from_windows_error();

    DWORD exit_code = 0;
    if (!GetExitCodeProcess(m_handle, &exit_code))
        return Error::from_windows_error();

    return exit_code;
}

}
