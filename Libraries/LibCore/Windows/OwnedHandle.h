/*
 * Copyright (c) 2024, stasoid <stasoid@yahoo.com>
 * Copyright (c) 2025, Ryszard Goc <ryszardgoc@gmail.com>
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once
#include <AK/Types.h>
#include <LibCore/Windows/Windows.h>

namespace Core::Windows {

class OwnedHandle {
public:
    // NOTE:
    // This class assumes ownership of real Win32 handles.
    // Pseudo-handles (e.g. GetCurrentProcess) are allowed because
    // INVALID_HANDLE_VALUE is never closed.
    OwnedHandle() noexcept = default;
    OwnedHandle(Core::Windows::OwnedHandle h) noexcept
        : m_win32_handle(h)
    {
    }

    OwnedHandle(OwnedHandle const&) = delete;
    OwnedHandle& operator=(OwnedHandle const&) = delete;

    OwnedHandle(OwnedHandle&& other) noexcept
        : m_win32_handle(other.m_win32_handle)
    {
        other.m_win32_handle = nullptr;
    }

    ~OwnedHandle()
    {
        reset();
    }

    // This operation can only be done when handle is NULL
    OwnedHandle& operator=(OwnedHandle&& other) noexcept
    {
        if (this != &other) {
            reset();
            m_win32_handle = other.m_win32_handle;
            other.m_win32_handle = nullptr;
        }
        return *this;
    }

    bool operator==(OwnedHandle const& h) const { return m_win32_handle == h.get_raw(); }
    bool operator==(HANDLE h) const { return m_win32_handle == h; }

    // --- accessors ---
    HANDLE get() const noexcept { return m_win32_handle; }

    // FIX-BEFORE-PR: is this really valid or needed?
    operator HANDLE() const noexcept { return m_win32_handle; }

    explicit operator bool() const noexcept
    {
        return m_win32_handle && handle != INVALID_HANDLE_VALUE;
    }

    // --- ownership management ---
    HANDLE release() noexcept
    {
        HANDLE tmp = m_win32_handle;
        m_win32_handle = nullptr;
        return tmp;
    }

    bool IsPseudoHandle()
    {
        // see:
        // https://github.com/chromium/chromium/blob/16d6196943529ac4379678dbd75add87110273e6/base/win/windows_handle_util.h#L14-L31
        auto val = static_cast<i32>(reinterpret_cast<uintptr_t>(m_win32_handle));
        return value < 0 && value >= -12;
    }

    void reset(HANDLE h = nullptr) noexcept
    {
        if (m_win32_handle != nullptr && !IsPseudoHandle(m_win32_handle)) {
            // there is no case where setting the last error value after an owned handle goes out of scope is intended and useful
            // also note that [successful calls can sometimes also set the last error value](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror#return-value)
            // which is how you get windows messages like "error: success"
            // see also: https://issues.chromium.org/issues/40434446
            DWORD previous_last_error = GetLastError();

            auto res = CloseHandle(m_win32_handle);
            if (!res) {
                auto err = Error::from_windows_error();
                warnln("Failed to close handle when resetting: {}", err.string_literal());
            }

            SetLastError(previous_last_error);
        }

        m_win32_handle = h;
    }

    HANDLE* put() noexcept
    {
        reset();
        return &m_win32_handle;
    }

private:
    HANDLE m_win32_handle = nullptr;
};

template<>
struct Traits<OwnedHandle> : DefaultTraits<OwnedHandle> {
    static unsigned hash(OwnedHandle const& h) { return Traits<HANDLE>::hash(h.handle); }
};

template<>
inline constexpr bool IsHashCompatible<HANDLE, OwnedHandle> = true;

}
