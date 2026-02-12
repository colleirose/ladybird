/*
 * Copyright (c) 2024, stasoid <stasoid@yahoo.com>
 * Copyright (c) 2025, Ryszard Goc <ryszardgoc@gmail.com>
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once
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
        : handle_(h)
    {
    }

    OwnedHandle(OwnedHandle const&) = delete;
    OwnedHandle& operator=(OwnedHandle const&) = delete;

    OwnedHandle(OwnedHandle&& other) noexcept
        : handle_(other.handle_)
    {
        other.handle_ = nullptr;
    }

    // This operation can only be done when handle is NULL
    OwnedHandle& operator=(OwnedHandle&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    bool operator==(OwnedHandle const& h) const { return handle_ == h.get_raw(); }
    bool operator==(HANDLE h) const { return handle_ == h; }

    ~OwnedHandle()
    {
        reset();
    }

    // --- accessors ---
    HANDLE get() const noexcept { return handle_; }

    // is this really valid or needed?
    operator HANDLE() const noexcept { return handle_; }

    explicit operator bool() const noexcept
    {
        return handle_ && handle != INVALID_HANDLE_VALUE;
    }

    // --- ownership management ---
    HANDLE release() noexcept
    {
        HANDLE tmp = handle_;
        handle_ = nullptr;
        return tmp;
    }

    void reset(HANDLE h = nullptr) noexcept
    {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
            auto res = CloseHandle(handle_);
            if (!res) {
                auto err = Error::from_windows_error();
                warnln("Failed to close handle when resetting: {}", err.string_literal());
            }
        }

        handle_ = h;
    }

    HANDLE* put() noexcept
    {
        reset();
        return &handle_;
    }

private:
    HANDLE handle_ = nullptr;
};

template<>
struct Traits<OwnedHandle> : DefaultTraits<OwnedHandle> {
    static unsigned hash(OwnedHandle const& h) { return Traits<HANDLE>::hash(h.handle); }
};

template<>
inline constexpr bool IsHashCompatible<HANDLE, OwnedHandle> = true;

}
