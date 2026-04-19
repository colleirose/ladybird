/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ByteString.h>
#include <AK/Error.h>
#include <AK/Types.h>
#include <LibCore/Windows/Windows.h>

#include <AK/Windows.h>

// Functions for interacting with [security identifiers](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-identifiers), aka SIDs

namespace Core::Windows {

ErrorOr<SID_AND_ATTRIBUTES> GetAppContainerCapabilitySidFromName(ByteString capability_name);

// This is roughly based on https://github.com/M2Team/Privexec/blob/a5fc4ea0091c4b8a40abb44fae6fbc0eb037c2bc/lib/exec/appcontainer.cc#L56-L77
class SidArray {
public:
    SidArray()
        : m_count(0)
        , m_sids(nullptr)
    {
    }

    ~SidArray()
    {
        if (!m_sids)
            return;

        for (auto index = 0; index < m_count; index++)
            Core::Windows::LocalFree(m_sids[index]);
        Core::Windows::LocalFree(m_sids);
    }

    DWORD count() { return m_count; }
    PSID* sids() { return m_sids; }
    PDWORD count_ptr() { return &m_count; }
    PSID** sids_ptr() { return &m_sids; }

private:
    DWORD m_count;
    PSID* m_sids;
};

}
