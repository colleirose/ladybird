/*
 * Copyright (c) 2026, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/Windows/Windows.h>

namespace Core::Windows {

// The Windows free functions can fail and set the last error value, but we don't need that error to override the current last error value,
// as we often will free things at function exit or error handlers, where a previous failure is almost always more important than a failure to free what is typically a very small amount of memory.
void LocalFree(HLOCAL hMem);

}
