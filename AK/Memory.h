/*
 * Copyright (c) 2020, Andreas Kling <andreas@ladybird.org>
 * Copyright (c) 2021-2022, Brian Gianforcaro <bgianf@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Types.h>
#include <string.h>

namespace AK {

void secure_memzero(void* ptr, size_t size);

bool timing_safe_compare(void const* b1, void const* b2, size_t len);

}

#if USING_AK_GLOBALLY
using AK::secure_memzero;
using AK::timing_safe_compare;
#endif
