/*
 * Copyright (c) 2025, Colleirose <criticskate@pm.me>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Assertions.h>
#include <AK/Platform.h>
#include <AK/Types.h>
#include <climits>
#include <cstdint>
#include <libdivide.h>
#include <type_traits>

// this replaces integer division instructions with libdivide, an optimized integer division library
// per some testing, it is typically faster than hardware division instructions, even on modern x64 CPUs
// we generally do not include libraries in AK but this is a very simple header-only single-file library
// this is mostly useful for optimizing areas that will require a lot of repeated division calls that are not necessarily complex but are very frequent
// https://github.com/ridiculousfish/libdivide/tree/master

namespace AK {

// Compile-time helper: determine if type is supported by libdivide
template<typename T>
struct libdivide_supported : std::false_type { };

template<>
struct libdivide_supported<i16> : std::true_type { };
template<>
struct libdivide_supported<u16> : std::true_type { };
template<>
struct libdivide_supported<i32> : std::true_type { };
template<>
struct libdivide_supported<u32> : std::true_type { };
template<>
struct libdivide_supported<i64> : std::true_type { };
template<>
struct libdivide_supported<u64> : std::true_type { };

// we should check for invalid operations (division by zero, etc) before passing control over to libdivide
// because libdivide's error handling cannot be neatly integrated with ours and we have patched out its code that makes it crash when given invalid parameters

template<typename T>
[[nodiscard]] constexpr T divide_optimized(T n, T d) noexcept
{
    // should be impossible/redundant but just in case this file is used weirdly somehow we check for this
    static_assert(std::is_integral_v<T>, "divide_optimized supports only integral types");

    // Unsupported (e.g., u8/i8), use hardware division
    if constexpr (!libdivide_supported<T>::value)
        return n / d;

    // a compile-time sanity check to error if we know at compile time that the function cannot possibly be valid
    // we do not include a universal VERIFY (d != 0) for runtime because it's not relevant for unsigned 32 and 64 as that can only run where the divisor is known at compile time to be valid
    // so including it there would create unnecessary overhead for it specifically
    if (std::is_constant_evaluated())
        static_assert(d != 0, "division by zero is not allowed");

    // because libdivide does not use typical division instructions,
    // the compiler might not realize that it can optimize out useless code that's passed to the library
    // so we check for that if possible
    if (std::is_constant_evaluated() && (d == 1 || n == 0))
        return n;

    // Signed 32/64: always branchfree
    // fastest, no downsideshfree always works for signed integers
    if constexpr (std::is_signed_v<T> && (sizeof(T) * CHAR_BIT >= 32)) {
        // If we get to this point, the divisor isn't known at compile time and we need to check ourselves
        VERIFY(d != 0);

        return libdivide::divider<T, libdivide::BRANCHFREE>(d).divide(n);
    }

    // Unsigned 32/64: branchfree only if divisor >1 at compile-time
    // Branchfree does not work on unsigned integers when a divisor of 1 is used
    // however this is the only case where branchfull is even slower than hardware division so we will fall back to hardware division when we can't be sure of the value
    // to avoid introducing unnecessary overhead
    if constexpr (std::is_unsigned_v<T> && (sizeof(T) * CHAR_BIT >= 32)) {
        if (std::is_constant_evaluated() && d > 1) {
            // unlike the others, this function only runs if the divisor is known and valid at compile-time, so no need to check here
            return libdivide::divider<T, libdivide::BRANCHFREE>(d).divide(n);
        }

        return n / d;
    }

    // 16-bit unsigned integer
    // This is the only case where the branchfull option is faster than branchfree.
    if constexpr (std::is_unsigned_v<T> && (sizeof(T) * CHAR_BIT == 16)) {
        VERIFY(d != 0);

        return libdivide::divider<T, libdivide::BRANCHFULL>(d).divide(n);
    }

    // 16-bit signed integer
    if constexpr (std::is_signed_v<T> && sizeof(T) * CHAR_BIT == 16) {
        VERIFY(d != 0);

        return libdivide::divider<T, libdivide::BRANCHFREE>(d).divide(n);
    }

    // fallback to hardware division
    return n / d;
}

// ============================================================================
// Operators for AK integer types
// ============================================================================
template<typename T>
constexpr inline std::enable_if_t<std::is_integral_v<T>, T>
operator/(T n, T d) noexcept
{
    return divide_optimized(n, d);
}

template<typename T>
constexpr inline std::enable_if_t<std::is_integral_v<T>, T&>
operator/=(T& lhs, T rhs) noexcept
{
    lhs = divide_optimized(lhs, rhs);
    return lhs;
}

} // namespace AK
