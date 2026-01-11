#pragma once

// C++
#include <cstdint>

namespace clues {

extern "C" {

/// 32-bit based `struct rlimit` used with `getrlimit()` and `setrlimit()`.
/**
 * The kernel calls this `struct compat_rlimit`. The userspace `struct rlimit`
 * always uses 64-bit wide integers (at least on glibc), but `getrlimit()` and
 * `setrlimit()` on e.g. i386 only support 32-bit wide ints, meaning that
 * larger values are silently ignored by glibc.
 *
 * The `prlimit64` system call always uses 64-bit integers instead, which is
 * not clearly visible from the man page.
 *
 * For `getrlimit()` and `setrlimit()` depending on system call ABI either
 * rlimit32 or rlimit64 needs to be considered.
 **/
struct rlimit32 {
	uint32_t rlim_cur;
	uint32_t rlim_max;
};

/// 64-bit based `struct rlimit` used with `prlimit()`.
/**
 * The kernel uses a struct of the same name for the prlimit64 system call.
 **/
struct rlimit64 {
	uint64_t rlim_cur;
	uint64_t rlim_max;
};

} // end extern

} // end ns
