#pragma once

// C++
#include <cstdint>

// Linux
#include <signal.h>

/*
 * this header contains special data structures used in the kernel for system
 * calls and not exposed to user space (usually dealt with in glibc)
 */

namespace clues {

extern "C" {

// deprecated flag that's still set in the sigaction flags obviously
#ifndef SA_RESTORER
#	define SA_RESTORER 0x04000000
#endif

/// This is the sigaction structure used by the kernel for e.g. rt_sigaction.
/**
 * Found in kernel_sigaction.h of glibc
 **/
struct kernel_sigaction {
	/// The signal handling function be it the old or the new signature.
	void *handler;
	/// The sigaction flags.
	unsigned long flags;
	/// The restorer function (deprecated).
	void *restorer;
	/// The signal mask.
	sigset_t mask;
};

/*
 * the man page says there's no header for this
 */
struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[];
	/*
	 * following fields, cannot be sensibly accessed by the compiler,
	 * needs to be calculated during runtime, therefore only as comments
	char pad; // zero padding byte
	char d_type; // file type since Linux 2.6.4
	*/
};

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

} // end extern "C"

} // end ns
