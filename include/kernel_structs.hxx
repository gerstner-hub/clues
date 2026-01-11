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

} // end extern "C"

} // end ns
