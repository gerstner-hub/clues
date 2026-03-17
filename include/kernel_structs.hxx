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

} // end extern "C"

} // end ns
