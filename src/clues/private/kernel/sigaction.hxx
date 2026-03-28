#pragma once

// Linux
#include <signal.h>

namespace clues {

extern "C" {

// deprecated flag that's still set in the sigaction flags obviously
#ifndef SA_RESTORER
#	define SA_RESTORER 0x04000000
#endif

using RestorerCB = void (*)();
using SignalCB = void (*)(int);

/// This is the sigaction structure used by the kernel for e.g. rt_sigaction.
/**
 * Found in kernel_sigaction.h of glibc
 **/
struct kernel_sigaction {
	/// The signal handling function be it the old or the new signature.
	SignalCB handler;
	/// The sigaction flags.
	unsigned long flags;
	/// The restorer function (deprecated).
	RestorerCB restorer;
	/// The signal mask.
	sigset_t mask;
};

} // end extern "C"

} // end ns
