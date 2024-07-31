#pragma once

// Linux
#include <signal.h>

/*
 * this header contains special data structures used in the kernel for system
 * calls and not exposed to user space (usually dealt with in glibc)
 */

namespace clues
{

// deprecated flag that's still set in the sigaction flags obviously
#define SA_RESTORER 0x04000000

/**
 * \brief
 * 	This is the sigaction structure used by the kernel for e.g.
 * 	rt_sigaction
 * \details
 * 	Found in kernel_sigaction.h of glibc
 **/
struct kernel_sigaction
{
	//! the signal handling function be it the old or the new signature
	void *handler;
	//! the sigaction flags
	unsigned long flags;
	//! the restorer function (deprecated)
	void *restorer;
	//! the signal mask
	sigset_t mask;
};

} // end ns

