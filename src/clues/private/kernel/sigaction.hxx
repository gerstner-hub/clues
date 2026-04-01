#pragma once

// C++
#include <cstdint>

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

/// Variant of sigaction for 64-bit <-> 32-bit cross ABI tracing.
struct kernel_sigaction32 {
	uint32_t handler;
	uint32_t flags;
	uint32_t restorer;
	sigset_t mask;
} __attribute__((packed));

/// Variant of sigaction used for the old sigaction() system call.
struct kernel_old_sigaction {
	uint32_t handler;
	// old sigset_t consisting of only 4 bytes.
	uint32_t mask;
	uint32_t flags;
	uint32_t restorer;
};

} // end extern "C"

} // end ns
