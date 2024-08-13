#pragma once

// C++
#include <map>
#include <string>

// Linux
#include <elf.h>

// cosmos
#include <cosmos/types.hxx>

namespace clues {

/*
 * some general types used across Clues
 */

/// A mapping of file descriptor numbers to their file system paths or other human readable description of the descriptor.
using DescriptorPathMapping = std::map<int, std::string>;

/// Current tracing state for a single tracee.
enum class TraceState {
	UNKNOWN,
	/// We're knowingly initially attached to the tracee.
	ATTACHED,
	/// The tracee is currently about to enter a system call.
	SYSCALL_ENTER,
	/// The tracee just left a system call.
	SYSCALL_EXIT,
	/// Tracee is gone.
	EXITED
};

/// An integer that is able to hold a word for the current architecture.
enum class Word : elf_greg_t {
	ZERO = 0
};

} // end ns
