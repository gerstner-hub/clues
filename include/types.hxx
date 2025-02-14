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
/**
 * These states are modelled after the states described in man(2) ptrace.
 **/
enum class TraceState {
	UNKNOWN, ///< initial PTRACE_SIZE / PTRACE_INTERRUPT.
	RUNNING, ///< tracee is running normally / not in a special trace state.
	SYSCALL_ENTER_STOP, ///< system call started.
	SYSCALL_EXIT_STOP, ///< system call finished.
	SIGNAL_DELIVERY_STOP, ///< signal was delivered.
	GROUP_STOP, ///< SIGSTOP executed, the tracee is stopped.
	EVENT_STOP, ///< special ptrace event occurred.
	DEAD ///< the tracee no longer exists.
};

/// An integer that is able to hold a word for the current architecture.
enum class Word : elf_greg_t {
	ZERO = 0
};

} // end ns
