#pragma once

namespace clues {

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

}; // end ns
