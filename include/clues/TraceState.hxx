#ifndef TUXTRACE_TRACESTATE_HXX
#define TUXTRACE_TRACESTATE_HXX

namespace clues
{

enum class TraceState
{
	UNKNOWN,
	//! we're knowingly initially attached to the tracee
	ATTACHED,
	//! the tracee is currently about to entering a system call
	SYSCALL_ENTER,
	//! the tracee just left a system call
	SYSCALL_EXIT,
	//! tracee is gone
	EXITED
};

};

#endif // inc. guard

