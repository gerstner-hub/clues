#pragma once

// cosmos
#include <cosmos/BitMask.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/string.hxx>

namespace clues {

class Tracee;
class SystemCall;

/// Pure virtual interface for consumers of tracing events.
class EventConsumer {
	friend class Tracee;
	friend class Engine;
public: // types

	/// Different status flags that can appear in callbacks.
	enum class Status {
		/// A system call was interrupted (only appears during syscallExit()).
		INTERRUPTED    = 1 << 0,
		/// A previously interrupted system call is resumed (only appears during syscallEntry()).
		RESUMED        = 1 << 1,
		/// An exit occurs because another thread called execve() (only appears in exited()).
		LOST_TO_EXECVE = 1 << 2,
	};

	using State = cosmos::BitMask<Status>;

protected: // functions

	virtual void syscallEntry(Tracee &tracee, const SystemCall &sc, const State state) = 0;

	virtual void syscallExit(Tracee &tracee, const SystemCall &sc, const State state) = 0;

	/// The tracee is now properly attached to.
	/**
	 * This should be the first call that that is visible for a tracee. It
	 * occurs when the ptrace() relationship is established and a defined
	 * tracing state has been reached. The Tracee will be in
	 * PTRACE_EVENT_STOP.
	 **/
	virtual void attached(Tracee &tracee) {
		(void)tracee;
	}

	/// The tracee has received a signal.
	/**
	 * This callback notifies about signals being delivered to the
	 * tracee.
	 **/
	virtual void signaled(Tracee &tracee, const cosmos::SigInfo &info) {
		(void)tracee;
		(void)info;
	};

	/// The tracee entered group-stop due to a stopping signal.
	virtual void stopped(Tracee &tracee) {
		(void)tracee;
	}

	/// The tracee resumed due to SIGCONT.
	virtual void resumed(Tracee &tracee) {
		(void)tracee;
	}

	/// The tracee is about to end execution.
	/**
	 * The tracee is about to either exit regularly, to be killed
	 * by a signal or to disappear due to an execve() in a
	 * multi-threaded process.
	 *
	 * When this callback occurs the tracee can still be inspected
	 * using ptrace(). One execution is continued the tracer <->
	 * tracee relationship is lost.
	 *
	 * If the exit happens due to an execve in a multi-threaded
	 * process then Status::LOST_TO_EXECVE is set in `state`.
	 **/
	virtual void exited(Tracee &tracee, const cosmos::WaitStatus status, const State state) {
		(void)tracee;
		(void)status;
		(void)state;
	}

	/// A new program is executed in the tracee.
	/**
	 * This call occurs after a successful `execve()` within the
	 * tracee. If the tracee was multi-threaded, then all but one
	 * thread will have exited in the process.
	 *
	 * Only the main process ID (main thread PID) will remain. The
	 * thread that caused the execve() can be a different thread.
	 * In this case `former_pid` contains the former PID that is
	 * now continuing as the main thread of the new execution
	 * context.
	 *
	 * The new executable path and command line can be retrieved
	 * via Tracee::executable() and Tracee::cmdLine(). The
	 * previous values are provided as input parameters.
	 *
	 * The callee can decide to stop tracing (by detaching) at
	 * this point to prevent following new tracing contexts.
	 **/
	virtual void newExecutionContext(
			Tracee &tracee,
			const std::string &old_executable,
			const cosmos::StringVector &old_cmdline,
			const std::optional<cosmos::ProcessID> former_pid) {
		(void)tracee;
		(void)former_pid;
		(void)old_cmdline;
		(void)old_executable;
	}

	/// A new child process has been created.
	/**
	 * The existing tracee `parent` has created a new child process, which
	 * has automatically been attached to and is now represented in
	 * `child`.
	 *
	 * Different ways to create a child process exist, these are
	 * differentiated via `event`. Note that some forms of `clone()` calls
	 * will appear as cosmos::ptrace::Event::FORK or
	 * cosmos::ptrace::Event::VFORK instead of
	 * cosmos::ptrace::Event::CLONE.
	 *
	 * cosmos::ptrace::Event::VFORK_DONE occurs when the child process
	 * exited or `exec()`'d and can be ignored if there is no need for it.
	 **/
	virtual void newChildProcess(
			Tracee &parent,
			Tracee &child,
			const cosmos::ptrace::Event event) {
		(void)parent;
		(void)child;
		(void)event;
	}

	/// A `vfork()` in `parent` for `child` completed.
	/**
	 * This is a special case of `newChildProcess()` event for `vfork()`.
	 * This is reported after the `vfork()` is complete i.e. the `child`
	 * either exited or performed an `execve()`.
	 *
	 * If `child` no longer exists then it is `nullptr`.
	 **/
	virtual void vforkComplete(Tracee &parent, Tracee *child) {
		(void)parent;
		(void)child;
	}
};

} // end ns
