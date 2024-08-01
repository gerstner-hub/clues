#pragma once

// Linux
#include <unistd.h>
#include <sys/ptrace.h>

// cosmos
#include <cosmos/proc/ChildCloner.hxx>
#include <cosmos/proc/SubProc.hxx>
#include <cosmos/proc/Signal.hxx>
#include <cosmos/proc/ptrace.hxx>
#include <cosmos/string.hxx>

// clues
#include <clues/types.hxx>
#include <clues/RegisterSet.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/TraceState.hxx>

namespace clues {

class RegisterSet;
class SystemCall;

/// pure virtual interface for consumers of tracing events.
class TraceEventConsumer {
	friend class TracedProc;
protected: // functions

	virtual void syscallEntry(const SystemCall &sc) = 0;

	virtual void syscallExit(const SystemCall &sc) = 0;
};

/// Base class for traced processes.
/**
 * The concrete implementation of TracedProc defines the means of how the
 * traced process is attached to and detached from etc.
 **/
class CLUES_API TracedProc {
public:
	virtual ~TracedProc() {}

	/// Logic to handle attaching to the tracee.
	virtual void attach() = 0;

	/// Logic to handle detaching from the tracee.
	virtual void detach() = 0;

	/// Actually start tracing the tracee.
	void trace();

	/// Reads a word of data from the tracee's memory.
	/**
	 * The word found at \c addr is returned from this function on
	 * success. On error an exception is thrown.
	 **/
	long getData(const long *addr) const;

public: // types

protected:

	explicit TracedProc(TraceEventConsumer &consumer);

	/// Waits for the next trace event of this tracee.
	virtual void wait(cosmos::WaitRes &res) = 0;

	/// Causes the traced process to stop.
	void interrupt();

	/// Continues the traced process, optionally delivering \c signal.
	void cont(
		const cosmos::ContinueMode &mode = cosmos::ContinueMode::NORMAL,
		const cosmos::Signal signal = cosmos::signal::NONE
	);

	/// Returns a message about the current ptrace event.
	/**
	 * This is either the exit status if the child exited or the PID of a
	 * new process for fork/clone tracing.
	 **/
	unsigned long getEventMsg() const;

	/// Sets \c options, a bitmask of TraceOpts.
	void setOptions(const cosmos::TraceFlags flags);

	/// Makes the tracee a tracee.
	void seize();

	/// Sets the tracee, if not already done so.
	void setTracee(const cosmos::ProcessID tracee);

	/// Called when the tracee exits
	virtual void exited(const cosmos::WaitRes &) {}

	/// Reads the current register set from the process.
	/**
	 * This is only possible it the tracee is currently in stopped state
	 **/
	void getRegisters(RegisterSet &rs);

	void handleSystemCall();

	void handleSignal(const cosmos::WaitRes &wr);

protected:
	/// Callback interface receiving our information
	TraceEventConsumer &m_consumer;
	/// The current state the tracee is in
	TraceState m_state = TraceState::UNKNOWN;
	/// PID of the tracee we're dealing with
	cosmos::ProcessID m_tracee = cosmos::ProcessID::INVALID;
	/// Here we store our current knowledge open file descriptions
	DescriptorPathMapping m_fd_path_map;
	/// Reusable database object for tracing system calls
	SystemCallDB m_syscall_db;
	/// Reusable register set object for tracing system calls
	RegisterSet m_reg_set;
	/// Holds state for the currently executing system call
	SystemCall *m_current_syscall = nullptr;
};

} // end ns
