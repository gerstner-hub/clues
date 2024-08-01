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

/// Specialization of TracedProc that attaches to an existing, unrelated process in the system.
class CLUES_API TracedSeizedProc :
		public TracedProc {
public: // functions

	/// Create a traced process object by attaching to the given process ID.
	TracedSeizedProc(TraceEventConsumer &consumer);

	~TracedSeizedProc() override;

	/// Sets the given process ID as the process to be traced.
	void configure(const cosmos::ProcessID tracee);

	void attach() override;
	void detach() override;

	void wait(cosmos::WaitRes &res) override;

protected: // data

};

/// Specialization of TracedProc that creates a new child process for tracing.
class CLUES_API TracedSubProc :
		public TracedProc {
public: // functions

	/// Create a traced process by creating a new process from `prog_args`
	TracedSubProc(TraceEventConsumer &consumer);

	~TracedSubProc() override;

	/// Set the child process executable and parameters to trace.
	void configure(const cosmos::StringVector &prog_args);
	void attach() override;
	void detach() override;

	/// The exit code of the sub-process, valid only after detach().
	cosmos::ExitStatus exitCode() const { return m_exit_code; }

	void wait(cosmos::WaitRes &res) override;

protected: // functions

protected: // data

	cosmos::ChildCloner m_cloner;
	/// sub-process we're tracing
	cosmos::SubProc m_child;
	cosmos::ExitStatus m_exit_code = cosmos::ExitStatus::SUCCESS;
};

} // end ns
