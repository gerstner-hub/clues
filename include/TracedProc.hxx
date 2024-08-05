#pragma once

// Linux
#include <unistd.h>
#include <sys/ptrace.h>

// cosmos
#include <cosmos/proc/ChildCloner.hxx>
#include <cosmos/proc/ptrace.hxx>
#include <cosmos/proc/Signal.hxx>
#include <cosmos/proc/SubProc.hxx>
#include <cosmos/string.hxx>

// clues
#include <clues/ptrace.hxx>
#include <clues/RegisterSet.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/types.hxx>

namespace clues {

class RegisterSet;
class SystemCall;

/// Base class for traced processes.
/**
 * The concrete implementation of TracedProc defines the means of how the
 * traced process is attached to and detached from etc.
 **/
class CLUES_API TracedProc {
public: // types

	/// Pure virtual interface for consumers of tracing events.
	class EventConsumer {
		friend class TracedProc;
	protected: // functions

		virtual void syscallEntry(const SystemCall &sc) = 0;

		virtual void syscallExit(const SystemCall &sc) = 0;
	};

public: // functions

	virtual ~TracedProc() {}

	/// Logic to handle attaching to the tracee.
	virtual void attach() = 0;

	/// Logic to handle detaching from the tracee.
	virtual void detach() = 0;

	/// Actually start processing events from the tracee.
	/**
	 * This call will run until the traced process stops executing.
	 **/
	void trace();

	/// Reads a word of data from the tracee's memory.
	/**
	 * The word found at \c addr is returned from this function on
	 * success. On error an exception is thrown.
	 **/
	long getData(const long *addr) const;

protected: // functions

	explicit TracedProc(EventConsumer &consumer);

	/// Waits for the next trace event of this tracee.
	virtual void wait(cosmos::WaitRes &res) = 0;

	/// Called when the tracee exits
	virtual void exited(const cosmos::WaitRes &) {}

	/// Forces the traced process to stop.
	void interrupt() {
		ptrace::interrupt(m_tracee);
	}

	/// Continues the traced process, optionally delivering `signal`.
	void cont(const cosmos::ContinueMode &mode = cosmos::ContinueMode::NORMAL,
			const std::optional<cosmos::Signal> signal = {}) {
		ptrace::cont(m_tracee, mode, signal);
	}

	/// Applies the given trace `flags`.
	void setOptions(const cosmos::TraceFlags flags) {
		ptrace::set_options(m_tracee, flags);
	}

	/// Makes the tracee a tracee.
	void seize() {
		ptrace::seize(m_tracee);
	}

	/// Sets the tracee PID
	void setTracee(const cosmos::ProcessID tracee);

	/// Reads the current register set from the process.
	/**
	 * This is only possible it the tracee is currently in stopped state
	 **/
	void getRegisters(RegisterSet &rs);

	void handleSystemCall();

	void handleSignal(const cosmos::WaitRes &wr);

protected: // data

	/// Callback interface receiving our information
	EventConsumer &m_consumer;
	/// The current state the tracee is in
	TraceState m_state = TraceState::UNKNOWN;
	/// PID of the tracee we're dealing with
	cosmos::ProcessID m_tracee = cosmos::ProcessID::INVALID;
	/// Here we store our current knowledge about open file descriptions
	DescriptorPathMapping m_fd_path_map;
	/// Reusable database object for tracing system calls
	SystemCallDB m_syscall_db;
	/// Reusable register set object for tracing system calls
	RegisterSet m_reg_set;
	/// Holds state for the currently executing system call
	SystemCall *m_current_syscall = nullptr;
};

} // end ns
