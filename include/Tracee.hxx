#pragma once

// Linux
#include <unistd.h>
#include <sys/ptrace.h>

// cosmos
#include <cosmos/proc/ptrace.hxx>
#include <cosmos/proc/signal.hxx>
#include <cosmos/proc/SubProc.hxx>
#include <cosmos/proc/Tracee.hxx>
#include <cosmos/string.hxx>

// clues
#include <clues/RegisterSet.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/types.hxx>

namespace clues {

class RegisterSet;
class SystemCall;

/// Base class for traced processes.
/**
 * The concrete implementation of Tracee defines the means of how the
 * traced process is attached to and detached from etc.
 **/
class CLUES_API Tracee {
public: // types

	/// Pure virtual interface for consumers of tracing events.
	class EventConsumer {
		friend class Tracee;
	protected: // functions

		virtual void syscallEntry(const SystemCall &sc) = 0;

		virtual void syscallExit(const SystemCall &sc) = 0;
	};

public: // functions

	virtual ~Tracee() {}

	/// Logic to handle attaching to the tracee.
	virtual void attach();

	/// Logic to handle detaching from the tracee.
	virtual void detach() = 0;

	/// Actually start processing events from the tracee.
	/**
	 * This call will run until the traced process stops executing.
	 **/
	void trace();

	/// Reads a word of data from the tracee's memory.
	/**
	 * The word found at `addr` is returned from this function on
	 * success. On error an exception is thrown.
	 **/
	long getData(const long *addr) const;

	/// Reads a zero-terminated C-string from the tracee.
	/**
	 * Read from the tracee's address space starting at `addr` into the
	 * C++ string object `out`.
	 **/
	void readString(const long *addr, std::string &out) const;

	/// Reads an arbitrary binary blob of fixed length from the tracee.
	void readBlob(const long *addr, char *buffer, const size_t bytes) const;

	/// Reads a system call struct from the tracee's address space into `out`.
	/**
	 * \return `true` if `out` could be filled, `false` otherwise (e.g.
	 * nullptr was encouneterd).
	 **/
	template <typename T>
	bool readStruct(const Word pointer, T &out) const {
		// the address of the struct in the tracee's address space
		const long *addr = reinterpret_cast<long*>(pointer);

		if (!addr)
			// null address specification
			return false;

		static_assert(std::is_pod_v<T> == true);

		readBlob(addr, reinterpret_cast<char*>(&out), sizeof(T));
		return true;
	}

	/// Reads in a zero terminated array of data items into the STL-vector like parameter `out`.
	template <typename VECTOR>
	void readVector(const long *addr, VECTOR &out) const;

protected: // functions

	explicit Tracee(EventConsumer &consumer);

	void changeState(const TraceState new_state);

	/// Waits for the next trace event of this tracee.
	virtual void wait(cosmos::ChildData &data) = 0;

	/// Called when the tracee exits
	virtual void exited(const cosmos::ChildData &) {}

	/// Forces the traced process to stop.
	void interrupt() {
		m_ptrace.interrupt();
	}

	/// Restarts the traced process, optionally delivering `signal`.
	void restart(const cosmos::Tracee::RestartMode mode = cosmos::Tracee::RestartMode::CONT,
			const std::optional<cosmos::Signal> signal = {}) {
		m_ptrace.restart(mode, signal);
	}

	/// Applies the given trace `flags`.
	void setOptions(const cosmos::ptrace::Opts opts) {
		m_ptrace.setOptions(opts);
	}

	/// Makes the tracee a tracee.
	void seize(const cosmos::ptrace::Opts opts) {
		m_ptrace.seize(opts);
	}

	/// Sets the tracee PID
	void setTracee(const cosmos::ProcessID tracee);

	/// Reads the current register set from the process.
	/**
	 * This is only possible it the tracee is currently in stopped state.
	 **/
	void getRegisters(RegisterSet &rs);

	void updateRegisters() {
		getRegisters(m_reg_set);
	}

	void handleSystemCall();

	void handleSignal(const cosmos::ChildData &data);

	/// Reads data from the Tracee starting at `addr` and feeds it to `filler` until it's saturated.
	template <typename FILLER>
	void fillData(const long *addr, FILLER &filler) const;

protected: // data

	/// Callback interface receiving our information.
	EventConsumer &m_consumer;
	/// The current state the tracee is in.
	TraceState m_state = TraceState::UNKNOWN;
	/// Whether we've seen SYSCALL_ENTER_STOP but not SYSCALL_EXIT_STOP yet.
	bool m_syscall_entered = false;
	/// PID of the tracee we're dealing with.
	cosmos::Tracee m_ptrace;
	/// Here we store our current knowledge about open file descriptions.
	DescriptorPathMapping m_fd_path_map;
	/// Reusable database object for tracing system calls.
	SystemCallDB m_syscall_db;
	/// Reusable register set object for tracing system calls.
	RegisterSet m_reg_set;
	/// Holds state for the currently executing system call.
	SystemCall *m_current_syscall = nullptr;
};

} // end ns
