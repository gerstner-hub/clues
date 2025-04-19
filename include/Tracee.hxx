#pragma once

// C++
#include <array>
#include <iosfwd>

// Linux
#include <unistd.h>

// cosmos
#include <cosmos/BitMask.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/proc/ptrace.hxx>
#include <cosmos/proc/signal.hxx>
#include <cosmos/proc/Tracee.hxx>
#include <cosmos/string.hxx>

// clues
#include <clues/RegisterSet.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/types.hxx>

namespace clues {

class SystemCall;
class RegisterSet;

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

		virtual void syscallEntry(const SystemCall &sc, const State state) = 0;

		virtual void syscallExit(const SystemCall &sc, const State state) = 0;

		/// The tracee has received a signal.
		/**
		 * This callback notifies about signals being delivered to the
		 * tracee.
		 **/
		virtual void signaled(const cosmos::SigInfo &info) {
			(void)info;
		};

		/// The tracee entered group-stop due to a stopping signal.
		virtual void stopped() {}

		/// The tracee resumed due to SIGCONT.
		virtual void resumed() {}

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
		virtual void exited(const cosmos::WaitStatus status, const State state) {
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
				const std::string &old_executable,
				const cosmos::StringVector &old_cmdline,
				const std::optional<cosmos::ProcessID> former_pid) {
			(void)former_pid;
			(void)old_cmdline;
			(void)old_executable;
		}
	};

	/// Current tracing state for a single tracee.
	/**
	 * These states are modelled after the states described in man(2) ptrace.
	 **/
	enum class State {
		UNKNOWN, ///< initial PTRACE_SIZE / PTRACE_INTERRUPT.
		RUNNING, ///< tracee is running normally / not in a special trace state.
		SYSCALL_ENTER_STOP, ///< system call started.
		SYSCALL_EXIT_STOP, ///< system call finished.
		SIGNAL_DELIVERY_STOP, ///< signal was delivered.
		GROUP_STOP, ///< SIGSTOP executed, the tracee is stopped.
		EVENT_STOP, ///< special ptrace event occurred.
		DEAD ///< the tracee no longer exists.
	};

	/// Different flags reflecting the tracer status.
	enum class Flag {
		WAIT_FOR_ATTACH_STOP = 1 << 1, ///< we're still waiting for the PTRACE_INTERRUPT event stop.
		WAIT_FOR_DETACH_STOP = 1 << 2, ///< we're still waiting for the SIGSTOP we injected for detaching.
		INJECTED_SIGSTOP     = 1 << 3, ///< whether we've injected a SIGSTOP that needs to be undone.
		SYSCALL_ENTERED      = 1 << 4, ///< we've seen a syscall-enter-stop and wait for the corresponding exit-stop.
	};

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	virtual ~Tracee() {}

	const std::string& executable() const {
		return m_executable;
	}

	const cosmos::StringVector cmdLine() const {
		return m_cmdline;
	}

	cosmos::ProcessID pid() const {
		return m_ptrace.pid();
	}

	static const char* getStateLabel(const State state);

	State state() const {
		return m_state;
	}

	State prevState() const {
		return m_prev_state;
	}

	/// Returns possible tracee exit data.
	/**
	 * After trace() returns, if tracee exit was observed, this returns
	 * the tracee exit information (it's exit status or kill signal etc.).
	 **/
	std::optional<cosmos::ChildData> exitData() const {
		return m_exit_data;
	}

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

protected: // constants

	/// Array of signals that cause tracee stop.
	/**
	 * Stopping signals are treated specially during tracing since they
	 * result in a group-stop state change. This constexpr array is used
	 * to identify them.
	 **/
	static constexpr std::array<cosmos::Signal, 4> STOPPING_SIGNALS = {
		cosmos::signal::STOP, cosmos::signal::TERM_STOP,
		cosmos::signal::TERM_INPUT, cosmos::signal::TERM_OUTPUT
	};

protected: // functions

	explicit Tracee(EventConsumer &consumer);

	void updateExecutable();

	void updateCmdLine();

	void updateExecInfo() {
		updateExecutable();
		updateCmdLine();
	}

	void changeState(const State new_state);

	/// Waits for the next trace event of this tracee.
	virtual void wait(cosmos::ChildData &data) = 0;

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

	void handleSystemCall();

	void handleSystemCallEntry();

	void handleSystemCallExit();

	void handleStateMismatch();

	void handleSignal(const cosmos::SigInfo &info);

	void handleEvent(const cosmos::ptrace::Event event, const cosmos::Signal signal);

	void handleStopEvent(const cosmos::Signal signal);

	void handleExitEvent();

	void handleExecEvent();

	void handleAttached();

	/// Reads data from the Tracee starting at `addr` and feeds it to `filler` until it's saturated.
	template <typename FILLER>
	void fillData(const long *addr, FILLER &filler) const;

protected: // data

	/// Callback interface receiving our information.
	EventConsumer &m_consumer;
	/// The current state the tracee is in.
	State m_state = State::UNKNOWN;
	/// The previous Tracee state we've seen (except RUNNING).
	State m_prev_state = State::UNKNOWN;
	/// These keep track of various state on the tracer side.
	Flags m_flags;
	/// PID of the tracee we're dealing with.
	cosmos::Tracee m_ptrace;
	/// Here we store our current knowledge about open file descriptions.
	DescriptorPathMapping m_fd_path_map;
	/// The current system call information, if any.
	std::optional<cosmos::ptrace::SyscallInfo> m_syscall_info;
	/// Reusable database object for tracing system calls.
	SystemCallDB m_syscall_db;
	/// Holds state for the currently executing system call.
	SystemCall *m_current_syscall = nullptr;
	/// Previous system call, if it has been interrupted.
	SystemCall *m_interrupted_syscall = nullptr;
	/// current RestartMode to use.
	cosmos::Tracee::RestartMode m_restart_mode = cosmos::Tracee::RestartMode::CONT;
	/// signal to inject upon next restart of the tracee.
	std::optional<cosmos::Signal> m_inject_sig;
	/// If tracee exit was observed then this contains the final exit data.
	std::optional<cosmos::ChildData> m_exit_data;
	/// Path to the executable we're tracing (/proc/<pid>/exe).
	std::string m_executable;
	/// Command line used to create the process (/proc/<pid>/cmdline).
	cosmos::StringVector m_cmdline;
	/// Number of system calls observed.
	size_t m_syscall_ctr = 0;
	/// Register set observed during initial attach event stop.
	RegisterSet m_initial_regset;
};

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::Tracee::State &state);
