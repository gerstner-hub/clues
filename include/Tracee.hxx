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
class EventConsumer;
class Engine;

/// Base class for traced processes.
/**
 * The concrete implementation of Tracee defines the means of how the
 * traced process is attached to and detached from etc.
 **/
class CLUES_API Tracee {
	friend class Engine;
public: // types

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
		DEAD, ///< the tracee no longer exists.
		DETACHED, ///< we already detached from the tracee
	};

	/// Different flags reflecting the tracer status.
	enum class Flag {
		WAIT_FOR_ATTACH_STOP = 1 << 0, ///< we're still waiting for the PTRACE_INTERRUPT event stop.
		DETACH_AT_NEXT_STOP  = 1 << 1, ///< as soon as the tracee reaches a stop stace, detach from it.
		INJECTED_SIGSTOP     = 1 << 2, ///< whether we've injected a SIGSTOP that needs to be undone.
		INJECTED_SIGCONT     = 1 << 3, ///< whether we've injected a SIGCONT that needs to be ignored.
		SYSCALL_ENTERED      = 1 << 4, ///< we've seen a syscall-enter-stop and are waiting for the corresponding exit-stop.
		WAIT_FOR_EXECVE_REPLACEMENT = 1 << 5, ///< execve() in another thread caused this tracee to exit, wait for the personality change of this pid.
		WAIT_FOR_EXITED      = 1 << 6, ///< we've already seen PTHREAD_EVENT_EXIT but are still waiting for CLD_EXITED.
		ATTACH_THREADS_PENDING = 1 << 7, ///< attach all threads of the process as soon as the initial event stop happens.
	};

	using Flags = cosmos::BitMask<Flag>;

public: // functions

	virtual ~Tracee();

	const std::string& executable() const {
		return m_executable;
	}

	const cosmos::StringVector cmdLine() const {
		return m_cmdline;
	}

	cosmos::ProcessID pid() const {
		return m_ptrace.pid();
	}

	bool alive() const {
		return pid() != cosmos::ProcessID::INVALID;
	}

	/// Returns the number of system calls observed so far
	/**
	 * This counts the number of system call entries observed while
	 * tracing this PID.
	 **/
	size_t syscallCtr() const {
		return m_syscall_ctr;
	}

	/// For state() == State::GROUP_STOP this returns the stopping signal that caused it.
	std::optional<cosmos::Signal> stopSignal() const {
		return m_stop_signal;
	}

	static const char* getStateLabel(const State state);

	State state() const {
		return m_state;
	}

	State prevState() const {
		return m_prev_state;
	}

	Flags flags() const {
		return m_flags;
	}

	/// Returns possible tracee exit data.
	/**
	 * After the tracee is detached, if tracee exit was observed, this
	 * returns the tracee exit information (it's exit status or kill
	 * signal etc.).
	 **/
	std::optional<cosmos::ChildState> exitData() const {
		return m_exit_data;
	}

	/// Logic to handle attaching to the tracee.
	/**
	 * \param[in] follow_childs If true then newly created child processes
	 * will automatically be attached. The EventConsumer interface will
	 * received a newChildProcess() callback once a new child process has
	 * been attached. This covers all ways by which new child processes
	 * can be created (fork, vfork, clone).
	 **/
	virtual void attach(const FollowChilds follow_childs);

	/// Logic to handle detaching from the tracee.
	void detach();

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

	/// Returns whether the tracee is a child process created by us.
	/**
	 * If the tracee is a child process then the tracer needs to take care
	 * of its lifecycle, while non-related tracee's can just be detached
	 * from.
	 **/
	virtual bool isChildProcess() const {
		return false;
	}

	/// Checks in the proc file system whether the Tracee is a thread group leader.
	/**
	 * Calling this function is only safe during a ptrace stop.
	 *
	 * This information is relevant for the execve in a multi-threaded
	 * process situation.
	 *
	 * Sadly this bit is not easily accessible via system calls. The only
	 * way to determine it is from /proc/<pid>/status or implicitly e.g. a
	 * newly fork()'ed process is a thread-group leader while clone()'ed
	 * processes _can_ be thread-group leaders (if its not a thread that
	 * has been created).
	 **/
	bool isThreadGroupLeader() const;

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

	explicit Tracee(Engine &engine, EventConsumer &consumer);

	/// Process the given ptrace event.
	/**
	 * This call will be invoked by the Engine class to drive the tracing
	 * logic.
	 **/
	void processEvent(const cosmos::ChildState &data);

	void updateExecutable();

	void updateCmdLine();

	void updateExecInfo() {
		updateExecutable();
		updateCmdLine();
	}

	void changeState(const State new_state);

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
	void setPID(const cosmos::ProcessID tracee);

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

	void handleEvent(const cosmos::ChildState &data,
			const cosmos::ptrace::Event event,
			const cosmos::Signal signal);

	void handleStopEvent(const cosmos::Signal signal);

	void handleExitEvent();

	void handleExecEvent(const cosmos::ProcessID main_pid);

	void handleNewChildEvent(const cosmos::ptrace::Event event);

	void handleAttached();

	void syncState(Tracee &other);

	/// Reads data from the Tracee starting at `addr` and feeds it to `filler` until it's saturated.
	template <typename FILLER>
	void fillData(const long *addr, FILLER &filler) const;

	virtual void cleanupChild() {}

protected: // data

	/// The engine that manages this tracee.
	Engine &m_engine;
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
	std::optional<cosmos::ChildState> m_exit_data;
	/// Path to the executable we're tracing (/proc/<pid>/exe).
	std::string m_executable;
	/// Command line used to create the process (/proc/<pid>/cmdline).
	cosmos::StringVector m_cmdline;
	/// Number of system calls observed.
	size_t m_syscall_ctr = 0;
	/// Register set observed during initial attach event stop.
	RegisterSet m_initial_regset;
	/// For GROUP_STOP this contains the signal that caused it.
	std::optional<cosmos::Signal> m_stop_signal;
};

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::Tracee::State &state);
