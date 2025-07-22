#pragma once

// C++
#include <map>
#include <memory>
#include <set>
#include <tuple>

// cosmos
#include <cosmos/BitMask.hxx>
#include <cosmos/io/StdLogger.hxx>
#include <cosmos/main.hxx>
#include <cosmos/types.hxx>

// clues
#include <clues/Engine.hxx>
#include <clues/EventConsumer.hxx>
#include <clues/SystemCall.hxx>

// termtracer
#include "Args.hxx"

namespace clues {

class TermTracer :
		public clues::EventConsumer,
       		public cosmos::MainPlainArgs {
public: // functions

	TermTracer();

	TermTracer(const TermTracer&) = delete;
	TermTracer& operator=(const TermTracer&) = delete;

protected: // types

	/// What to do upon execve
	enum class FollowExecContext {
		YES,
		NO,
		ASK,
		CHECK_PATH,
		CHECK_GLOB
	};

	enum class FollowChildMode {
		YES,
		NO,
		ASK,
		THREADS
	};

	enum class Flag {
		SEEN_INITIAL_EXEC      = 1 << 0, ///< whether we've seen a ChildTracee's initial newExecutionContext().
		DROPPED_TO_LAST_TRACEE = 1 << 1, ///< whether we've returned to tracing only a single PID anymore.
	};

	using Flags = cosmos::BitMask<Flag>;

protected: // functions

	bool processPars();

	void printSyscalls();

	cosmos::ExitStatus main(const int argc, const char **argv) override;

	bool configureTracee(const cosmos::ProcessID pid);

	void runTrace();

	void configureLogger();

	void printTraceeInvocation(std::ostream &out, const Tracee &tracee);
	void printTraceeInvocation(std::ostream &out,
			const std::string &exe,
			const cosmos::StringVector &cmdline) const;
	void printPar(const SystemCallItem &value) const;
	void printParsOnEntry(const SystemCall::ParameterVector &pars) const;
	void printParsOnExit(const SystemCall::ParameterVector &pars) const;

	bool followExecutionContext(Tracee &tracee);

	/// Start a new output line concerning `tracee.
	/**
	 * This prints out any preamble that might be necessary for starting a
	 * new trace output line, like `[<pid>] `, when multiple tracees are
	 * present.
	 *
	 * It also cares about managing the system call state to make sure
	 * unfinished system calls are kept track of.
	 **/
	void startNewLine(const Tracee &tracee);

	/// Store an active system call in m_unfinished_syscalls.
	/**
	 * If there's an active system call then store if in
	 * m_unfinished_syscalls and reset it.
	 **/
	void storeUnfinishedSyscallCtx();

	/// Check whether `tracee` has an unfinished system call pending.
	/**
	 * If `tracee` has an unfinished system call pending in
	 * m_unfinished_syscalls, then clean up the data structure and output
	 * appropriate text to indicate the situation.
	 **/
	void checkResumedSyscall(const Tracee &tracee);

	bool hasActiveSyscall(const Tracee &tracee) const {
		return hasActiveSyscall(tracee.pid());
	}

	bool hasActiveSyscall(const cosmos::ProcessID pid) const {
		if (!m_active_syscall)
		       return false;

		return std::get<cosmos::ProcessID>(*m_active_syscall) == pid;
	}

	const SystemCall* activeSyscall() const {
		if (!m_active_syscall)
			return nullptr;

		return std::get<const SystemCall*>(*m_active_syscall);
	}

	bool isExecSyscall(const SystemCall &sc) const;

	/// Returns `true` if `sc` is set and supposed to the printed.
	bool isEnabled(const SystemCall *sc) const;

	/// Returns the system call last seen for `tracee`.
	const SystemCall* currentSyscall(const Tracee &tracee) const;

	void cleanupTracee(const Tracee &tracee);

	void updateTracee(const Tracee &tracee, const cosmos::ProcessID old_pid);

	bool seenInitialExec() const {
		return m_flags[Flag::SEEN_INITIAL_EXEC];
	}

protected: // event consumer interface

	void syscallEntry(Tracee &tracee, const SystemCall &sc, const StatusFlags flags) override;

	void syscallExit(Tracee &tracee, const SystemCall &sc, const StatusFlags flags) override;

	void signaled(Tracee &tracee, const cosmos::SigInfo &info) override;

	void attached(Tracee &tracee) override;

	void exited(Tracee &tracee, const cosmos::WaitStatus status, const StatusFlags flags) override;

	void newExecutionContext(Tracee &tracee,
			const std::string &old_exe,
			const cosmos::StringVector &old_cmdline,
			const std::optional<cosmos::ProcessID> old_pid) override;

	void newChildProcess(
			Tracee &parent,
			Tracee &child,
			const cosmos::ptrace::Event event) override;

	void stopped(Tracee &tracee) override;

protected: // data

	/// Command line arguments and parser.
	Args m_args;

	/// cosmos ILogger instance for clues library logging.
	cosmos::StdLogger m_logger;
	cosmos::Init m_cosmos;

	/// libclues main object.
	Engine m_engine;

	/// Whether to print system call parameters at all (-s 0 disables it).
	bool m_print_pars = true;
	/// Maximum length of of system call parameter values to print before truncating the output.
	size_t m_par_truncation_len = 64;
	/// optional argument to m_follow_exec (e.g. path, glob, script)
	std::string m_exec_context_arg;
	/// Whitelist of system calls to trace, if any.
	std::set<SystemCallNr> m_syscall_filter;
	/// Behaviour upon newExecutionContext()
	FollowExecContext m_follow_exec = FollowExecContext::YES;
	/// Behaviour upon newChildProcess()
	FollowChildMode m_follow_children = FollowChildMode::NO;

	/// The number of tracees we're currently dealing with.
	size_t m_num_tracees = 0;
	/// State flags with global context or carried between different callbacks.
	Flags m_flags;
	/// The PID of the main process we're tracing (the one we created or attached to).
	cosmos::ProcessID m_main_tracee_pid;
	/// The WaitStatus of the main process we've seen upon it exiting.
	std::optional<cosmos::WaitStatus> m_main_status;

	/// A currently active system call, if any.
	std::optional<std::tuple<cosmos::ProcessID, const SystemCall*>> m_active_syscall;
	/// Unfinished / preempted system calls.
	/**
	 * Unfinished in this context is purely tracing related, it only means
	 * that we already started printing system call entry for one tracee,
	 * while another event came in, preempting this line.
	 **/
	std::map<cosmos::ProcessID, const SystemCall*> m_unfinished_syscalls;
	/// Newly created tracees that haven't seen any ptrace stop yet
	std::map<cosmos::ProcessID, std::pair<cosmos::ProcessID, cosmos::ptrace::Event>> m_new_tracees;
};

} // end ns
