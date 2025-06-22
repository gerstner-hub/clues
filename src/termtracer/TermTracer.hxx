#pragma once

// C++
#include <map>
#include <memory>
#include <set>
#include <tuple>

// cosmos
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

protected: // functions

	bool processPars();

	cosmos::ExitStatus main(const int argc, const char **argv) override;

	bool configureTrace(const cosmos::ProcessID pid);

	void runTrace();

	void configureLogger();

	void printTraceeInvocation(std::ostream &out,
			const std::string &exe,
			const cosmos::StringVector &cmdline) const;
	void printPar(const SystemCallItem &value, const bool is_last) const;
	void printEntryPars(const SystemCall::ParameterVector &pars) const;
	void printExitPars(const SystemCall::ParameterVector &pars) const;

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
	void startNewOutputLine(const Tracee &tracee);

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

	void cleanupTracee(const Tracee &tracee);

	void updateTracee(const Tracee &tracee, const cosmos::ProcessID old_pid);

protected: // event consumer interface

	void syscallEntry(Tracee &tracee, const SystemCall &sc, const State state) override;

	void syscallExit(Tracee &tracee, const SystemCall &sc, const State state) override;

	void signaled(Tracee &tracee, const cosmos::SigInfo &info) override;

	void attached(Tracee &tracee) override;

	void exited(Tracee &tracee, const cosmos::WaitStatus status, const State state) override;

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

	Engine m_engine;
	cosmos::ProcessID m_main_tracee_pid;
	std::optional<cosmos::WaitStatus> m_main_status;

	bool m_seen_initial_exec = false;
	bool m_print_values = true;
	std::optional<std::tuple<cosmos::ProcessID, const SystemCall*>> m_active_syscall;
	/// Unfinished / preempted system calls.
	/**
	 * Unfinished in this context is purely tracing related, it only means
	 * that we already started printing system call entry for one tracee,
	 * while another event came in, preempting this line.
	 **/
	std::map<cosmos::ProcessID, const SystemCall*> m_unfinished_syscalls;
	size_t m_value_truncation_len = 64;

	FollowExecContext m_follow_exec = FollowExecContext::YES;
	FollowChildMode m_follow_childs = FollowChildMode::NO;
	/// optional argument to m_follow_exec (e.g. path, glob, script)
	std::string m_exec_context_arg;

	/// The number of tracees we're currently dealing with.
	size_t m_num_tracees = 0;
	/// Whether we've had multiple tracees but lost all but one again.
	bool m_dropped_to_single_tracee = false;
	/// Newly created tracees that haven't seen any ptrace stop yet
	std::map<cosmos::ProcessID, std::pair<cosmos::ProcessID, cosmos::ptrace::Event>> m_new_tracees;
};

} // end ns
