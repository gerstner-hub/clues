#pragma once

// C++
#include <memory>

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

protected: // functions

	void processPars();

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

protected: // event consumer interface

	void syscallEntry(Tracee &tracee, const SystemCall &sc, const State state) override;

	void syscallExit(Tracee &tracee, const SystemCall &sc, const State state) override;

	void signaled(Tracee &tracee, const cosmos::SigInfo &info) override;

	void exited(Tracee &tracee, const cosmos::WaitStatus status, const State state) override;

	void newExecutionContext(Tracee &tracee,
			const std::string &old_exe,
			const cosmos::StringVector &old_cmdline,
			const std::optional<cosmos::ProcessID> former_pid) override;

	void stopped(Tracee &tracee) override;

protected: // data

	/// Command line arguments and parser.
	Args m_args;

	/// cosmos ILogger instance for clues library logging.
	cosmos::StdLogger m_logger;
	cosmos::Init m_cosmos;

	Engine m_engine;
	Tracee *m_main_tracee = nullptr;
	std::optional<cosmos::WaitStatus> m_main_status;

	bool m_seen_initial_exec = false;
	bool m_print_values = true;
	size_t m_value_truncation_len = 64;

	FollowExecContext m_follow_exec = FollowExecContext::YES;
	/// optional argument to m_follow_exec (e.g. path, glob, script)
	std::string m_exec_context_arg;
};

} // end ns
