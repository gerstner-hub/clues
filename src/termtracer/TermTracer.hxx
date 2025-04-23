#pragma once

// C++
#include <memory>

// cosmos
#include <cosmos/io/StdLogger.hxx>
#include <cosmos/main.hxx>
#include <cosmos/types.hxx>

// clues
#include <clues/SystemCall.hxx>

// termtracer
#include "Args.hxx"

namespace clues {

class TermTracer :
		public Tracee::EventConsumer,
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

	bool configureTrace(const cosmos::StringVector &cmdline);

	void runTrace();

	void configureLogger();

	void printTraceeInvocation(std::ostream &out,
			const std::string &exe,
			const cosmos::StringVector &cmdline) const;
	void printPar(const SystemCallItem &value, const bool is_last) const;
	void printEntryPars(const SystemCall::ParameterVector &pars) const;
	void printExitPars(const SystemCall::ParameterVector &pars) const;

	bool followExecutionContext();

protected: // event consumer interface

	void syscallEntry(const SystemCall &sc, const State state) override;

	void syscallExit(const SystemCall &sc, const State state) override;

	void signaled(const cosmos::SigInfo &info) override;

	void exited(const cosmos::WaitStatus status, const State state) override;

	void newExecutionContext(const std::string &old_exe,
			const cosmos::StringVector &old_cmdline,
			const std::optional<cosmos::ProcessID> former_pid) override;

	void stopped() override;

protected: // data

	/// Command line arguments and parser.
	Args m_args;

	/// cosmos ILogger instance for clues library logging.
	cosmos::StdLogger m_logger;
	cosmos::Init m_cosmos;

	std::unique_ptr<Tracee> m_tracee;

	bool m_seen_initial_exec = false;
	bool m_print_values = true;
	size_t m_value_truncation_len = 64;

	FollowExecContext m_follow_exec = FollowExecContext::YES;
	/// optional argument to m_follow_exec (e.g. path, glob, script)
	std::string m_exec_context_arg;
};

} // end ns
