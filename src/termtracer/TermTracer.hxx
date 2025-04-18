#pragma once

// C++
#include <memory>

// TCLAP
#include <tclap/CmdLine.h>

// cosmos
#include <cosmos/io/StdLogger.hxx>
#include <cosmos/main.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/types.hxx>

// clues
#include <clues/SystemCall.hxx>

namespace clues {

class TermTracer :
		public Tracee::EventConsumer,
       		public cosmos::MainPlainArgs {
public: // functions

	TermTracer();

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

protected: // event consumer interface

	void syscallEntry(const SystemCall &sc, const State state) override;

	void syscallExit(const SystemCall &sc, const State state) override;

	void signaled(const cosmos::SigInfo &info) override;

	void exited(const cosmos::WaitStatus status, const State state) override;

	void newExecutionContext(const std::string &old_exe,
			const cosmos::StringVector &old_cmdline,
			const std::optional<cosmos::ProcessID> former_pid) override;

protected: // data

	TCLAP::CmdLine m_cmdline;
	/// Already running process to attach to.
	TCLAP::ValueArg<std::underlying_type<cosmos::ProcessID>::type> m_attach_proc;
	/// Increase verbosity of tracing output.
	TCLAP::SwitchArg m_verbose;
	/// Maximum length of parameter values to print.
	TCLAP::ValueArg<int> m_max_value_len;

	/// cosmos ILogger instance for clues library logging.
	cosmos::StdLogger m_logger;
	cosmos::Init m_cosmos;

	std::unique_ptr<Tracee> m_tracee;
	/// Messages that that are supposed to be printed after the next syscall-exit event.
	cosmos::StringVector m_delayed_messages;

	bool m_seen_initial_exec = false;
	bool m_print_values = true;
	size_t m_value_truncation_len = 64;
};

} // end ns
