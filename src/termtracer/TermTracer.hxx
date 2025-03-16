#pragma once

// TCLAP
#include <tclap/CmdLine.h>

// cosmos
#include <cosmos/main.hxx>

// clues
#include <clues/SystemCall.hxx>
#include <cosmos/io/StdLogger.hxx>
#include <cosmos/proc/process.hxx>

namespace clues {

class TermTracer :
		public Tracee::EventConsumer,
       		public cosmos::MainPlainArgs {
public: // functions

	TermTracer();

protected: // functions

	void processPars();

	cosmos::ExitStatus main(const int argc, const char **argv) override;

	cosmos::ExitStatus runTrace(const cosmos::ProcessID pid);

	cosmos::ExitStatus runTrace(const cosmos::StringVector &cmdline);

	void configureLogger();

	void printPar(const SystemCallValue &value, const bool is_last) const;
	void printEntryPars(const SystemCall::ParameterVector &pars) const;
	void printExitPars(const SystemCall::ParameterVector &pars) const;

protected: // event consumer interface

	void syscallEntry(const SystemCall &sc) override;

	void syscallExit(const SystemCall &sc) override;

	void signaled(const cosmos::SigInfo &info) override;

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

	bool m_print_values = true;
	size_t m_value_truncation_len = 64;
};

} // end ns
