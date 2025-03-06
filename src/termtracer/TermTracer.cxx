// TCLAP
#include <tclap/CmdLine.h>

// C++
#include <cstdlib>
#include <iostream>
#include <map>
#include <string_view>

// cosmos
#include <cosmos/cosmos.hxx>
#include <cosmos/error/CosmosError.hxx>
#include <cosmos/io/StdLogger.hxx>
#include <cosmos/main.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/proc/signal.hxx>
#include <cosmos/string.hxx>

// clues
#include <clues/ChildTracee.hxx>
#include <clues/clues.hxx>
#include <clues/ForeignTracee.hxx>
#include <clues/SystemCall.hxx>
#include <clues/SystemCallValue.hxx>

namespace clues {

class TermTracer :
		public Tracee::EventConsumer,
       		public cosmos::MainPlainArgs {
public: // functions

	TermTracer();

protected: // functions

	void processPars();

	cosmos::ExitStatus main(const int argc, const char **argv) override;

	void runTrace(const cosmos::ProcessID pid);

	cosmos::ExitStatus runTrace(const cosmos::StringVector &cmdline);

	void configureLogger();

protected: // event consumer interface

	void syscallEntry(const SystemCall &sc) override;

	void syscallExit(const SystemCall &sc) override;

	void signaled(const cosmos::SigInfo &info) override;

protected: // data

	TCLAP::CmdLine m_cmdline;
	/// Already running process to attach to.
	TCLAP::ValueArg<std::underlying_type<cosmos::ProcessID>::type> m_attach_proc;
	/// Switch to express we want to start a new process as a frontend.
	TCLAP::SwitchArg m_start_proc;
	/// Increase verbosity of tracing output.
	TCLAP::SwitchArg m_verbose;
	/// Maximum length of parameter values to print.
	TCLAP::ValueArg<int> m_max_value_len;

	/// cosmos ILogger instance for clues library logging.
	cosmos::StdLogger m_logger;

	bool m_print_values = true;
	size_t m_value_truncation_len = 64;
};

TermTracer::TermTracer() :
		m_cmdline{"Command line process tracer", ' ', "0.1"},
		m_attach_proc{
			"p", "process",
			"attach to the given already running process for tracing",
			false,
			cosmos::to_integral(cosmos::ProcessID::INVALID),
			"Process ID"},
		m_start_proc{
			"c", "create",
			"create a new process using arguments specified after '--'",
			false},
		m_verbose{
			"v", "verbose",
			"increase verbosity of tracing output",
			false},
		m_max_value_len{
			"s", "max-len",
			"maximum length of parameter values to print. 0 to to print not at all, -1 to disable truncation",
			false,
			64,
			"number of bytes"} {
}

void TermTracer::processPars() {
	auto max_len = m_max_value_len.getValue();

	if (max_len == 0)
		m_print_values = false;
	else if (max_len < 0)
		m_value_truncation_len = SIZE_MAX;
	else
		m_value_truncation_len = static_cast<size_t>(max_len);
}

void TermTracer::configureLogger() {
	std::map<std::string_view, bool> settings = {
		{"error", true},
		{"warn", true},
		{"info", false},
		{"debug", false}
	};

	if (auto config = cosmos::proc::get_env_var("CLUES_LOGGING"); config != std::nullopt) {
		for (auto &stream: cosmos::split(
					config->view(), ",", cosmos::SplitFlags{cosmos::SplitFlag::STRIP_PARTS})) {
			stream = cosmos::to_lower(stream);
			bool enabled = true;

			if (stream[0] == '!') {
				enabled = false;
				stream = stream.substr(1);
			}

			if (auto it = settings.find(stream); it != settings.end()) {
				it->second = enabled;
			}
		}
	}

	m_logger.setChannels(settings["error"], settings["warn"], settings["info"], settings["debug"]);
	clues::set_logger(m_logger);
}

void TermTracer::syscallEntry(const SystemCall &sc) {
	std::cerr << sc.name() << "(" << std::flush;
}

void TermTracer::syscallExit(const SystemCall &sc) {
	bool first = true;
	for (const auto par: sc.parameters()) {
		if (first)
			first = false;
		else
			std::cerr << ", ";

		std::cerr << (m_verbose.isSet() ? par->longName() : par->shortName());

		if (m_print_values) {
			auto value = par->str();

			if (value.size() > m_value_truncation_len) {
				value.resize(m_value_truncation_len);
				value += "...";
			}

			std::cerr << "=" << value;
		}
	}

	const auto &res = sc.result();

	std::cerr << ") = " << res.str() << " (" << (m_verbose.isSet() ? res.longName() : res.shortName()) << ")\n";
}

void TermTracer::signaled(const cosmos::SigInfo &info) {
	std::cerr << "-- " << info.sigNr() << " --\n";
}

void TermTracer::runTrace(const cosmos::ProcessID pid) {
	ForeignTracee proc{*this};
	proc.configure(pid);
	proc.attach();
	proc.trace();
	proc.detach();
}

cosmos::ExitStatus TermTracer::runTrace(const cosmos::StringVector &cmdline) {
	ChildTracee proc{*this};
	proc.create(cmdline);
	proc.attach();
	proc.trace();
	proc.detach();
	return proc.exitStatus();
}

cosmos::ExitStatus TermTracer::main(const int argc, const char **argv) {
	m_cmdline.add(m_attach_proc);
	m_cmdline.add(m_start_proc);
	m_cmdline.parse(argc, argv);

	configureLogger();

	processPars();

	cosmos::signal::block(cosmos::SigSet{cosmos::signal::CHILD});

	if (m_attach_proc.isSet()) {
		runTrace(cosmos::ProcessID{m_attach_proc.getValue()});
		return cosmos::ExitStatus::SUCCESS;
	} else if (m_start_proc.isSet()) {
		// extract any additional arguments into a StringVector
		cosmos::StringVector sv;
		bool found_sep = false;

		for (auto arg = 1; arg < argc; arg++) {
			if (found_sep) {
				sv.push_back(argv[arg]);
			} else if (std::string(argv[arg]) == "--") {
				found_sep = true;
			}
		}

		return runTrace(sv);
	} else {
		std::cerr << "Neither -p nor -c was given. Nothing to do.\n";
		return cosmos::ExitStatus::FAILURE;
	}
}

} // end ns

int main(const int argc, const char **argv) {
	return cosmos::main<clues::TermTracer>(argc, argv);
}
