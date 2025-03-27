// C++
#include <cstdlib>
#include <iostream>
#include <map>
#include <string_view>

// cosmos
#include <cosmos/cosmos.hxx>
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/CosmosError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/proc/signal.hxx>
#include <cosmos/string.hxx>

// clues
#include <clues/ChildTracee.hxx>
#include <clues/clues.hxx>
#include <clues/ForeignTracee.hxx>
#include <clues/SystemCallItem.hxx>
#include "TermTracer.hxx"

namespace clues {

TermTracer::TermTracer() :
		m_cmdline{"Command line process tracer.\nTo use clues as a front-end pass the command line to execute after '--'", ' ', "0.1"},
		m_attach_proc{
			"p", "process",
			"attach to the given already running process for tracing",
			false,
			cosmos::to_integral(cosmos::ProcessID::INVALID),
			"Process ID"},
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

void TermTracer::printEntryPars(const SystemCall::ParameterVector &pars) const {
	/*
	 * This logic covers printing of parameters during system-call entry.
	 *
	 * During entry we can print all input-only parameters and stop once
	 * we see a non-input parameter or once we are finished with all
	 * parameters.
	 *
	 * During exit we continue printing from the first non-input parameter
	 * onwards. This way we can present at least some of the system call
	 * data already for blocking system calls.
	 *
	 * There exist system calls where the order of parameters is like
	 * this:
	 *
	 * <input>, <output>, <input>
	 *
	 * In this case, while the final parameter would still be printable,
	 * we will stop at the third parameter which is an output parameter.
	 * `strace` does this similarly. In theory we could print a '?' in
	 * this case for the not yet available output data, then do a
	 * carriage-return during syscall-exit to print the end result.
	 */

	if (pars.empty())
		return;

	const auto last = pars.back();

	for (const auto &par: pars) {
		if (!par->isIn()) {
			// non-input parameter encountered, stop output
			break;
		}

		printPar(*par, par == last);
	}
}

void TermTracer::printExitPars(const SystemCall::ParameterVector &pars) const {
	if (pars.empty())
		return;

	const auto last = pars.back();
	bool seen_non_input = false;

	for (const auto &par: pars) {
		if (!seen_non_input) {
		       	if (par->isIn()) {
				// this was already printed during entry
				continue;
			} else {
				seen_non_input = true;
			}
		}

		printPar(*par, par == last);
	}
}

void TermTracer::printPar(const SystemCallItem &par, const bool is_last) const {
	std::cerr << (m_verbose.isSet() ? par.longName() : par.shortName());

	if (m_print_values) {
		auto value = par.str();

		if (value.size() > m_value_truncation_len) {
			value.resize(m_value_truncation_len);
			value += "...";
		}

		std::cerr << "=" << value;
	}

	if (!is_last) {
		std::cerr << ", ";
	}
}

void TermTracer::syscallEntry(const SystemCall &sc, const State state) {
	if (state[Status::RESUMED]) {
		std::cerr << "<resuming previously interrupted " << sc.name() << "...>\n";
	}
	std::cerr << sc.name() << "(";

	printEntryPars(sc.parameters());

	std::cerr << std::flush;
}

void TermTracer::syscallExit(const SystemCall &sc, const State state) {
	printExitPars(sc.parameters());

	std::cerr << ") = ";

	if (auto res = sc.result(); res) {
		std::cerr << res->str() << " (" << (m_verbose.isSet() ? res->longName() : res->shortName()) << ")";
	} else {
		const auto err = *sc.error();
		std::cerr << err.str() << " (errno)";
	}

	if (state[Status::INTERRUPTED]) {
		std::cerr << " (interrupted)";
	}

	std::cerr << std::endl;
}

void TermTracer::signaled(const cosmos::SigInfo &info) {
	std::cerr << "-- " << info.sigNr() << " --\n";
}

void TermTracer::exited(const cosmos::ExitStatus status) {
	// this should only ever happen after a syscallEntry() for
	// exit_group() occurred. Thus we finish that first.
	std::cerr << ") = ?\n";

	std::cerr << "+++ exited with " << status << " +++\n";
}

cosmos::ExitStatus TermTracer::runTrace(const cosmos::ProcessID pid) {
	ForeignTracee proc{*this};
	proc.configure(pid);
	try {
		proc.attach();
	} catch (const cosmos::ApiError &e) {
		std::cerr << "Failed to attach to PID " << pid << ": " << e.msg() << "\n";
		if (e.errnum() == cosmos::Errno::PERMISSION) {
			std::cerr << "You need to be root to attach to processes not owned by you\n";
			std::cerr << "The YAMA kernel security extension can prevent attaching your own processes.\n";
			std::cerr << "This also happens when another process is already tracing this process.\n";
		}
		return cosmos::ExitStatus::FAILURE;
	}
	proc.trace();
	proc.detach();
	return cosmos::ExitStatus::SUCCESS;
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
	m_cmdline.parse(argc, argv);

	configureLogger();

	processPars();

	cosmos::signal::block(cosmos::SigSet{cosmos::signal::CHILD});

	if (m_attach_proc.isSet()) {
		return runTrace(cosmos::ProcessID{m_attach_proc.getValue()});
	}

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

	if (sv.empty()) {
		std::cerr << "Neither -p nor command to execute after '--' was given. Nothing to do.\n";
		return cosmos::ExitStatus::FAILURE;
	}

	return runTrace(sv);
}

} // end ns

int main(const int argc, const char **argv) {
	return cosmos::main<clues::TermTracer>(argc, argv);
}
