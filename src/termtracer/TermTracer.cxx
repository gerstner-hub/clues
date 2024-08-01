// TCLAP
#include <tclap/CmdLine.h>

// C++
#include <cstdlib>
#include <iostream>

// cosmos
#include <cosmos/cosmos.hxx>
#include <cosmos/proc/SubProc.hxx>
#include <cosmos/error/CosmosError.hxx>

// clues
#include <clues/TracedProc.hxx>
#include <clues/SystemCall.hxx>
#include <clues/SystemCallValue.hxx>

namespace clues {

class TermTracer :
		public TraceEventConsumer {
public: // functions

	TermTracer();

	~TermTracer();

	cosmos::ExitStatus run(const int argc, const char **argv);

protected: // functions

	void processPars();


protected: // event consumer interface

	void syscallEntry(const SystemCall &sc) override;

	void syscallExit(const SystemCall &sc) override;

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

	TracedSeizedProc m_seized_proc;
	TracedSubProc m_sub_proc;
	/// Generic handling of either TracedSeizedProc or TracedSubProc.
	TracedProc *m_proc = nullptr;
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
			"number of bytes"},
		m_seized_proc{*this},
		m_sub_proc{*this} {
}

TermTracer::~TermTracer() {
	m_proc = nullptr;
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

void TermTracer::syscallEntry(const SystemCall &) {
}

void TermTracer::syscallExit(const SystemCall &sc) {
	std::cerr << sc.name() << "(";
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

cosmos::ExitStatus TermTracer::run(const int argc, const char **argv) {
	m_cmdline.add(m_attach_proc);
	m_cmdline.add(m_start_proc);
	m_cmdline.parse(argc, argv);

	processPars();

	if (m_attach_proc.isSet()) {
		m_seized_proc.configure( cosmos::ProcessID{m_attach_proc.getValue()} );
		m_proc = &m_seized_proc;
	} else if (m_start_proc.isSet()) {
		// extract any additional arguments into a StringVector
		cosmos::StringVector sv;
		bool found_sep = false;

		for (auto arg = 1; arg < argc; arg++) {
			if (found_sep) {
				sv.push_back( argv[arg] );
			} else if (std::string(argv[arg]) == "--") {
				found_sep = true;
				continue;
			}
		}

		m_sub_proc.configure(sv);
		m_proc = &m_sub_proc;
	} else {
		std::cerr << "Neither -p nor -c was given. Nothing to do.\n";
		return cosmos::ExitStatus::FAILURE;
	}

	m_proc->attach();
	m_proc->trace();

	m_proc->detach();

	return m_attach_proc.isSet() ? cosmos::ExitStatus::SUCCESS : m_sub_proc.exitCode();
}

} // end ns

int main(const int argc, const char **argv) {
	try {
		cosmos::Init init;
		return cosmos::to_integral(clues::TermTracer().run(argc, argv));
	} catch (const cosmos::CosmosError &ce) {
		std::cerr
			<< "Exception catched:\n\n"
			<< ce.what() << std::endl;

		return EXIT_FAILURE;
	}
}
