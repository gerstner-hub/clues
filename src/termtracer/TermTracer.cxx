// C++
#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>
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
#include <clues/format.hxx>
#include <clues/SystemCallItem.hxx>

// termtracer
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

void TermTracer::printTraceeInvocation(std::ostream &out,
		const std::string &exe,
		const cosmos::StringVector &cmdline) const {
	out << exe << " [";
	bool first = true;
	for (const auto &arg: cmdline) {
		if (first) {
			first = false;
		} else {
			out << ", ";
		}
		out << "\"" << arg << "\"";
	}

	out << "]";
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

	for (const auto &msg: m_delayed_messages) {
		std::cerr << msg;
	}

	m_delayed_messages.clear();
}

void TermTracer::signaled(const cosmos::SigInfo &info) {

	using SigInfo = cosmos::SigInfo;

	// TODO: this formatting logic should rather go into libclues

	auto add_process_ctx = [](const SigInfo::ProcessCtx ctx) {
		std::cerr << ", si_pid=" << cosmos::to_integral(ctx.pid);
		std::cerr << ", si_uid=" << cosmos::to_integral(ctx.uid);
	};

	auto add_custom_data = [](const SigInfo::CustomData data) {
		std::cerr << ", si_int=" << data.asInt();
		std::cerr << ", si_ptr=" << data.asPtr();
	};

	std::cerr << "-- " << info.sigNr() << " {";
	if (info.source() != SigInfo::Source::KERNEL || info.raw()->si_code == SI_KERNEL) {
		std::cerr << "si_code=" << format::si_code(info.source());
	} else {
		// we have to use the raw number instead
		std::cerr << "si_code=" << info.raw()->si_code;
	}

	if (auto user_data = info.userSigData(); user_data) {
		add_process_ctx(user_data->sender);
	} else if (auto queue_data = info.queueSigData(); queue_data) {
		add_process_ctx(queue_data->sender);
		add_custom_data(queue_data->data);
	} else if (auto msg_queue_data = info.msgQueueData(); msg_queue_data) {
		add_process_ctx(msg_queue_data->msg_sender);
		add_custom_data(msg_queue_data->data);
	} else if (auto timer_data = info.timerData(); timer_data) {
		std::cerr << ", si_timerid=" << cosmos::to_integral(timer_data->id);
		std::cerr << ", si_overrun=" << timer_data->overrun;
	} else if (auto sys_data = info.sysData(); sys_data) {
		std::cerr << ", reason=" << format::si_reason(sys_data->reason);
		std::cerr << ", si_addr=" << sys_data->call_addr;
		std::cerr << ", si_syscall=" << sys_data->call_nr
			<< "(" << SystemCall::name(SystemCallNr{static_cast<uint64_t>(sys_data->call_nr)})
			<< ")";
		std::cerr << ", si_arch=" << format::ptrace_arch(sys_data->arch);
		std::cerr << ", si_errno=" << sys_data->error;
	} else if (auto child_data = info.childData(); child_data) {
		// translated si_code
		std::cerr << " (" << format::child_event(child_data->event) << ")";
		add_process_ctx(child_data->child);
		std::cerr << ", si_status=" << info.raw()->si_status;
		if (child_data->signal) {
			std::cerr << " (" << *child_data->signal << ")";
		} else {
			std::cerr << " (exit code)";
		}
		if (child_data->user_time) {
			std::cerr << ", si_utime=" << cosmos::to_integral(*child_data->user_time);
		}
		if (child_data->system_time) {
			std::cerr << ", si_stime=" << cosmos::to_integral(*child_data->system_time);
		}
	} else if (auto poll_data = info.pollData(); poll_data) {
		// translated si_code
		std::cerr << " (" << format::si_reason(poll_data->reason) << ")";
		std::cerr << ", si_fd=" << cosmos::to_integral(poll_data->fd);
		std::cerr << ", si_band=" << format::poll_events(poll_data->events);
	} else if (auto ill_data = info.illData(); ill_data) {
		// TODO: In C++20 we can use a templated lambda to output the
		// common fault data for SIGILL, SIGFPE etc.
		// translated si_code
		std::cerr << " (" << format::si_reason(ill_data->reason) << ")";
		std::cerr << ", si_addr=" << ill_data->addr;
	} else if (auto fpe_data = info.fpeData(); fpe_data) {
		// translated si_code
		std::cerr << " (" << format::si_reason(fpe_data->reason) << ")";
		std::cerr << ", si_addr=" << fpe_data->addr;
	} else if (auto segv_data = info.segfaultData(); segv_data) {
		// translated si_code
		std::cerr << " (" << format::si_reason(segv_data->reason) << ")";
		std::cerr << ", si_addr=" << segv_data->addr;
		if (auto bound = segv_data->bound; bound) {
			std::cerr << ", si_lower=" << bound->lower;
			std::cerr << ", si_upper=" << bound->upper;
		}
		if (auto key = segv_data->key; key) {
			std::cerr << ", si_pkey=" << cosmos::to_integral(*key);
		}
	} else if (auto bus_data = info.busData(); bus_data) {
		// translated si_code
		std::cerr << " (" << format::si_reason(bus_data->reason) << ")";
		std::cerr << ", si_addr=" << bus_data->addr;
		if (auto lsb = bus_data->addr_lsb; lsb) {
			std::cerr << ", si_addr_lsb=" << *lsb;
		}
	}

	std::cerr << "} --\n";
}

void TermTracer::exited(const cosmos::WaitStatus status, const State state) {
	if (m_tracee->prevState() == Tracee::State::SYSCALL_ENTER_STOP) {
		// this should only ever happen after a syscallEntry() for
		// exit_group() occurred. Thus we finish that first.
		std::cerr << ") = ?\n";
	}

	if (state[Status::LOST_TO_EXECVE]) {
		std::cerr << "--- <execve in another thread> ---\n";
	}

	if (status.exited()) {
		std::cerr << "+++ exited with " << cosmos::to_integral(*status.status()) << " +++\n";
	} else {
		std::cerr << "+++ killed by signal " << cosmos::to_integral(status.termSig()->raw()) << " +++\n";
	}
}

void TermTracer::newExecutionContext(const std::string &old_exe, const cosmos::StringVector &old_cmdline, const std::optional<cosmos::ProcessID> former_pid) {
	std::stringstream ss;
	if (former_pid) {
		ss << "--- PID " << cosmos::to_integral(*former_pid) << " is now known as " << cosmos::to_integral(m_tracee->pid()) << " ---\n";
		m_delayed_messages.push_back(ss.str());
		ss.str("");
	}

	if (m_seen_initial_exec || m_attach_proc.isSet()) {
		ss << "--- no longer running " ;
		printTraceeInvocation(ss, old_exe, old_cmdline);
		ss << " ---\n";
		m_delayed_messages.push_back(ss.str());
		ss.str("");
	}
	ss << "--- now running ";
	printTraceeInvocation(ss, m_tracee->executable(), m_tracee->cmdLine());
	ss << " ---\n";

	// this callback will happen before system call exit of execve(), thus
	// don't print it out right away, but only after system call exit.
	m_delayed_messages.push_back(ss.str());
	m_seen_initial_exec = true;
}

bool TermTracer::configureTrace(const cosmos::ProcessID pid) {
	auto proc = std::make_unique<ForeignTracee>(*this);
	proc->configure(pid);
	try {
		proc->attach();
	} catch (const cosmos::ApiError &e) {
		std::cerr << "Failed to attach to PID " << pid << ": " << e.msg() << "\n";
		if (e.errnum() == cosmos::Errno::PERMISSION) {
			std::cerr << "You need to be root to attach to processes not owned by you\n";
			std::cerr << "The YAMA kernel security extension can prevent attaching your own processes.\n";
			std::cerr << "This also happens when another process is already tracing this process.\n";
		}
		return false;
	}

	m_tracee = std::move(proc);

	std::cerr << "--- tracing ";
	printTraceeInvocation(std::cerr, m_tracee->executable(), m_tracee->cmdLine());
	std::cerr << " ---\n";

	return true;
}

bool TermTracer::configureTrace(const cosmos::StringVector &cmdline) {
	auto proc = std::make_unique<ChildTracee>(*this);
	proc->create(cmdline);
	proc->attach();
	m_tracee = std::move(proc);
	return true;
}

cosmos::ExitStatus TermTracer::main(const int argc, const char **argv) {
	constexpr auto FAILURE = cosmos::ExitStatus::FAILURE;
	m_cmdline.add(m_attach_proc);
	m_cmdline.parse(argc, argv);

	configureLogger();

	processPars();

	cosmos::signal::block(cosmos::SigSet{cosmos::signal::CHILD});

	if (m_attach_proc.isSet()) {
		if (!configureTrace(cosmos::ProcessID{m_attach_proc.getValue()})) {
			return FAILURE;
		}
	} else {
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
			return FAILURE;
		}

		if (!configureTrace(sv)) {
			return FAILURE;
		}
	}

	try {
		m_tracee->trace();
	} catch (const std::exception &ex) {
		std::cerr << "internal tracing error: " << ex.what() << std::endl;
	}

	m_tracee->detach();

	auto status = cosmos::ExitStatus::SUCCESS;

	/*
	 * Evaluate exit code of the tracee, valid only after detach().
	 *
	 * We mimic the behaviour of the tracee by returning the same exit
	 * status.
	 */
	if (const auto exit_data = m_tracee->exitData(); exit_data) {
		if (exit_data->exited()) {
			status = *exit_data->status;
		} else if (exit_data->killed()) {
			// this is what the shell returns for childs that have been killed.
			// TODO: strace actually sends the same kill signal to iself
			// I don't know whether this is very useful. It can
			// cause core dumps of the tracer, thus we'd need to
			// change ulimit to prevent that.
			status = cosmos::ExitStatus{128 + cosmos::to_integral(exit_data->signal->raw())};
		}
	}

	m_tracee.reset();

	return status;
}

} // end ns

int main(const int argc, const char **argv) {
	return cosmos::main<clues::TermTracer>(argc, argv);
}
