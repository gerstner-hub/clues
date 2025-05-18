// C
#include <fnmatch.h>

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
#include <clues/ForeignTracee.hxx>
#include <clues/format.hxx>
#include <clues/logger.hxx>
#include <clues/SystemCallItem.hxx>

// termtracer
#include "TermTracer.hxx"

namespace clues {

TermTracer::TermTracer() :
		m_engine{*this} {
}

void TermTracer::processPars() {
	auto max_len = m_args.max_value_len.getValue();

	if (max_len == 0)
		m_print_values = false;
	else if (max_len < 0)
		m_value_truncation_len = SIZE_MAX;
	else
		m_value_truncation_len = static_cast<size_t>(max_len);

	if (m_args.follow_execve.isSet()) {
		const auto &arg = m_args.follow_execve.getValue();
		constexpr std::string_view PATH_PREFIX{"path:"};
		constexpr std::string_view GLOB_PREFIX{"glob:"};

		if (arg == "yes") {
			m_follow_exec = FollowExecContext::YES;
		} else if (arg == "no") {
			m_follow_exec = FollowExecContext::NO;
		} else if (arg == "ask") {
			m_follow_exec = FollowExecContext::ASK;
		} else if (cosmos::is_prefix(arg, PATH_PREFIX)) {
			m_follow_exec = FollowExecContext::CHECK_PATH;
			m_exec_context_arg = arg.substr(PATH_PREFIX.size());
		} else if (cosmos::is_prefix(arg, GLOB_PREFIX)) {
			m_follow_exec = FollowExecContext::CHECK_GLOB;
			m_exec_context_arg = arg.substr(GLOB_PREFIX.size());
		}
	}
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
	std::cerr << (m_args.verbose.isSet() ? par.longName() : par.shortName());

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

void TermTracer::syscallEntry(Tracee &tracee, const SystemCall &sc, const State state) {

	startNewOutputLine(tracee);

	m_active_syscall = std::make_optional(std::make_tuple(&tracee, &sc));

	if (state[Status::RESUMED]) {
		std::cerr << "<resuming previously interrupted " << sc.name() << "...>\n";
	}
	std::cerr << sc.name() << "(";

	printEntryPars(sc.parameters());

	std::cerr << std::flush;
}

void TermTracer::syscallExit(Tracee &tracee, const SystemCall &sc, const State state) {

	// TODO: other ways to execve exist like fexecve()
	if (sc.callNr() == SystemCallNr::EXECVE && sc.result()) {
		// this is already dealt with in newExecutionContext()
		return;
	}

	checkResumedSyscall(tracee);

	printExitPars(sc.parameters());

	std::cerr << ") = ";

	if (auto res = sc.result(); res) {
		std::cerr << res->str() << " (" << (m_args.verbose.isSet() ? res->longName() : res->shortName()) << ")";
	} else {
		const auto err = *sc.error();
		std::cerr << err.str() << " (errno)";
	}

	if (state[Status::INTERRUPTED]) {
		std::cerr << " (interrupted)";
	}

	std::cerr << std::endl;

	m_active_syscall.reset();
}

void TermTracer::signaled(Tracee &tracee, const cosmos::SigInfo &info) {
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

	startNewOutputLine(tracee);

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

void TermTracer::attached(Tracee &tracee) {
	if (m_num_tracees++ == 0) {
		// the initial process, don't print anything special in this case
		return;
	}

	auto it = m_new_tracees.find(&tracee);
	if (it == m_new_tracees.end()) {
		std::cerr << "unknown Tracee attached?!";
		return;
	}

	auto [parent, event] = it->second;

	startNewOutputLine(*(it->first));
	std::cerr << "→ automatically attached (created by PID " << cosmos::to_integral(parent) << " via ";
	using Event = cosmos::ptrace::Event;
	switch (event) {
		case Event::VFORK: std::cerr << "vfork()"; break;
		case Event::FORK: std::cerr << "fork()"; break;
		case Event::CLONE: std::cerr << "clone()"; break;
		default: std::cerr << "???"; break;
	}

	std::cerr << ")\n";

	m_new_tracees.erase(it);
}

void TermTracer::exited(Tracee &tracee, const cosmos::WaitStatus status, const State state) {
	if (tracee.prevState() == Tracee::State::SYSCALL_ENTER_STOP) {
		if (hasActiveSyscall(tracee)) {
			m_active_syscall.reset();
		} else {
			checkResumedSyscall(tracee);
		}
		// this should only ever happen after a syscallEntry() for
		// exit_group() occurred. Thus we finish that first.
		std::cerr << ") = ?\n";
	}

	if (state[Status::LOST_TO_EXECVE]) {
		startNewOutputLine(tracee);
		std::cerr << "--- <lost to execve in another thread";
		if (state[Status::EXECVE_REPLACE_PENDING]) {
			std::cerr << " [waiting to be replaced by exec'ing thread]";
		}
		std::cerr << "> ---\n";
	}

	if (status.exited()) {
		startNewOutputLine(tracee);
		std::cerr << "+++ exited with " << cosmos::to_integral(*status.status()) << " +++\n";
		if (!m_seen_initial_exec) {
			std::cerr << "!!! failed to execute the specified program\n";
		}
	} else {
		startNewOutputLine(tracee);
		std::cerr << "+++ killed by signal " << cosmos::to_integral(status.termSig()->raw()) << " +++\n";
	}

	if (&tracee == m_main_tracee) {
		m_main_status = status;
	}

	cleanupTracee(tracee);
}

void TermTracer::stopped(Tracee &tracee) {
	if (tracee.syscallCtr() == 0) {
		startNewOutputLine(tracee);
		std::cerr << "--- currently in stopped state due to " << *tracee.stopSignal() << " ---\n";
	}
}

void TermTracer::newExecutionContext(Tracee &tracee,
		const std::string &old_exe,
		const cosmos::StringVector &old_cmdline,
		const Tracee *former_tracee) {

	if (former_tracee) {
		// this needs to be done first to avoid any inconsistent state down below.
		updateTracee(tracee, former_tracee);
	}

	checkResumedSyscall(tracee);
	// anticipate the sucess system call status to avoid complexities
	// while outputting status messages and interactive dialogs.
	std::cerr << ") = 0 (success)\n";

	if (former_tracee) {
		startNewOutputLine(tracee);
		std::cerr << "--- PID " << cosmos::to_integral(former_tracee->pid()) << " is now known as " << cosmos::to_integral(tracee.pid()) << " ---\n";
	}

	if (m_seen_initial_exec) {
		startNewOutputLine(tracee);
		std::cerr << "--- no longer running " ;
		printTraceeInvocation(std::cerr, old_exe, old_cmdline);
		std::cerr << " ---\n";
	}
	startNewOutputLine(tracee);
	std::cerr << "--- now running ";
	printTraceeInvocation(std::cerr, tracee.executable(), tracee.cmdLine());
	std::cerr << " ---\n";

	if (!m_seen_initial_exec) {
		m_seen_initial_exec = true;
	} else {
		if (!followExecutionContext(tracee)) {
			std::cerr << "--- detaching after execve ---\n";
			tracee.detach();
		}
	}
}

void TermTracer::newChildProcess(Tracee &parent, Tracee &child, const cosmos::ptrace::Event event) {
	// keep this information for later when something actually happens in the new child
	m_new_tracees.insert({&child, {parent.pid(), event}});
}

bool TermTracer::followExecutionContext(Tracee &tracee) {

	switch (m_follow_exec) {
		case FollowExecContext::YES: return true;
		case FollowExecContext::NO: return false;
		case FollowExecContext::ASK: {
			std::cout << "Follow into new execution context?\n";
			std::string yes_no;
			while (true) {
				std::cout << "(y/n) > ";
				std::cin >> yes_no;
				if (!std::cin.good() || yes_no == "n")
					return false;
				else if (yes_no == "y")
					return true;
			}
		} case FollowExecContext::CHECK_PATH: {
			return m_exec_context_arg == tracee.executable();
		} case FollowExecContext::CHECK_GLOB: {
			return ::fnmatch(m_exec_context_arg.c_str(), tracee.executable().c_str(), 0) == 0;
		}
		default:
			return false;
	}
}

void TermTracer::startNewOutputLine(const Tracee &tracee) {
	if (m_active_syscall) {
		// a system call in another thread remains unfinished
		std::cerr << " <...unfinished>\n";
		storeUnfinishedSyscallCtx();
	}

	const auto pid = cosmos::to_integral(tracee.pid());

	if (m_num_tracees > 1) {
		std::cerr << "[" << pid << "] ";
	} else if (m_dropped_to_single_tracee) {
		std::cerr << "--- only PID " << pid << " is remaining ---\n";
		m_dropped_to_single_tracee = false;
	}
}

void TermTracer::storeUnfinishedSyscallCtx() {
	if (!m_active_syscall)
		return;

	auto [tracee, syscall] = *m_active_syscall;
	m_unfinished_syscalls[tracee] = syscall;
	m_active_syscall.reset();
}

void TermTracer::checkResumedSyscall(const Tracee &tracee) {
	if (hasActiveSyscall(tracee))
		return;

	startNewOutputLine(tracee);

	auto node = m_unfinished_syscalls.extract(&tracee);
	auto sc = node.mapped();

	std::cerr << "<resuming ...> " << sc->name();
	if (sc->hasOutParameter()) {
		std::cerr << "(..., ";
	} else {
		std::cerr << "(...";
	}
}

void TermTracer::cleanupTracee(const Tracee &tracee) {
	/* remove the given tracee from all bookkeeping */
	if (hasActiveSyscall(tracee)) {
		m_active_syscall.reset();
	} else {
		m_unfinished_syscalls.erase(&tracee);
	}

	if (m_main_tracee == &tracee) {
		/* re-assign this during newExecutionContext() when
		 * `former_pid` is set */
		m_main_tracee = nullptr;
	}

	m_new_tracees.erase(&tracee);

	if (--m_num_tracees == 1) {
		m_dropped_to_single_tracee = true;
	}
}

void TermTracer::updateTracee(const Tracee &tracee, const Tracee *former_tracee) {
	if (m_main_tracee == former_tracee) {
		m_main_tracee = &tracee;
	}

	if (hasActiveSyscall(*former_tracee)) {
		m_active_syscall = std::make_tuple(&tracee, std::get<const SystemCall*>(*m_active_syscall));
	}

	if (auto it = m_unfinished_syscalls.find(former_tracee); it != m_unfinished_syscalls.end()) {
		m_unfinished_syscalls[&tracee] = it->second;
		m_unfinished_syscalls.erase(it);
	}

	m_new_tracees.erase(&tracee);

	if (auto it = m_new_tracees.find(former_tracee); it != m_new_tracees.end()) {
		m_new_tracees[&tracee] = it->second;
		m_new_tracees.erase(it);
	}
}

bool TermTracer::configureTrace(const cosmos::ProcessID pid) {
	// this is only for newly created child processes
	m_seen_initial_exec = true;
	try {
		// TODO: make FollowChilds configurable
		m_main_tracee = &m_engine.addTracee(pid, FollowChilds{true});
	} catch (const cosmos::ApiError &e) {
		std::cerr << "Failed to attach to PID " << pid << ": " << e.msg() << "\n";
		if (e.errnum() == cosmos::Errno::PERMISSION) {
			std::cerr << "You need to be root to attach to processes not owned by you\n";
			std::cerr << "The YAMA kernel security extension can prevent attaching your own processes.\n";
			std::cerr << "This also happens when another process is already tracing this process.\n";
		}
		return false;
	}

	std::cerr << "--- tracing ";
	printTraceeInvocation(std::cerr, m_main_tracee->executable(), m_main_tracee->cmdLine());
	std::cerr << " ---\n";

	return true;
}

cosmos::ExitStatus TermTracer::main(const int argc, const char **argv) {
	constexpr auto FAILURE = cosmos::ExitStatus::FAILURE;
	m_args.cmdline.parse(argc, argv);

	configureLogger();

	processPars();

	cosmos::signal::block(cosmos::SigSet{cosmos::signal::CHILD});

	if (m_args.attach_proc.isSet()) {
		if (!configureTrace(cosmos::ProcessID{m_args.attach_proc.getValue()})) {
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

		// TODO: make FollowChilds configurable
		m_main_tracee = &m_engine.addTracee(sv, FollowChilds{true});
	}

	try {
		m_engine.trace();
	} catch (const std::exception &ex) {
		std::cerr << "internal tracing error: " << ex.what() << std::endl;
	}

	auto status = cosmos::ExitStatus::SUCCESS;

	/*
	 * Evaluate exit code of the tracee, valid only after detach().
	 *
	 * We mimic the behaviour of the tracee by returning the same exit
	 * status.
	 */
	if (m_main_status) {
		if (m_main_status->exited()) {
			status = *m_main_status->status();
		} else if (m_main_status->signaled()) {
			// this is what the shell returns for childs that have been killed.
			// TODO: strace actually sends the same kill signal to iself
			// I don't know whether this is very useful. It can
			// cause core dumps of the tracer, thus we'd need to
			// change ulimit to prevent that.
			status = cosmos::ExitStatus{128 + cosmos::to_integral(m_main_status->termSig()->raw())};
		}
	}

	return status;
}

} // end ns

int main(const int argc, const char **argv) {
	return cosmos::main<clues::TermTracer>(argc, argv);
}
