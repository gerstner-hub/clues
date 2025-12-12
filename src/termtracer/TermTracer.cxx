// C
#include <fnmatch.h>

// C++
#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>
#include <string_view>
#include <vector>

// cosmos
#include <cosmos/cosmos.hxx>
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/CosmosError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/proc/signal.hxx>
#include <cosmos/string.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/ChildTracee.hxx>
#include <clues/ForeignTracee.hxx>
#include <clues/SystemCallItem.hxx>
#include <clues/format.hxx>
#include <clues/logger.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/utils.hxx>

// termtracer
#include "TermTracer.hxx"

namespace clues {

namespace {

std::string_view to_label(const cosmos::ptrace::Event event) {
	using Event = cosmos::ptrace::Event;
	switch (event) {
		case Event::VFORK: return "vfork()";
		case Event::FORK: return "fork()";
		case Event::CLONE: return "clone()";
		default: return "???";
	}
}

bool ask_yes_no() {
	std::string yes_no;
	while (true) {
		std::cout << "(y/n) > ";
		std::cin >> yes_no;
		if (!std::cin.good() || yes_no == "n")
			return false;
		else if (yes_no == "y")
			return true;
	}
}

} // anon ns

TermTracer::TermTracer() :
		m_engine{*this} {
}

bool TermTracer::processPars() {

	auto handle_bad_arg = [](auto &arg) {
		std::cerr << "bad argument to --" << arg.getName() << ": '" << arg.getValue() << "'\n";
		return false;
	};

	if (m_args.list_syscalls.isSet()) {
		printSyscalls();
		throw cosmos::ExitStatus::SUCCESS;
	}

	if (const auto max_len = m_args.max_value_len.getValue(); max_len == 0)
		m_print_pars = false;
	else if (max_len < 0)
		m_par_truncation_len = SIZE_MAX;
	else
		m_par_truncation_len = static_cast<size_t>(max_len);

	if (m_args.follow_execve.isSet()) {
		const auto &follow = m_args.follow_execve.getValue();
		constexpr std::string_view PATH_PREFIX{"path:"};
		constexpr std::string_view GLOB_PREFIX{"glob:"};

		if (follow == "yes") {
			m_follow_exec = FollowExecContext::YES;
		} else if (follow == "no") {
			m_follow_exec = FollowExecContext::NO;
		} else if (follow == "ask") {
			m_follow_exec = FollowExecContext::ASK;
		} else if (cosmos::is_prefix(follow, PATH_PREFIX)) {
			m_follow_exec = FollowExecContext::CHECK_PATH;
			m_exec_context_arg = follow.substr(PATH_PREFIX.size());
		} else if (cosmos::is_prefix(follow, GLOB_PREFIX)) {
			m_follow_exec = FollowExecContext::CHECK_GLOB;
			m_exec_context_arg = follow.substr(GLOB_PREFIX.size());
		} else {
			return handle_bad_arg(m_args.follow_execve);
		}
	}

	if (m_args.follow_children.isSet() && m_args.follow_children_switch.isSet()) {
		std::cerr << "cannot set both '-f' and '--follow-children'\n";
		return false;
	} else if (m_args.follow_children_switch.isSet()) {
		m_follow_children = FollowChildMode::YES;
	} else if (m_args.follow_children.isSet()) {
		const auto &follow = m_args.follow_children.getValue();

		if (follow == "yes") {
			m_follow_children = FollowChildMode::YES;
		} else if (follow == "no") {
			m_follow_children = FollowChildMode::NO;
		} else if (follow == "ask") {
			m_follow_children = FollowChildMode::ASK;
		} else if (follow == "threads") {
			m_follow_children = FollowChildMode::THREADS;
		} else {
			return handle_bad_arg(m_args.follow_children);
		}
	}

	if (m_args.follow_threads.isSet()) {
		if (m_follow_children != FollowChildMode::NO) {
			std::cerr << "cannot combine '--threads' with '-f' or '--follow-children'\n";
			return false;
		}

		m_follow_children = FollowChildMode::THREADS;
	}

	if (m_args.syscall_filter.isSet()) {
		auto parts = cosmos::split(m_args.syscall_filter.getValue(), ",");

		auto translate_name = [](const std::string_view name) {
			if (auto nr = lookup_system_call(name); nr) {
				return *nr;
			}

			std::cerr << "invalid system call name: "
				<< name << "\n";
			throw cosmos::ExitStatus::FAILURE;
		};

		std::vector<SystemCallNr> to_add;
		std::vector<SystemCallNr> to_remove;

		for (auto &part: parts) {
			if (part.starts_with("!")) {
				part = part.substr(1);
				to_remove.push_back(translate_name(part));
			} else {
				to_add.push_back(translate_name(part));
			}
		}

		for (const auto nr: to_add) {
			m_syscall_filter.insert(nr);
		}

		// NOTE: this removal logic can make sense in the future when
		// we support system call groups (→ add a group, remove a few
		// again)
		for (const auto nr: to_remove) {
			m_syscall_filter.erase(nr);
		}
	}

	return true;
}

void TermTracer::printSyscalls() {
	// start at index one to skip the "UKNOWN" system call
	for (size_t nr = 1; nr < SYSTEM_CALL_NAMES.size(); nr++) {
		auto NAME = SYSTEM_CALL_NAMES[nr];
		if (!NAME[0])
			continue;
		std::cout << NAME << "\n";
	}
}

void TermTracer::configureLogger() {
	// enable errors and warnings by default
	m_logger.setChannels(true, true, false, false);
	m_logger.configFromEnvVar("CLUES_LOGGING");
	clues::set_logger(m_logger);
}

void TermTracer::printParsOnEntry(std::ostream &trace, const SystemCall::ParameterVector &pars) const {
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

	const auto &last = pars.back();

	for (const auto &par: pars) {
		if (!par->isIn()) {
			// non-input parameter encountered, stop output
			break;
		}

		printPar(trace, *par);

		if (const auto is_last = &par == &last; !is_last) {
			trace << ", ";
		}
	}
}

void TermTracer::printParsOnExit(std::ostream &trace, const SystemCall::ParameterVector &pars) const {
	if (pars.empty())
		return;

	const auto &last = pars.back();
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

		printPar(trace, *par);

		if (const auto is_last = &par == &last; !is_last) {
			trace << ", ";
		}
	}
}

std::string TermTracer::formatTraceeInvocation(const Tracee &tracee) {
	return formatTraceeInvocation(tracee.executable(), tracee.cmdLine());
}

std::string TermTracer::formatTraceeInvocation(const std::string &exe,
		const cosmos::StringVector &cmdline) const {
	std::stringstream ss;
	ss << exe << " [";
	bool first = true;
	for (const auto &arg: cmdline) {
		if (first) {
			first = false;
		} else {
			ss << ", ";
		}
		ss << "\"" << arg << "\"";
	}

	ss << "]";

	return ss.str();
}

void TermTracer::printPar(std::ostream &trace, const SystemCallItem &par) const {
	trace << (m_args.verbose.isSet() ? par.longName() : par.shortName());

	if (m_print_pars) {
		auto value = par.str();

		if (value.size() > m_par_truncation_len) {
			value.resize(m_par_truncation_len);
			value += "...";
		}

		trace << "=" << value;
	}
}

void TermTracer::syscallEntry(Tracee &tracee,
		const SystemCall &sc,
		const StatusFlags flags) {

	// this needs to be assigned before returning from this function but
	// after traceStream() is called, if at all.
	auto defer_assign_syscall = cosmos::defer([this, &tracee, &sc]() {
		m_active_syscall = std::make_optional(
				std::make_tuple(tracee.pid(), &sc));
	});

	if (!isEnabled(&sc)) {
		return;
	}

	const auto syscall_info = *tracee.currentSystemCallInfo();
	checkABI(tracee, syscall_info);
	/* libclues also offers an ABI_CHANGED flag in `cflags`, but this
	 * doesn't suffice for us, since we might filter system calls, which
	 * means we don't necessarily need to report every ABI change.
	 */
	m_last_abi = syscall_info.abi();

	auto &trace = traceStream(tracee);

	if (flags[StatusFlag::RESUMED]) {
		trace << "<resuming previously interrupted " << sc.name() << "...>\n";
	}
	trace << sc.name() << "(";

	printParsOnEntry(trace, sc.parameters());

	trace << std::flush;
}

void TermTracer::syscallExit(Tracee &tracee, const SystemCall &sc,
		const StatusFlags flags) {

	/// This needs to be reset before returning from this function but
	/// after `checkResumedSyscall()` is called, if at all.
	auto defer_reset_syscall = cosmos::defer([this]() {
		m_active_syscall.reset();
	});

	if (isExecSyscall(sc) && sc.result()) {
		// this was already dealt with in newExecutionContext()
		return;
	} else if (!isEnabled(&sc)) {
		return;
	}

	checkResumedSyscall(tracee);

	auto &trace = traceStream(tracee, false);
	printParsOnExit(trace, sc.parameters());

	trace << ") = ";

	if (auto res = sc.result(); res) {
		trace << res->str() << " (" << (m_args.verbose.isSet() ? res->longName() : res->shortName()) << ")";
	} else {
		const auto err = *sc.error();
		trace << err.str() << " (errno)";
	}

	if (flags[StatusFlag::INTERRUPTED]) {
		trace << " (interrupted)";
	}

	trace << std::endl;
}

void TermTracer::signaled(Tracee &tracee, const cosmos::SigInfo &info) {
	traceStream(tracee) << "-- " << clues::format::sig_info(info) << " --\n";
}

void TermTracer::attached(Tracee &tracee) {
	if (m_num_tracees++ == 0) {
		// the initial process, don't print anything special in this case
		return;
	} else if (tracee.isInitiallyAttachedThread()) {
		// part of the initial attach procedure when attaching to a
		// possibly multi-threaded existing process.
		traceStream(tracee) << "→ additionally attached thread\n";
	} else if (auto it = m_new_tracees.find(tracee.pid()); it != m_new_tracees.end()) {
		auto [parent, event] = it->second;

		traceStream(tracee) << "→ automatically attached (created by PID " << parent << " via " << to_label(event) << "\n";
		m_new_tracees.erase(it);
	} else {
		traceStream(tracee) << "unknown Tracee " << cosmos::to_integral(tracee.pid()) << " attached?!";
	}
}

void TermTracer::exited(Tracee &tracee, const cosmos::WaitStatus status, const StatusFlags flags) {
	if (tracee.prevState() == Tracee::State::SYSCALL_ENTER_STOP) {
		abortSyscall(tracee);
	}

	if (flags[StatusFlag::LOST_TO_MT_EXIT]) {
		auto &trace = traceStream(tracee);
		trace << "--- <lost to exit or execve in another thread> ---\n";
	}

	if (status.exited()) {
		traceStream(tracee) << "+++ exited with " << cosmos::to_integral(*status.status()) << " +++\n";
		if (!seenInitialExec()) {
			traceStream(tracee) << "!!! failed to execute the specified program\n";
		}
	} else {
		traceStream(tracee) << "+++ killed by signal " << cosmos::to_integral(status.termSig()->raw()) << " +++\n";
	}

	if (tracee.pid() == m_main_tracee_pid) {
		m_main_status = status;
	}

	cleanupTracee(tracee);
}

void TermTracer::stopped(Tracee &tracee) {
	if (tracee.syscallCtr() == 0) {
		traceStream(tracee) << "--- currently in stopped state due to " << *tracee.stopSignal() << " ---\n";
	}
}

void TermTracer::disappeared(Tracee &tracee, const cosmos::ChildState &data) {
	abortSyscall(tracee);

	traceStream(tracee) << "!!! disappeared (e.g. exit() or execve() in another thread)\n";

	if (data.exited()) {
		traceStream(tracee) << "+++ exited with " << cosmos::to_integral(*data.status) << " +++\n";
	} else {
		traceStream(tracee) << "+++ killed by signal " << cosmos::to_integral(data.signal->raw()) << " +++\n";
	}

	if (tracee.pid() == m_main_tracee_pid) {
		/*
		 * Here we get a more complex cosmos::ChildState instead of
		 * WaitStatus as in the other callbacks. This is unfortunate,
		 * we can build a WaitStatus from ChildState, however.
		 *
		 * TODO: add a helper to libcosmos, pass homogenous types from
		 * libclues into EventConsumer to avoid this on the
		 * application's end.
		 */
		int raw_status = 0;
		if (data.exited()) {
			raw_status = cosmos::to_integral(*data.status) << 8;
		} else {
			raw_status = cosmos::to_integral(data.signal->raw());
		}
		m_main_status = cosmos::WaitStatus{raw_status};
	}

	cleanupTracee(tracee);
}

void TermTracer::newExecutionContext(Tracee &tracee,
		const std::string &old_exe,
		const cosmos::StringVector &old_cmdline,
		const std::optional<cosmos::ProcessID> old_pid) {
	if (old_pid) {
		// this needs to be done first to avoid any inconsistent state down below.
		updateTracee(tracee, *old_pid);
	}

	// cache this state here, because checkResumedSyscall() might alter the info
	const auto is_enabled = isEnabled(currentSyscall(tracee));
	checkResumedSyscall(tracee);

	if (is_enabled) {
		/* anticipate the success system call status to avoid
		 * complexities while outputting status messages and
		 * interactive dialogs. */
		traceStream(tracee, false) << ") = 0 (success)\n";
	}

	m_active_syscall = {};

	if (old_pid) {
		traceStream(tracee) << "--- PID " << *old_pid << " is now known as PID " << tracee.pid() << " ---\n";
	}

	// skip the output for the initial exec of a new child process,
	// because there's no interesting information in that
	if (seenInitialExec()) {
		traceStream(tracee) << "--- no longer running " << formatTraceeInvocation(old_exe, old_cmdline) << " ---\n";
	}
	traceStream(tracee) << "--- now running " << formatTraceeInvocation(tracee) << " ---\n";

	if (!seenInitialExec()) {
		m_flags.set(Flag::SEEN_INITIAL_EXEC);
	} else {
		if (!followExecutionContext(tracee)) {
			traceStream(tracee) << "--- detaching after execve ---\n";
			tracee.detach();
		}
	}
}

void TermTracer::newChildProcess(Tracee &parent, Tracee &child, const cosmos::ptrace::Event event) {
	auto follow = m_follow_children;

	if (follow == FollowChildMode::ASK) {
		traceStream(parent) << "Follow into new child process created by PID " << parent.pid() << " via " << to_label(event) << "?\n";
		std::cout << "PID " << parent.pid() << " is " << formatTraceeInvocation(parent) << "\n";
		follow = ask_yes_no() ? FollowChildMode::YES : FollowChildMode::NO;
	} else if (follow == FollowChildMode::THREADS) {
		if (event == cosmos::ptrace::Event::CLONE) {
			// TODO: inspect the clone system call that caused this and
			// check whether the CLONE_THREAD flag was specified.
			// If it isn't set, then the clone() is likely not for
			// a regular thread but for something else and we
			// shouldn't follow it (?).
			follow = FollowChildMode::YES;
		} else {
			follow = FollowChildMode::NO;
		}
	}

	if (follow == FollowChildMode::YES) {
		// keep this information for later when something actually happens in the new child
		m_new_tracees.insert({child.pid(), {parent.pid(), event}});
	} else {
		child.detach();
	}
}

bool TermTracer::followExecutionContext(Tracee &tracee) {
	switch (m_follow_exec) {
		case FollowExecContext::YES: return true;
		case FollowExecContext::NO: return false;
		case FollowExecContext::ASK: {
			std::cout << "Follow into new execution context?\n";
			return ask_yes_no();
		} case FollowExecContext::CHECK_PATH: {
			return m_exec_context_arg == tracee.executable();
		} case FollowExecContext::CHECK_GLOB: {
			return ::fnmatch(m_exec_context_arg.c_str(), tracee.executable().c_str(), 0) == 0;
		}
		default:
			return false;
	}
}

std::ostream& TermTracer::traceStream(const Tracee &tracee, const bool new_line) {
	// TODO: this is currently fixed to cerr, but we should implement
	// trace to file, maybe also separate files for each PID, or even
	// separate PTYs in some form.
	auto &stream = std::cerr;

	if (new_line) {
		startNewLine(stream, tracee);
	}
	return std::cerr;
}

void TermTracer::startNewLine(std::ostream &trace, const Tracee &tracee) {
	// make sure to terminate a possibly pending system call line
	if (storeUnfinishedSyscallCtx()) {
		// a system call in another thread remains unfinished
		trace << " <...unfinished>\n";
	}

	if (m_num_tracees > 1) {
		trace << "[" << tracee.pid() << "] ";
	} else if (m_flags.steal(Flag::DROPPED_TO_LAST_TRACEE)) {
		trace << "--- only PID " << tracee.pid() << " is remaining ---\n";
	}
}

bool TermTracer::storeUnfinishedSyscallCtx() {
	if (!m_active_syscall) {
		return false;
	}

	auto [pid, syscall] = *m_active_syscall;
	const bool ret = isEnabled(syscall);

	m_unfinished_syscalls[pid] = syscall;
	m_active_syscall.reset();
	return ret;
}

bool TermTracer::isExecSyscall(const SystemCall &sc) const {
	switch (sc.callNr()) {
		default: return false;
		case SystemCallNr::EXECVE:
		case SystemCallNr::EXECVEAT:
			 return true;
	}
}

const SystemCall* TermTracer::currentSyscall(const Tracee &tracee) const {
	if (m_active_syscall) {
		auto &[pid, syscall] = *m_active_syscall;

		if (pid == tracee.pid()) {
			return syscall;
		}
	}

	auto it = m_unfinished_syscalls.find(tracee.pid());
	if (it != m_unfinished_syscalls.end()) {
		return it->second;
	}

	return nullptr;
}

bool TermTracer::isEnabled(const SystemCall *sc) const {
	if (!sc)
		return false;
	else if (m_syscall_filter.empty())
		return true;

	return m_syscall_filter.count(sc->callNr()) != 0;
}

void TermTracer::checkResumedSyscall(const Tracee &tracee) {
	if (hasActiveSyscall(tracee))
		return;

	auto node = m_unfinished_syscalls.extract(tracee.pid());
	auto sc = node.mapped();

	if (!isEnabled(sc))
		// we cleaned up the data, nothing else to do
		return;

	auto &trace = traceStream(tracee);
	trace << "<resuming ...> " << sc->name();
	if (sc->hasOutParameter()) {
		trace << "(..., ";
	} else {
		trace << "(...";
	}
}

void TermTracer::cleanupTracee(const Tracee &tracee) {
	/* remove the given tracee from all bookkeeping */
	if (hasActiveSyscall(tracee)) {
		m_active_syscall.reset();
	} else {
		m_unfinished_syscalls.erase(tracee.pid());
	}

	m_new_tracees.erase(tracee.pid());

	if (--m_num_tracees == 1) {
		m_flags.set(Flag::DROPPED_TO_LAST_TRACEE);
	}
}

void TermTracer::updateTracee(const Tracee &tracee, const cosmos::ProcessID old_pid) {
	if (hasActiveSyscall(old_pid)) {
		m_active_syscall = std::make_tuple(tracee.pid(), activeSyscall());
	} else if (auto it = m_unfinished_syscalls.find(old_pid); it != m_unfinished_syscalls.end()) {
		m_unfinished_syscalls[tracee.pid()] = it->second;
		m_unfinished_syscalls.erase(it);
	}

	// if there should be an entry for the new PID already, then it's from
	// an already dead sibbling tracee. get rid of that.
	m_new_tracees.erase(tracee.pid());

	if (auto it = m_new_tracees.find(old_pid); it != m_new_tracees.end()) {
		m_new_tracees[tracee.pid()] = it->second;
		m_new_tracees.erase(it);
	}
}

void TermTracer::abortSyscall(const Tracee &tracee) {
	// obtain this information before the active syscall is reset below
	const auto is_enabled = isEnabled(currentSyscall(tracee));

	if (hasActiveSyscall(tracee)) {
		m_active_syscall.reset();
	} else if (is_enabled) {
		checkResumedSyscall(tracee);
	}

	if (is_enabled) {
		/*
		 * finish any possibly pending system call to make clear it
		 * never visibly returned.
		 */
		traceStream(tracee, false) << ") = ?\n";
	}
}

void TermTracer::checkABI(const Tracee &tracee, const SystemCallInfo &info) {
	bool report_abi = false;

	if (m_last_abi == clues::ABI::UNKNOWN) {
		// check if the initial system call already has some
		// non-default ABI.
		if (!clues::is_default_abi(info.abi()))
			report_abi = true;
	} else if (info.abi() != m_last_abi) {
		report_abi = true;
	}

	if (report_abi) {
		traceStream(tracee) << "[system call ABI changed to " << get_abi_label(info.abi()) << "]\n";
	}
}

bool TermTracer::configureTracee(const cosmos::ProcessID pid) {
	// this is only for newly created child processes, so set it right away
	m_flags.set(Flag::SEEN_INITIAL_EXEC);
	TraceePtr tracee;
	try {
		/* strace ties the attach threads behaviour to `-f`. There
		 * can be situations when this is not helpful. Thus we do the
		 * same but offer a `-1` switch to opt out of this and only
		 * attach to the single thread specified on the command line.
		 */
		tracee = m_engine.addTracee(pid,
				FollowChildren{m_follow_children == FollowChildMode::NO ? false : true},
				AttachThreads{m_follow_children == FollowChildMode::NO || m_args.no_initial_threads_attach.isSet() ? false : true});
	} catch (const cosmos::ApiError &e) {
		std::cerr << "Failed to attach to PID " << pid << ": " << e.msg() << "\n";
		if (e.errnum() == cosmos::Errno::PERMISSION) {
			std::cerr << "You need to be root to attach to processes not owned by you\n";
			std::cerr << "The YAMA kernel security extension can also prevent attaching your own processes.\n";
			std::cerr << "This also happens when another process is already tracing this process.\n";
		}
		return false;
	}

	traceStream(*tracee, false) << "--- tracing " << formatTraceeInvocation(*tracee) << " ---\n";

	m_main_tracee_pid = tracee->pid();

	return true;
}

cosmos::ExitStatus TermTracer::main(const int argc, const char **argv) {
	constexpr auto FAILURE = cosmos::ExitStatus::FAILURE;
	m_args.cmdline.parse(argc, argv);

	configureLogger();

	if (!processPars()) {
		return FAILURE;
	}

	cosmos::signal::block(cosmos::SigSet{cosmos::signal::CHILD});

	if (m_args.attach_proc.isSet()) {
		if (!configureTracee(cosmos::ProcessID{m_args.attach_proc.getValue()})) {
			return FAILURE;
		}
	} else {
		// extract any additional arguments into a StringVector
		cosmos::StringVector sv;
		bool found_sep = false;

		for (auto arg = 1; arg < argc; arg++) {
			if (found_sep) {
				sv.push_back(argv[arg]);
			} else if (std::string{argv[arg]} == "--") {
				found_sep = true;
			}
		}

		if (sv.empty()) {
			std::cerr << "Neither -p nor command to execute after '--' was given. Nothing to do.\n";
			return FAILURE;
		}

		try {
			auto tracee = m_engine.addTracee(sv,
					FollowChildren{m_follow_children == FollowChildMode::NO ? false : true});
			m_main_tracee_pid = tracee->pid();
		} catch (const cosmos::CosmosError &ex) {
			std::cerr << ex.shortWhat() << "\n";
			return FAILURE;
		}
	}

	try {
		m_engine.trace();
	} catch (const std::exception &ex) {
		std::cerr << "internal tracing error: " << ex.what() << std::endl;
		// try to do a hard exit to avoid blocking in the Engine's
		// destructor, should the state be messed up
		cosmos::proc::exit(FAILURE);
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
			// this is what the shell returns for children that have been killed.
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
