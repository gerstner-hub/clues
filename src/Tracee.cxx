// C++
#include <cstring>
#include <fstream>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/fs/DirStream.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/io/ILogger.hxx>

// clues
#include <clues/Engine.hxx>
#include <clues/EventConsumer.hxx>
#include <clues/logger.hxx>
#include <clues/RegisterSet.hxx>
#include <clues/SystemCall.hxx>
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>

#define LOG_DEBUG_PID(X) LOG_DEBUG("[" << cosmos::to_integral(m_ptrace.pid()) << "] " << X)
#define LOG_INFO_PID(X) LOG_INFO("[" << cosmos::to_integral(m_ptrace.pid()) << "] " << X)
#define LOG_WARN_PID(X) LOG_WARN("[" << cosmos::to_integral(m_ptrace.pid()) << "] " << X)
#define LOG_ERROR_PID(X) LOG_ERROR("[" << cosmos::to_integral(m_ptrace.pid()) << "] " << X)

namespace {

/// A filler that fills Tracee data into a container supporting push_back() until a terminating zero element is found.
/**
 * This only works for primitive data types that are smaller than `long` (the
 * basic I/O size for reading data from a Tracee).
 **/
template <typename CONTAINER>
class ContainerFiller {
	using ptr_type = typename CONTAINER::pointer;
public: // functions

	explicit ContainerFiller(CONTAINER &container) :
			m_container{container} {
	}

	bool operator()(long word) {
		static_assert(std::is_trivial_v<typename CONTAINER::value_type> == true);
		static_assert(sizeof(ITEM_SIZE) <= sizeof(long), "Unexpected ITEM_SIZE (must be <= sizeof(long))");
		ptr_type word_ptr = reinterpret_cast<ptr_type>(&word);
		typename CONTAINER::value_type item;

		for (size_t numitem = 0; numitem < sizeof(word) / ITEM_SIZE; numitem++) {
			std::memcpy(&item, word_ptr + numitem, sizeof(item));
			if (item == 0)
				// termination found
				return false;

			m_container.push_back(item);
		}

		return true;
	}

protected:
	CONTAINER &m_container;
	static constexpr size_t ITEM_SIZE = sizeof(typename CONTAINER::value_type);
};

/// Fills an opaque blog of data with Tracee data a given number of bytes has bee processed.
class BlobFiller {
public: // functions

	BlobFiller(const size_t bytes, char *buffer) :
			m_left{bytes},
			m_buffer{buffer} {
	}

	bool operator()(long word) {
		const size_t to_copy = std::min(sizeof(word), m_left);

		std::memcpy(m_buffer, &word, to_copy);

		m_buffer += to_copy;
		m_left -= to_copy;

		return m_left != 0;
	}

protected: // data

	size_t m_left;
	char *m_buffer;
};

} // end anon ns

namespace clues {

Tracee::Tracee(Engine &engine, EventConsumer &consumer, TraceePtr sibling) :
		m_engine{engine},
		m_consumer{consumer},
		m_process_data{sibling ?
			sibling->m_process_data :
			std::make_shared<ProcessData>()} {
}

Tracee::~Tracee() {
	if (m_state != State::DEAD && m_state != State::DETACHED) {
		LOG_WARN_PID("destroying Tracee in live state");
	}
}

const char* Tracee::getStateLabel(const State state) {
	switch (state) {
		case State::UNKNOWN:              return "UNKNOWN";
		case State::RUNNING:              return "RUNNING";
		case State::SYSCALL_ENTER_STOP:   return "SYSCALL_ENTER_STOP";
		case State::SYSCALL_EXIT_STOP:    return "SYSCALL_EXIT_STOP";
		case State::SIGNAL_DELIVERY_STOP: return "SIGNAL_DELIVERY_STOP";
		case State::GROUP_STOP:           return "GROUP_STOP";
		case State::EVENT_STOP:           return "EVENT_STOP";
		case State::DEAD:                 return "DEAD";
		case State::DETACHED:             return "DETACHED";
		default:                          return "???";
	}
}

void Tracee::setPID(const cosmos::ProcessID tracee) {
	m_ptrace = cosmos::Tracee{tracee};
}

void Tracee::attach(const FollowChildren follow_children, const AttachThreads attach_threads) {
	using Opt = cosmos::ptrace::Opt;
	m_ptrace_opts = cosmos::ptrace::Opts{
		Opt::TRACESYSGOOD,
		Opt::TRACEEXIT,
		Opt::TRACEEXEC,
	};

	if (follow_children) {
		m_ptrace_opts.set({
			Opt::TRACECLONE,
			Opt::TRACEFORK,
			Opt::TRACEVFORK,
			Opt::TRACEVFORKDONE
		});
	}

	try {
		seize(m_ptrace_opts);
	} catch (...) {
		if (!isChildProcess()) {
			changeState(State::DEAD);
		}
		throw;
	}
	updateExecutable();
	updateCmdLine();
	interrupt();
	m_flags.set(Flag::WAIT_FOR_ATTACH_STOP);
	if (m_flags[Flag::INJECTED_SIGSTOP]) {
		// send SIGCONT via kill() instead of via a ptrace injected
		// signal. For some reason, when injecting the signal via
		// ptrace, the stopped state will be applied again after
		// performing a PTRACE_DETACH operation. This could even be a
		// kernel bug.
		cosmos::signal::send(m_ptrace.pid(), cosmos::signal::CONT);
		m_flags.set(Flag::INJECTED_SIGCONT);
	}

	if (attach_threads) {
		m_flags.set(Flag::ATTACH_THREADS_PENDING);
	}
}

void Tracee::detach() {
	if (!m_ptrace.valid()) {
		return;
	} else if (m_state == State::DEAD || m_state == State::DETACHED) {
		return;
	}

	try {
		if (m_state == State::RUNNING) {
			m_flags.set(Flag::DETACH_AT_NEXT_STOP);

			if (!m_flags[Flag::WAIT_FOR_ATTACH_STOP]) {
				// interrupt, if not still pending, for being able to detach
				interrupt();
			}
		} else {
			m_ptrace.detach();
			changeState(State::DETACHED);
		}
	} catch (const cosmos::ApiError &error) {
		if (error.errnum() == cosmos::Errno::SEARCH) {
			// some execve() scenarios end up without a proper
			// exit notification. ignore them.
			if (!m_flags[Flag::WAIT_FOR_EXITED] &&
					currentSystemCallNr() != SystemCallNr::EXECVE) {
				LOG_WARN_PID("tracee found to be already dead upon detach()/interrupt()");
			}
			// already gone for some reason
			changeState(State::DEAD);
		} else {
			// shouldn't really happen, unless we're not a
			// tracee for the process at all anyway
			m_ptrace = cosmos::Tracee{};
			throw;
		}
	}

	m_ptrace = cosmos::Tracee{};
	m_flags = {};
	m_initial_attacher.reset();
}

void Tracee::updateExecutable() {
	// obtain the executable name from proc.
	// as long as we're tracing the PID there is no race involved.
	// this information is more reliable than what we see in execve(),
	// since symlinks or other magic might be involved.
	const auto path = cosmos::sprintf("/proc/%d/exe", cosmos::to_integral(m_ptrace.pid()));
	try {
		m_process_data->executable = cosmos::fs::read_symlink(path);
	} catch (const cosmos::ApiError &e) {
		// likely ENOENT, tracee disappeared
		// but can this even happen while we're tracing it? and even
		// if it happens, then no more tracing will happen, so the
		// information is no longer relevant.
		//
		// As a fallback we could rely on the less precise information
		// from evecve-entry. The issue is that the execve-event-stop
		// happens before system-call-exit-stop and also that in
		// multi-threaded contexts, the actual execve system call data
		// might be in a wholly different tracee, or one that we're
		// not even tracing.
		//
		// so let's ignore this for the moment, assuming that this is
		// not a relevant situation anyway.
		m_process_data->executable.clear();
	}
}

void Tracee::updateCmdLine() {
	// the cmdline file contains null terminator separated strings
	// the tracee controls this data and could place crafted data here.
	//
	// obtain the data from here instead of from execve() has the
	// following advantages:
	// - it works the same for newly created tracee's as for tracee's
	// we're attaching to during runtime.
	// - we can obtain the information without having to find the correct
	// syscall-exit stop context that caused a ptrace-exec event stop.
	const auto path = cosmos::sprintf("/proc/%d/cmdline", cosmos::to_integral(m_ptrace.pid()));

	m_process_data->cmdline.clear();

	std::ifstream is{path};
	if (!is) {
		// see updateExecutable() for the rationale here
		return;
	}
	std::string arg;
	while (std::getline(is, arg, '\0').good()) {
		m_process_data->cmdline.push_back(arg);
	}
}

void Tracee::syncFDsAfterExec() {
	/*
	 * We could mimic what the kernel does by inspecting the file
	 * descriptor flags. To prevent any inconsistencies and because it
	 * shouldn't bee too expensive to do this for each execve(),
	 * synchronize the state with what is found in /proc/<pid>/fd.
	 */
	try {
		auto left_fds = clues::get_currently_open_fds(m_ptrace.pid());

		auto &fd_info_map = m_process_data->fd_info_map;

		for (auto it = fd_info_map.begin(); it != fd_info_map.end(); it++) {
			if (left_fds.count(it->first) == 0) {
				it = fd_info_map.erase(it);
			}
		}
	} catch (const cosmos::ApiError &ex) {
		/* It seems the process died.
		 * The Tracee will be cleaned up soon anyway, so let's keep
		 * the file descriptors we've seen last time to avoid further
		 * confusion.
		 */
		LOG_WARN_PID("unable to get currently open fds: " << ex.what());
	}
}

void Tracee::changeState(const State new_state) {
	LOG_DEBUG_PID("state " << m_state << " → " << new_state);

	if (new_state == State::SYSCALL_ENTER_STOP) {
		m_flags.set(Flag::SYSCALL_ENTERED);
	} else if (new_state == State::SYSCALL_EXIT_STOP) {
		m_flags.reset(Flag::SYSCALL_ENTERED);
	} else if (new_state == State::GROUP_STOP) {
		if (m_flags[Flag::INJECTED_SIGSTOP]) {
			// our own injected group stop
			// let the tracee continue and we're tracing syscalls now
			m_flags.reset(Flag::INJECTED_SIGSTOP);
			m_restart_mode = cosmos::Tracee::RestartMode::SYSCALL;
		} else {
			// enter listen state to avoid restarting a stopped
			// process as a side-effect.
			m_restart_mode = cosmos::Tracee::RestartMode::LISTEN;
		}
	} else if (new_state == State::DETACHED) {
		m_flags.reset(Flag::DETACH_AT_NEXT_STOP);
	} else if (new_state == State::DEAD) {
		if (isChildProcess()) {
			cleanupChild();
		}
	}

	if (m_state != State::RUNNING)
		m_prev_state = m_state;

	if (m_prev_state == State::GROUP_STOP && m_state != State::GROUP_STOP)
		m_stop_signal = std::nullopt;

	m_state = new_state;
}

void Tracee::handleStateMismatch() {
	LOG_ERROR_PID("encountered system call state mismatch: we believe "
		<< (m_flags[Flag::SYSCALL_ENTERED] ? "we already entered " : "we did not enter ")
		<< "a system call, but we got a "
		<< (m_syscall_info->isEntry() ? "SyscallInfo::ENTRY" : "SyscallInfo::EXIT")
		<< " event.");

	throw cosmos::RuntimeError{"system call state mismatch"};
}

void Tracee::handleSystemCall() {

	m_syscall_info = cosmos::ptrace::SyscallInfo{};
	auto &info = *m_syscall_info;

	// NOTE: this call can fail if the tracee was killed meanwhile
	m_ptrace.getSyscallInfo(info);

	if (m_flags[Flag::SYSCALL_ENTERED]) {
		if (!info.isExit()) {
			handleStateMismatch();
		}

		changeState(State::SYSCALL_EXIT_STOP);
		handleSystemCallExit();
	} else {
		if (!info.isEntry()) {
			handleStateMismatch();
		}

		changeState(State::SYSCALL_ENTER_STOP);
		handleSystemCallEntry();
	}

	m_syscall_info.reset();
}

void Tracee::handleSystemCallEntry() {
	EventConsumer::State state;
	auto &info = *m_syscall_info->entryInfo();

	const SystemCallNr nr{info.syscallNr()};
	m_current_syscall = &m_syscall_db.get(nr);

	if (nr == SystemCallNr::RESTART_SYSCALL) {
		if (m_interrupted_syscall) {
			m_current_syscall = m_interrupted_syscall;
			state.set(EventConsumer::Status::RESUMED);
		} else if (m_syscall_ctr != 0) {
			// explicit restart_syscall done by user space?
			LOG_WARN_PID("unknown system call is resumed");
		} else {
			// this happens when attaching to a non-child process
			// and a system call like clock_nanosleep is
			// interrupted as a result.
			// we cannot know which system call is being resumed,
			// since we have no history. restart_syscall() carries
			// no additional context information pointing us to
			// the kind of system call that is being resumed.
			//
			// it would be quite a feature, though, to know which
			// system call is being resumed, as it happens quite
			// often that a process is attached that behaves
			// unusually e.g. because it blocks.

			// m_initial_regset is obtained during the initial
			// ptrace-event-stop. It seems it contains the
			// currently running system call. This only works if
			// the system call was not interrupted before already,
			// though.

			const auto orig_syscall = m_initial_regset.syscall();
			if (orig_syscall != SystemCallNr::RESTART_SYSCALL && SystemCall::validNr(orig_syscall)) {
				m_current_syscall = &m_syscall_db.get(orig_syscall);
				state.set(EventConsumer::Status::RESUMED);
			}
		}
	}
	m_current_syscall->setEntryInfo(*this, info);
	m_syscall_ctr++;
	m_consumer.syscallEntry(*this, *m_current_syscall, state);
}

void Tracee::handleSystemCallExit() {
	EventConsumer::State state;
	auto &syscall = *m_current_syscall;

	syscall.setExitInfo(*this, *m_syscall_info->exitInfo());
	syscall.updateOpenFiles(m_process_data->fd_info_map);

	if (auto error = syscall.error(); error && error->hasKernelErrorCode()) {
		// system call was interrupted, remember it for later
		m_interrupted_syscall = m_current_syscall;
		state.set(EventConsumer::Status::INTERRUPTED);
	} else {
		m_interrupted_syscall = nullptr;
	}

	m_consumer.syscallExit(*this, syscall, state);
}

void Tracee::handleSignal(const cosmos::SigInfo &info) {
	LOG_INFO_PID("Signal: " << info.sigNr());

	if (m_flags[Flag::INJECTED_SIGCONT] && info.sigNr() == cosmos::signal::CONT) {
		// ignore injected SIGCONT
		m_flags.reset(Flag::INJECTED_SIGCONT);
		return;
	}

	m_consumer.signaled(*this, info);
}

void Tracee::handleEvent(const cosmos::ChildState &data,
		const cosmos::ptrace::Event event,
		const cosmos::Signal signal) {
	LOG_INFO_PID("PTRACE_EVENT_" << get_ptrace_event_str(event) << " (" << signal << ")");

	using Event = cosmos::ptrace::Event;

	switch(event) {
	case Event::STOP: return handleStopEvent(signal);
	case Event::EXIT: return handleExitEvent();
	case Event::EXEC: return handleExecEvent(data.child.pid);
	case Event::CLONE:
	case Event::VFORK:
	case Event::VFORK_DONE:
	case Event::FORK:
			  return handleNewChildEvent(event);
	default: LOG_WARN_PID("PTRACE_EVENT unhandled");
	}
}

void Tracee::handleStopEvent(const cosmos::Signal signal) {
	if (m_flags[Flag::WAIT_FOR_ATTACH_STOP]) {
		// this is the initial ptrace-stop. now we can start tracing
		LOG_INFO_PID("initial ptrace-stop");
		handleAttached();
	} else if (cosmos::in_container(signal, STOPPING_SIGNALS)) {
		// must be a group stop, unless we're tracing
		// automatically-attached children, which is not yet
		// implemented
		changeState(State::GROUP_STOP);
		m_stop_signal = signal;
		m_consumer.stopped(*this);
	} else if (signal == cosmos::signal::TRAP) {
		// SIGTRAP has quite a blurry meaning in the ptrace()
		// API. From practical experiments and the original
		// strace code I could deduce that for some reason
		// PTRACE_EVENT_STOP combined with SIGTRAP is observed
		// when a SIGCONT is received by a tracee that is
		// currently in group-stop.
		// We then need to restart using system call tracing
		// to see the actual SIGCONT being delivered.
		m_restart_mode = cosmos::Tracee::RestartMode::SYSCALL;
	}
}

void Tracee::handleExitEvent() {

	EventConsumer::State state;

	/*
	 * Detecting "lost to execve" is a bit of a heuristic:
	 *
	 * - regular exit happens due to exit_group(2). No SYSCALL_EXIT_STOP
	 *   will be reported for this.
	 * - exit due to signal. SIGNAL_DELIVERY_STOP should have been the
	 *   last state we saw.
	 * - anything else should be execve in multi-threaded process.
	 */

	const auto wait_status = m_ptrace.getExitEventMsg();

	if (wait_status.exited() &&
			(prevState() != State::SYSCALL_ENTER_STOP ||
			!cosmos::in_list(*currentSystemCallNr(),
				{SystemCallNr::EXIT_GROUP, SystemCallNr::EXIT}))) {
		// the exit status in this case is simply 0
		LOG_INFO_PID("execve() related exit detected");
		state.set(EventConsumer::Status::LOST_TO_EXECVE);

		if (isThreadGroupLeader()) {
			// this Tracee will be replaced with another thread
			// from the same process
			// TODO: do we actually need this flag for anything?
			m_flags.set(Flag::WAIT_FOR_EXECVE_REPLACEMENT);
			state.set(EventConsumer::Status::EXECVE_REPLACE_PENDING);
		}
	}

	m_consumer.exited(*this, wait_status, state);

	m_flags.set(Flag::WAIT_FOR_EXITED);
}

void Tracee::handleExecEvent(const cosmos::ProcessID main_pid) {
	const auto old_exe = m_process_data->executable;
	const auto old_cmdline = m_process_data->cmdline;

	// in a multi-threaded conext we can receive this event under a
	// different PID than we currently have. Thus use a dedicated ptrace
	// wrapper here until we maybe call setPID() below..
	cosmos::Tracee ptrace{main_pid};

	std::optional<cosmos::ProcessID> old_pid;

	// for a regular execve() this returns the same pid as we have, ignore that
	if (const auto former_pid = ptrace.getPIDEventMsg(); former_pid != main_pid) {
		old_pid = former_pid;
	}

	if (old_pid) {
		auto old_tracee = m_engine.handleSubstitution(*old_pid);
		/*
		 * we will receive this event already under the new PID i.e.
		 * if we trace the main thread (which doesn't exec) and the
		 * exec'ing thread as well then we will receive this in main
		 * thread context.
		 *
		 * The "old" main thread no longer exists and we need to sync
		 * state with the actually exec()'ing thread.
		 *
		 * This is good for us currently, because if we have a
		 * ChildTracee running then it will be the main thread and
		 * this thread will stay the main thread in the newly
		 * executing process no matter what. Otherwise we'd have to
		 * abandon the ChildTracee, which holds a SubProc that needs
		 * to be wait()'ed on.
		 */
		if (old_tracee) {
			syncState(*old_tracee);
		} else {
			/*
			 * If the old main thread was not traced at all then
			 * `old_tracee` is not available here and we are
			 * already the correct Tracee (Engine takes care of
			 * that).
			 * We have to actively change our own PID, though.
			 */
			setPID(ptrace.pid());
		}
	}

	// only update executable info here, since our PID might have changed
	// above
	updateExecInfo();

	/*
	 * Check which file descriptors have been closed due to execve.
	 */
	syncFDsAfterExec();

	m_consumer.newExecutionContext(*this, old_exe, old_cmdline, old_pid);
}

void Tracee::handleNewChildEvent(const cosmos::ptrace::Event event) {
	// the engine will perform callbacks at m_consumer, since it is
	// responsible for creating the new Tracee instance.
	m_engine.handleAutoAttach(*this, m_ptrace.getPIDEventMsg(), event);
}

void Tracee::handleAttached() {
	m_flags.reset(Flag::WAIT_FOR_ATTACH_STOP);

	if (!m_flags[Flag::INJECTED_SIGSTOP]) {
		m_restart_mode = cosmos::Tracee::RestartMode::SYSCALL;
	}

	getRegisters(m_initial_regset);

	if (m_process_data->fd_info_map.empty()) {
		auto &map = m_process_data->fd_info_map;
		/*
		 * this is a root tracee, either a direct child process or an
		 * initially attached foreign process
		 */
		try {
			for (auto &info: get_fd_infos(pid())) {
				map.insert({info.fd, std::move(info)});
			}
		} catch (const cosmos::CosmosError &error) {
			LOG_WARN_PID("failed to get initial FD infos: " << error.what());
		}
	}

	m_consumer.attached(*this);

	if (m_flags[Flag::ATTACH_THREADS_PENDING]) {
		try {
			attachThreads();
		} catch (const std::exception &e) {
			LOG_ERROR_PID("failed to attach to other threads: " << e.what());
		}
		m_flags.reset(Flag::ATTACH_THREADS_PENDING);
	}
}

void Tracee::attachThreads() {
	const auto path = cosmos::sprintf("/proc/%d/task",
			cosmos::to_integral(m_ptrace.pid()));

	/*
	 * TODO: there is a race condition involved here:
	 *
	 * We are stopping one of the threads but all the others are still
	 * running while we're looking into /proc. Two things can happen here:
	 *
	 * - threads we're trying to attach might already be lost by the time
	 *   we're trying to call ptrace() on them. This is not much of an
	 *   issue.
	 * - new threads might come into existence that we don't catch in
	 *   /proc, and we'll never trace them, giving an incomplete picture.
	 *
	 * It would be safer to send a SIGSTOP to the whole thread group
	 * before attaching, but this would make the attach procedure even
	 * more complicated than it already is.
	 *
	 * It seems `strace` does not take any precautions regarding this
	 * matter neither.
	 *
	 * We could look at /proc/<pid>/status, which has a thread count
	 * field. This is again racy, however. We could do this after the
	 * fact for verification, or iterate over /proc/<pid>/task until we're
	 * sure we've attached all threads.
	 */
	cosmos::DirStream task_dir{path};
	const FollowChildren follow_children{
		m_ptrace_opts[cosmos::ptrace::Opt::TRACEFORK]};

	for (const auto &entry: task_dir) {
		if (entry.isDotEntry() ||
				entry.type() != cosmos::DirEntry::Type::DIRECTORY)
			continue;

		auto pid = cosmos::ProcessID{static_cast<int>(std::strtol(entry.name(), nullptr, 10))};
		if (pid == m_ptrace.pid())
			// ourselves
			continue;

		try {
			auto tracee = m_engine.addTracee(
					pid, follow_children, AttachThreads{false}, this->pid());
			tracee->m_initial_attacher = m_ptrace.pid();
		} catch (const std::exception &ex) {
			LOG_WARN_PID("failed to attach to thread " << cosmos::to_integral(pid) << ": " << ex.what());
		}
	}
}

void Tracee::syncState(Tracee &other) {
	m_syscall_info = other.m_syscall_info;
	m_syscall_db = std::move(other.m_syscall_db);
	m_current_syscall = other.m_current_syscall;
	m_interrupted_syscall = other.m_interrupted_syscall;
	m_syscall_ctr = other.m_syscall_ctr;
	other.changeState(State::DEAD);
}

void Tracee::processEvent(const cosmos::ChildState &data) {
	m_inject_sig = {};

	if (data.exited() || data.killed() || data.dumped()) {
		changeState(State::DEAD);
		m_exit_data = data;
		return;
	} else if (data.trapped()) {
		if (m_flags[Flag::DETACH_AT_NEXT_STOP]) {
			detach();
			return;
		}

		if (data.signal == cosmos::signal::SYS_TRAP) {
			handleSystemCall();
		} else if (data.signal->isPtraceEventStop()) {
			changeState(State::EVENT_STOP);
			const auto [signr, event] = cosmos::ptrace::decode_event(*data.signal);
			handleEvent(data, event, cosmos::Signal{signr});
		} else {
			changeState(State::SIGNAL_DELIVERY_STOP);
			cosmos::SigInfo info;
			m_ptrace.getSigInfo(info);
			handleSignal(info);
			m_inject_sig = *data.signal;
		}
	} else if (data.signaled()) {
		// it seems this branch is never hit, signals are
		// always handled as a TRAP, never as regular events
		// when tracing.
		// TODO: but for direct child processes that we want to stop
		// tracing this could happen after detaching.
		LOG_WARN_PID("seeing non-trap signal delivery stop");
		changeState(State::SIGNAL_DELIVERY_STOP);
		cosmos::SigInfo info;
		m_ptrace.getSigInfo(info);
		handleSignal(info);
		m_inject_sig = *data.signal;
	} else {
		LOG_WARN_PID("Other Tracee event?");
	}

	if (m_state == State::DEAD || m_state == State::DETACHED)
		return;

	// NOTE: this can fail with ESRCH if the tracee got killed meanwhile
	restart(m_restart_mode, m_inject_sig);

	if (m_restart_mode != cosmos::Tracee::RestartMode::LISTEN) {
		const auto resumed = m_state == State::GROUP_STOP;
		changeState(State::RUNNING);
		if (resumed) {
			m_consumer.resumed(*this);
		}
	}
}

void Tracee::getRegisters(RegisterSet &rs) {
	cosmos::InputMemoryRegion iovec;
	rs.fillIov(iovec);

	m_ptrace.getRegisterSet(rs.registerType(), iovec);
	rs.iovFilled(iovec);
}

long Tracee::getData(const long *addr) const {
	return m_ptrace.peekData(addr);
}

/// Reads data from the Tracee and feeds it to `filler` until it's saturated.
template <typename FILLER>
void Tracee::fillData(const long *addr, FILLER &filler) const {
	long word;

	do {
		word = getData(addr);

		// get the next word
		addr++;
	} while (filler(word));
}

void Tracee::readString(const long *addr, std::string &out) const {
	return readVector(addr, out);
}

template <typename VECTOR>
void Tracee::readVector(const long *addr, VECTOR &out) const {
	out.clear();

	ContainerFiller<VECTOR> filler{out};
	fillData(addr, filler);
}

bool Tracee::isThreadGroupLeader() const {
	const auto path = cosmos::sprintf("/proc/%d/status",
			cosmos::to_integral(m_ptrace.pid()));
	std::ifstream is{path};

	if (!is) {
		// Tracee disappeared?!
		return false;
	}

	std::string line;

	while (std::getline(is, line).good()) {
		auto parts = cosmos::split(line, ":",
				cosmos::SplitFlags{cosmos::SplitFlag::STRIP_PARTS});
		if (parts[0] == "Tgid") {
			auto tgid = std::strtol(parts[1].c_str(), nullptr, 10);
			return cosmos::ProcessID{static_cast<int>(tgid)} == m_ptrace.pid();
		}
	}

	throw cosmos::RuntimeError{"failed to parse Tgid"};

	// nothing found?!
	return false;
}

std::optional<SystemCallNr> Tracee::currentSystemCallNr() const {
	if (!m_current_syscall)
		return {};

	return m_current_syscall->callNr();
}

void Tracee::readBlob(const long *addr, char *buffer, const size_t bytes) const {
	BlobFiller filler{bytes, buffer};
	fillData(addr, filler);
}

// explicit template instantiations
template void Tracee::readVector<std::vector<long*>>(const long*, std::vector<long*>&) const;

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::Tracee::State &state) {
	o << clues::Tracee::getStateLabel(state);
	return o;
}
