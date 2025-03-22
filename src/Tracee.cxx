// C++
#include <cstring>

// cosmos
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/io/ILogger.hxx>

// clues
#include <clues/clues.hxx>
#include <clues/RegisterSet.hxx>
#include <clues/SystemCall.hxx>
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>

namespace {

/// A filler that fills Tracee data into a container supporting push_back() until a terminating zero element is found.
/**
 * This only works for primitive data types that are small than `long` (the
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
		static_assert(std::is_pod_v<typename CONTAINER::value_type> == true);
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

std::string_view ptrace_event_str(const cosmos::ptrace::Event event) {
	using Event = cosmos::ptrace::Event;
	switch (event) {
		case Event::VFORK: return "VFORK";
		case Event::FORK: return "FORK";
		case Event::CLONE: return "CLONE";
		case Event::VFORK_DONE: return "VFORK_DONE";
		case Event::EXEC: return "EXEC";
		case Event::EXIT: return "EXIT";
		case Event::STOP: return "STOP";
		case Event::SECCOMP: return "SECCOMP";
		default: return "??? unknown ???";
	}
}

} // end anon ns

namespace clues {

Tracee::Tracee(EventConsumer &consumer) :
		m_consumer{consumer} {
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
		default:                          return "???";
	}
}

void Tracee::setTracee(const cosmos::ProcessID tracee) {
	m_ptrace = cosmos::Tracee{tracee};
}

void Tracee::attach() {
	seize(cosmos::ptrace::Opts{cosmos::ptrace::Opt::TRACESYSGOOD});
	interrupt();
	m_flags.set(Flag::WAIT_FOR_ATTACH_STOP);
}

void Tracee::changeState(const State new_state) {
	LOG_DEBUG("state " << m_state << " → " << new_state);

	if (new_state == State::SYSCALL_ENTER_STOP) {
		m_flags.set(Flag::SYSCALL_ENTERED);
	} else if (new_state == State::SYSCALL_EXIT_STOP) {
		m_flags.reset(Flag::SYSCALL_ENTERED);
	} else if (new_state == State::GROUP_STOP) {
		if (m_flags[Flag::INJECTED_SIGSTOP]) {
			// our own injected group stop
			// let the tracee continue and we're tracing syscalls now
			m_flags.reset(Flag::INJECTED_SIGSTOP);
			m_inject_sig = cosmos::signal::CONT;
			m_restart_mode = cosmos::Tracee::RestartMode::SYSCALL;
		} else {
			// enter listen state to avoid restarting a stopped
			// process as a side-effect.
			m_restart_mode = cosmos::Tracee::RestartMode::LISTEN;
		}
	}

	m_state = new_state;
}

void Tracee::handleStateMismatch() {
	LOG_ERROR("encountered system call state mismatch: we believe "
		<< (m_flags[Flag::SYSCALL_ENTERED] ? "we already entered " : "we did not enter ")
		<< "a system call, but we got a "
		<< (m_syscall_info->isEntry() ? "SyscallInfo::ENTRY" : "SyscallInfo::EXIT")
		<< " event.");

	cosmos_throw (cosmos::RuntimeError("system call state mismatch"));
}

void Tracee::handleSystemCall() {

	m_syscall_info = cosmos::ptrace::SyscallInfo{};
	auto &info = *m_syscall_info;

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
		} else {
			// explicit restart_syscall done by user space?
			LOG_WARN("unknown system call is resumed");
		}
	}
	m_current_syscall->setEntryInfo(*this, info);
	m_consumer.syscallEntry(*m_current_syscall, state);
}

void Tracee::handleSystemCallExit() {
	EventConsumer::State state;
	auto &syscall = *m_current_syscall;

	syscall.setExitInfo(*this, *m_syscall_info->exitInfo());
	syscall.updateOpenFiles(m_fd_path_map);

	if (syscall.hasErrorCode() && syscall.error().kernelErrcode() != std::nullopt) {
		// system call was interrupted, remember it for later
		m_interrupted_syscall = m_current_syscall;
		state.set(EventConsumer::Status::INTERRUPTED);
	} else {
		m_interrupted_syscall = nullptr;
	}
	m_consumer.syscallExit(syscall, state);
}

void Tracee::handleSignal(const cosmos::SigInfo &info) {
	LOG_INFO("Signal: " << info.sigNr());

	m_consumer.signaled(info);
}

void Tracee::handleEvent(const cosmos::ptrace::Event event, const cosmos::Signal signal) {
	LOG_INFO("PTRACE_EVENT_" << ptrace_event_str(event) << " (" << signal << ")");

	using Event = cosmos::ptrace::Event;

	if (event == Event::STOP) {
		if (m_flags[Flag::WAIT_FOR_ATTACH_STOP]) {
			// this is the initial ptrace-stop. now we can start tracing
			LOG_INFO("initial ptrace-stop");
			handleAttached();
		} else if (cosmos::in_container(signal, STOPPING_SIGNALS)) {
			// must be a group stop, unless we're tracing
			// automatically-attached children, which is not yet
			// implemented
			changeState(State::GROUP_STOP);
			m_consumer.stopped();
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
}

void Tracee::handleAttached() {
	m_flags.reset(Flag::WAIT_FOR_ATTACH_STOP);

	if (!m_flags[Flag::INJECTED_SIGSTOP]) {
		m_restart_mode = cosmos::Tracee::RestartMode::SYSCALL;
	}
}

void Tracee::trace() {
	cosmos::ChildData data;

	while (true) {
		m_inject_sig = {};
		wait(data);

		if (data.exited() || data.killed()) {
			changeState(State::DEAD);
			this->gone(data);
			break;
		} else if (data.trapped()) {
			if (data.signal == cosmos::signal::SYS_TRAP) {
				handleSystemCall();
			} else if (*data.signal > cosmos::signal::MAXIMUM) {
				// a ptrace event stop
				const auto raw_sigval = cosmos::to_integral(data.signal->raw());
				const auto event = cosmos::ptrace::Event{raw_sigval >> 8};
				const cosmos::SignalNr signr{raw_sigval & 0xff};
				changeState(State::EVENT_STOP);
				handleEvent(event, cosmos::Signal{signr});
			} else {
				// a special signal delivery stop?
				// this is redundant code to below...
				changeState(State::SIGNAL_DELIVERY_STOP);
				cosmos::SigInfo info;
				m_ptrace.getSigInfo(info);
				handleSignal(info);
				m_inject_sig = *data.signal;
			}
		} else if (data.signaled()) {
			changeState(State::SIGNAL_DELIVERY_STOP);
			cosmos::SigInfo info;
			m_ptrace.getSigInfo(info);
			handleSignal(info);
			m_inject_sig = *data.signal;
		} else {
			LOG_WARN("Other Tracee event?");
		}

		restart(m_restart_mode, m_inject_sig);

		if (m_restart_mode != cosmos::Tracee::RestartMode::LISTEN) {
			const auto resumed = m_state == State::GROUP_STOP;
			changeState(State::RUNNING);
			if (resumed) {
				m_consumer.resumed();
			}
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
