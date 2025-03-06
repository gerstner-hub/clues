// C++
#include <cstring>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/errno.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/io/iovector.hxx>

// clues
#include <clues/clues.hxx>
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

void Tracee::handleSystemCall() {
	if (!m_flags[Flag::SYSCALL_ENTERED]) {
		changeState(State::SYSCALL_ENTER_STOP);
		updateRegisters();
		m_current_syscall = &m_syscall_db.get(m_reg_set.syscall());
		m_current_syscall->setEntryRegs(*this, m_reg_set);
		m_consumer.syscallEntry(*m_current_syscall);
	} else {
		changeState(State::SYSCALL_EXIT_STOP);
		updateRegisters();
		m_current_syscall->setExitRegs(*this, m_reg_set);
		m_current_syscall->updateOpenFiles(m_fd_path_map);
		m_consumer.syscallExit(*m_current_syscall);
	}
}

void Tracee::handleSignal(const cosmos::ChildData &data) {
	LOG_INFO("Signal: " << *data.signal);

	cosmos::SigInfo info;
	m_ptrace.getSigInfo(info);
	m_consumer.signaled(info);
}

void Tracee::handleEvent(const cosmos::ptrace::Event event) {
	LOG_INFO("PTRACE_EVENT_" << ptrace_event_str(event));

	using Event = cosmos::ptrace::Event;

	if (event == Event::STOP) {
		if (m_flags[Flag::WAIT_FOR_ATTACH_STOP]) {
			// this is the initial ptrace-stop. now we can start tracing
			LOG_INFO("initial ptrace-stop");
			handleAttached();
		} else {
			// must be a group stop, unless we're tracing
			// automatically-attached children, which is not yet
			// implemented
			changeState(State::GROUP_STOP);
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
			} else {
				if (*data.signal > cosmos::signal::MAXIMUM) {
					auto event = cosmos::ptrace::Event{cosmos::to_integral(data.signal->raw()) >> 8};
					changeState(State::EVENT_STOP);
					handleEvent(event);
				} else {
					changeState(State::SIGNAL_DELIVERY_STOP);
					handleSignal(data);
					m_inject_sig = *data.signal;
				}
			}
		} else if (data.signaled()) {
			changeState(State::SIGNAL_DELIVERY_STOP);
			handleSignal(data);
			m_inject_sig = *data.signal;
		} else {
			LOG_WARN("Other Tracee event?");
		}

		restart(m_restart_mode, m_inject_sig);

		if (m_restart_mode != cosmos::Tracee::RestartMode::LISTEN) {
			changeState(State::RUNNING);
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
