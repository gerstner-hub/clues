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

} // end anon ns

namespace clues {

Tracee::Tracee(EventConsumer &consumer) :
		m_consumer{consumer} {
}

void Tracee::setTracee(const cosmos::ProcessID tracee) {
	m_ptrace = cosmos::Tracee{tracee};
}

void Tracee::attach() {
	seize(cosmos::ptrace::Opts{cosmos::ptrace::Opt::TRACESYSGOOD});
	interrupt();
}

void Tracee::changeState(const TraceState new_state) {
	if (logger) {
		logger->debug() << "state " << m_state << " → " << new_state << "\n";
	}

	if (new_state == TraceState::SYSCALL_ENTER_STOP) {
		m_syscall_entered = true;
	} else if (new_state == TraceState::SYSCALL_EXIT_STOP) {
		m_syscall_entered = false;
	}

	m_state = new_state;
}

void Tracee::handleSystemCall() {
	if (!m_syscall_entered) {
		changeState(TraceState::SYSCALL_ENTER_STOP);
		updateRegisters();
		m_current_syscall = &m_syscall_db.get(m_reg_set.syscall());
		m_current_syscall->setEntryRegs(*this, m_reg_set);
		m_consumer.syscallEntry(*m_current_syscall);
	} else {
		changeState(TraceState::SYSCALL_EXIT_STOP);
		updateRegisters();
		m_current_syscall->setExitRegs(*this, m_reg_set);
		m_current_syscall->updateOpenFiles(m_fd_path_map);
		m_consumer.syscallExit(*m_current_syscall);
	}
}

void Tracee::handleSignal(const cosmos::ChildData &data) {
	const auto signal = data.signal;

	if (logger) {
		logger->info() << "Got signal: " << *signal << std::endl;
	}
}


static std::string_view ptrace_event_str(const cosmos::ptrace::Event event) {
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

void Tracee::trace() {
	cosmos::ChildData data;
	std::optional<cosmos::Signal> inject_sig;

	while (true) {
		wait(data);

		if (data.exited() || data.killed()) {
			changeState(TraceState::DEAD);
			this->exited(data);
			break;
		} else if (data.trapped()) {
			if (data.signal == cosmos::signal::SYS_TRAP) {
				handleSystemCall();
			} else {
				if (*data.signal > cosmos::signal::MAXIMUM) {
					changeState(TraceState::EVENT_STOP);
					auto event = cosmos::ptrace::Event{cosmos::to_integral(data.signal->raw()) >> 8};
					if (logger) {
						logger->info() << "PTRACE_EVENT_" << ptrace_event_str(event) << std::endl;

					}
				} else {
					if (logger) {
						logger->warn() << "Other trap event ???" << std::endl;
					}
				}
			}
		} else if (data.signaled()) {
			changeState(TraceState::SIGNAL_DELIVERY_STOP);
			handleSignal(data);
			inject_sig = *data.signal;
		} else {
			if (logger) {
				logger->info() << "Other Tracee event" << std::endl;
			}
		}

		restart(cosmos::Tracee::RestartMode::SYSCALL, inject_sig);
		changeState(TraceState::RUNNING);
		inject_sig = {};
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
