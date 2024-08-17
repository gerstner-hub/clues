// C++
#include <cstring>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/errno.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/io/iovector.hxx>
#include <cosmos/proc/WaitRes.hxx>

// clues
#include <clues/clues.hxx>
#include <clues/SystemCall.hxx>
#include <clues/Tracee.hxx>

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
	m_tracee = tracee;
}

void Tracee::handleSystemCall() {
	if (m_state != TraceState::SYSCALL_ENTER) {
		m_state = TraceState::SYSCALL_ENTER;
		updateRegisters();
		m_current_syscall = &m_syscall_db.get(m_reg_set.syscall());
		m_current_syscall->setEntryRegs(*this, m_reg_set);
		m_consumer.syscallEntry(*m_current_syscall);
	} else {
		m_state = TraceState::SYSCALL_EXIT;
		updateRegisters();
		m_current_syscall->setExitRegs(*this, m_reg_set);
		m_current_syscall->updateOpenFiles(m_fd_path_map);
		m_consumer.syscallExit(*m_current_syscall);
	}
}

void Tracee::handleSignal(const cosmos::WaitRes &wr) {
	const auto signal = wr.stopSignal();

	if (signal == cosmos::Signal{cosmos::signal::TRAP})
		// our own tracing point
		return;

	if (logger) {
		logger->info() << "Got signal: " << signal << std::endl;
	}
}

void Tracee::trace() {
	cosmos::WaitRes wr;
	interrupt();

	while (true) {
		wait(wr);

		if (wr.trapped()) {
			if (wr.isSyscallTrap()) {
				handleSystemCall();
			} else {
				handleSignal(wr);
			}

			cont(cosmos::ContinueMode::SYSCALL, wr.stopSignal());
		} else if (wr.exited()) {
			this->exited(wr);
			m_state = TraceState::EXITED;
			break;
		} else {
			if (logger) {
				logger->debug() << "Other Tracee event" << std::endl;
			}
		}
	}
}

void Tracee::getRegisters(RegisterSet &rs) {
	cosmos::InputMemoryRegion iovec;
	rs.fillIov(iovec);

	ptrace::get_register_set(m_tracee, rs.registerType(), iovec);
	rs.iovFilled(iovec);
}

long Tracee::getData(const long *addr) const {
	return ptrace::get_data(m_tracee, addr);
}

/// Reads data from the Tracee and feeds it to \c filler until it's saturated.
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
