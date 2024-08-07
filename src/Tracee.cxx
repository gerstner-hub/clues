// C++
#include <iostream>

// Linux
#include <sys/types.h>
#include <sys/wait.h>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/error/errno.hxx>
#include <cosmos/io/iovector.hxx>
#include <cosmos/proc/WaitRes.hxx>

// clues
#include <clues/Tracee.hxx>
#include <clues/SystemCall.hxx>

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
		getRegisters(m_reg_set);
		m_current_syscall = &m_syscall_db.get(m_reg_set.syscall());
		m_current_syscall->setEntryRegs(*this, m_reg_set);
		m_consumer.syscallEntry(*m_current_syscall);
	} else {
		m_state = TraceState::SYSCALL_EXIT;
		getRegisters(m_reg_set);
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

	std::cout << "Got signal: " << signal << std::endl;
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
			std::cout << "Tracee exited" << std::endl;
			this->exited(wr);
			m_state = TraceState::EXITED;
			break;
		} else {
			std::cout << "Other Tracee event" << std::endl;
		}
	}
}

void Tracee::getRegisters(RegisterSet &rs) {
	cosmos::InputMemoryRegion iovec;
	rs.fillIov(iovec);

	ptrace::get_register_set(m_tracee, rs.registerType(), iovec);
	rs.iovFilled(iovec);

	//std::cout << "Read registers " << reg_vector.iov_len << " vs. " << sizeof(regs) << std::endl;
}

long Tracee::getData(const long *addr) const {
	cosmos::reset_errno();
	const long ret = ::ptrace(PTRACE_PEEKDATA, m_tracee, addr, 0);

	if (cosmos::is_errno_set()) {
		cosmos_throw(cosmos::ApiError("ptrace"));
	}

	return ret;
}

} // end ns
