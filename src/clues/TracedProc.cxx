// C++
#include <iostream>

// Linux
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/proc/WaitRes.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/TracedProc.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

TracedProc::TracedProc(TraceEventConsumer &consumer) :
		m_consumer{consumer} {
}

void TracedProc::setTracee(const cosmos::ProcessID tracee) {
	m_tracee = tracee;
}

void TracedProc::cont(
		const cosmos::ContinueMode &mode,
		const cosmos::Signal signal) {
	const auto raw_signal = signal.raw();

	if (::ptrace(
			static_cast<__ptrace_request>(mode),
			m_tracee,
			signal.valid() ? &raw_signal: nullptr,
			nullptr)) {
		cosmos_throw(cosmos::ApiError("ptrace"));
	}
}

unsigned long TracedProc::getEventMsg() const {
	unsigned long ret;

	if (::ptrace(
		PTRACE_GETEVENTMSG,
		m_tracee,
		nullptr,
		&ret)) {
		cosmos_throw(cosmos::ApiError("ptrace"));
	}

	return ret;
}

void TracedProc::setOptions(const cosmos::TraceFlags flags) {
	if (::ptrace(
			PTRACE_SETOPTIONS,
			m_tracee,
			nullptr,
			flags.raw())) {
		cosmos_throw(cosmos::ApiError("ptrace"));
	}
}

void TracedProc::interrupt() {
	if (::ptrace( PTRACE_INTERRUPT, m_tracee, nullptr, nullptr )) {
		cosmos_throw(cosmos::ApiError("ptrace"));
	}
}

void TracedProc::seize() {
	if (::ptrace( PTRACE_SEIZE, m_tracee, nullptr, nullptr ) != 0 ) {
		cosmos_throw( cosmos::ApiError("ptrace") );
	}
}

void TracedProc::handleSystemCall() {
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

void TracedProc::handleSignal(const cosmos::WaitRes &wr) {
	const auto &signal = wr.stopSignal();

	if (signal == cosmos::Signal{cosmos::signal::TRAP})
		// our own tracing point
		return;

	std::cout << "Got signal: " << wr.stopSignal() << std::endl;
}

void TracedProc::trace() {
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

void TracedProc::getRegisters(RegisterSet &rs) {
	struct iovec reg_vector;
	rs.fillIov(reg_vector);

	if (::ptrace(PTRACE_GETREGSET, m_tracee, rs.registerType(), &reg_vector) != 0 ) {
		cosmos_throw( cosmos::ApiError("ptrace") );
	}

	//std::cout << "Read registers " << reg_vector.iov_len << " vs. " << sizeof(regs) << std::endl;
}

long TracedProc::getData(const long *addr) const {
	errno = 0;
	const long ret = ::ptrace(PTRACE_PEEKDATA, m_tracee, addr, 0);

	if (errno != 0) {
		cosmos_throw( cosmos::ApiError("ptrace") );
	}

	return ret;
}

TracedSeizedProc::TracedSeizedProc(TraceEventConsumer &consumer) :
		TracedProc{consumer} {
}

void TracedSeizedProc::configure(const cosmos::ProcessID tracee) {
	m_tracee = tracee;
}

void TracedSeizedProc::wait(cosmos::WaitRes &res) {
	res = *cosmos::proc::wait(cosmos::WaitFlags{cosmos::WaitFlag::WAIT_FOR_EXITED, cosmos::WaitFlag::WAIT_FOR_STOPPED});
}

void TracedSeizedProc::attach() {
	seize();
	interrupt();
	cosmos::WaitRes wr;

	do {
		wait(wr);

		if (wr.exited())
			return;
	} while (!wr.stopped() && !(wr.stopSignal() == cosmos::signal::TRAP));

	setOptions(cosmos::TraceFlags(cosmos::TraceFlag::TRACESYSGOOD));
	m_state = TraceState::ATTACHED;
	cont(cosmos::ContinueMode::SYSCALL);
}

void TracedSeizedProc::detach() {
	if (m_tracee != cosmos::ProcessID::INVALID && m_state != TraceState::EXITED) {
		if (::ptrace(PTRACE_DETACH, m_tracee, nullptr, nullptr) != 0) {
			cosmos_throw(cosmos::ApiError("ptrace"));
		}

		m_tracee = cosmos::ProcessID::INVALID;
	}
}

TracedSeizedProc::~TracedSeizedProc() {
	try {
		detach();
	} catch(const cosmos::CosmosError &ce) {
		std::cerr
			<< "Couldn't detach from PID " << cosmos::to_integral(m_tracee) << ":\n\n"
			<< ce.what() << "\n";
	}
}


TracedSubProc::TracedSubProc(TraceEventConsumer &consumer) :
	TracedProc{consumer}
{
}

void TracedSubProc::configure(const cosmos::StringVector &prog_args) {
	m_cloner.setArgs(prog_args);
	m_cloner.setPostForkCB([](const cosmos::ChildCloner &){
#if 0
               // actually if we make our parent a tracer this way then we
               // can't deal with it the "new" way that is possible with SEIZED
               // processes. So we only raise a SIGSTOP instead to have the
               // parent catch us before doing anything else and otherwise
               // the parent can SEIZE us.
               if( ::ptrace( PTRACE_TRACEME, INVALID_PID, 0, 0 ) != 0 )
               {
                       cosmos_throw( ApiError() );
               }
#endif

               // this allows our parent to wait for us, such that is knows we're a tracee now
               cosmos::signal::raise(cosmos::signal::STOP);
	});
}

TracedSubProc::~TracedSubProc() {
	try {
		if (m_child.running()) {
			// make sure we can wait for it
			try {
				m_child.kill(cosmos::signal::KILL);
			} catch( ... ) { }
		}

		detach();
	} catch(const cosmos::CosmosError &ce) {
		std::cerr << "Error detaching from child process PID " << cosmos::to_integral(m_child.pid())
			<< ":\n\n" << ce.what();
	}
}

void TracedSubProc::wait(cosmos::WaitRes &res) {
	res = m_child.wait(cosmos::WaitFlags{cosmos::WaitFlag::WAIT_FOR_EXITED, cosmos::WaitFlag::WAIT_FOR_STOPPED});
}

void TracedSubProc::attach() {
	m_exit_code = cosmos::ExitStatus::SUCCESS;
	m_child = m_cloner.run();

	setTracee(m_child.pid());

	seize();

	cosmos::WaitRes r;

	do {
		wait(r);

		if (r.exited())
			return;
	}
	while (! r.trapped());

	setOptions(cosmos::TraceFlags(cosmos::TraceFlag::TRACESYSGOOD));

	if (r.trapped()) {
		m_state = TraceState::ATTACHED;
		cont(cosmos::ContinueMode::SYSCALL);
	}
}

void TracedSubProc::detach() {
	if (m_child.running()) {
		cosmos::WaitRes wr = m_child.wait();
		m_exit_code = wr.exitStatus();
	}
}

} // end ns
