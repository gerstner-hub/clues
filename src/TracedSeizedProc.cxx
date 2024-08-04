// C++
#include <iostream>

// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/TracedSeizedProc.hxx>

namespace clues {

TracedSeizedProc::TracedSeizedProc(EventConsumer &consumer) :
		TracedProc{consumer} {
}

void TracedSeizedProc::configure(const cosmos::ProcessID tracee) {
	m_tracee = tracee;
}

void TracedSeizedProc::wait(cosmos::WaitRes &res) {
	res = *cosmos::proc::wait(
			cosmos::WaitFlags{cosmos::WaitFlag::WAIT_FOR_EXITED, cosmos::WaitFlag::WAIT_FOR_STOPPED});
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

} // end ns
