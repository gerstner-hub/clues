// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/clues.hxx>
#include <clues/SeizedTracee.hxx>

namespace clues {

SeizedTracee::SeizedTracee(EventConsumer &consumer) :
		Tracee{consumer} {
}

void SeizedTracee::configure(const cosmos::ProcessID tracee) {
	m_tracee = tracee;
}

void SeizedTracee::wait(cosmos::WaitRes &res) {
	res = *cosmos::proc::wait(
			m_tracee,
			cosmos::WaitFlags{
				cosmos::WaitFlag::WAIT_FOR_EXITED,
				cosmos::WaitFlag::WAIT_FOR_STOPPED
			});
}

void SeizedTracee::attach() {
	seize();
	interrupt();
	cosmos::WaitRes wr;

	do {
		wait(wr);

		if (wr.exited())
			return;
	} while (!wr.stopped() && wr.stopSignal() != cosmos::signal::TRAP);

	setOptions(cosmos::TraceFlags{cosmos::TraceFlag::TRACESYSGOOD});
	m_state = TraceState::ATTACHED;
	cont(cosmos::ContinueMode::SYSCALL);
}

void SeizedTracee::detach() {
	if (m_tracee != cosmos::ProcessID::INVALID && m_state != TraceState::EXITED) {
		ptrace::detach(m_tracee);
		m_tracee = cosmos::ProcessID::INVALID;
	}
}

SeizedTracee::~SeizedTracee() {
	try {
		detach();
	} catch (const cosmos::CosmosError &ce) {
		if (logger) {
			logger->debug()
				<< "Couldn't detach from PID " << cosmos::to_integral(m_tracee) << ":\n\n"
				<< ce.what() << "\n";
		}
	}
}

} // end ns
