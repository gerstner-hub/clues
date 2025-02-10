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
	setTracee(tracee);
}

void SeizedTracee::wait(cosmos::ChildData &data) {
	data = *cosmos::proc::wait(
			m_ptrace.pid(),
			cosmos::WaitFlags{
				cosmos::WaitFlag::WAIT_FOR_EXITED,
				cosmos::WaitFlag::WAIT_FOR_STOPPED
			});
}

void SeizedTracee::attach() {
	seize(cosmos::ptrace::Opts{cosmos::ptrace::Opt::TRACESYSGOOD});
	interrupt();
	cosmos::ChildData child;

	do {
		wait(child);

		if (child.exited())
			return;
	} while (!(child.stopped() && child.signal != cosmos::signal::TRAP) && !child.trapped());

	m_state = TraceState::ATTACHED;
	restart(cosmos::Tracee::RestartMode::SYSCALL);
}

void SeizedTracee::detach() {
	if (m_ptrace.valid() && m_state != TraceState::EXITED) {
		m_ptrace.detach();
		m_ptrace = cosmos::Tracee{};
	}
}

SeizedTracee::~SeizedTracee() {
	try {
		detach();
	} catch (const cosmos::CosmosError &ce) {
		if (logger) {
			logger->debug()
				<< "Couldn't detach from PID " << cosmos::to_integral(m_ptrace.pid()) << ":\n\n"
				<< ce.what() << "\n";
		}
	}
}

} // end ns
