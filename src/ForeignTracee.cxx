// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/clues.hxx>
#include <clues/ForeignTracee.hxx>

namespace clues {

ForeignTracee::ForeignTracee(EventConsumer &consumer) :
		Tracee{consumer} {
}

void ForeignTracee::configure(const cosmos::ProcessID tracee) {
	setTracee(tracee);
}

void ForeignTracee::wait(cosmos::ChildData &data) {
	data = *cosmos::proc::wait(
			m_ptrace.pid(),
			cosmos::WaitFlags{
				cosmos::WaitFlag::WAIT_FOR_EXITED,
				cosmos::WaitFlag::WAIT_FOR_STOPPED
			});
}

void ForeignTracee::detach() {
	if (m_ptrace.valid() && m_state != TraceState::DEAD) {
		m_ptrace.detach();
		m_ptrace = cosmos::Tracee{};
	}
}

ForeignTracee::~ForeignTracee() {
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
