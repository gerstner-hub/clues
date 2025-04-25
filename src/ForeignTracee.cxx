// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/ForeignTracee.hxx>
#include <clues/logger.hxx>

namespace clues {

ForeignTracee::ForeignTracee(EventConsumer &consumer) :
		Tracee{consumer} {
}

void ForeignTracee::configure(const cosmos::ProcessID tracee) {
	setTracee(tracee);
}

ForeignTracee::~ForeignTracee() {
	try {
		detach();
	} catch (const cosmos::CosmosError &ce) {
		LOG_DEBUG("Couldn't detach from PID " << cosmos::to_integral(m_ptrace.pid()) << ":\n\n" << ce.what());
	}
}

} // end ns
