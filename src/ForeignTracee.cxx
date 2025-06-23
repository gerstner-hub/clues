// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/ForeignTracee.hxx>
#include <clues/logger.hxx>

namespace clues {

ForeignTracee::ForeignTracee(Engine &engine, EventConsumer &consumer,
		TraceePtr sibling) :
		Tracee{engine, consumer, sibling} {
}

void ForeignTracee::configure(const cosmos::ProcessID tracee) {
	setPID(tracee);
}

ForeignTracee::~ForeignTracee() {
	try {
		detach();
	} catch (const cosmos::CosmosError &ce) {
		LOG_DEBUG("Couldn't detach from PID " << cosmos::to_integral(m_ptrace.pid()) << ":\n\n" << ce.what());
	}
}

} // end ns
