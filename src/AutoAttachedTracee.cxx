// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/AutoAttachedTracee.hxx>
#include <clues/logger.hxx>

namespace clues {

AutoAttachedTracee::AutoAttachedTracee(Engine &engine, EventConsumer &consumer, TraceePtr parent) :
		Tracee{engine, consumer, parent} {
}

void AutoAttachedTracee::configure(const cosmos::ProcessID pid, const cosmos::ptrace::Event event) {
	setPID(pid);
	m_flags.set(Flag::WAIT_FOR_ATTACH_STOP);

	/* In case of clone() we need to share process process data with the
	 * parent.
	 * In all other cases we need a deep-copy of process data (sharing
	 * ends).
	 */
	// TODO: in custom clone configurations the file descriptor table
	// might not be shared with `parent`

	if (event != cosmos::ptrace::Event::CLONE) {
		m_process_data = std::make_shared<ProcessData>(*m_process_data);
	}
}

AutoAttachedTracee::~AutoAttachedTracee() {
	try {
		detach();
	} catch (const cosmos::CosmosError &ce) {
		LOG_DEBUG("Couldn't detach from PID " << cosmos::to_integral(m_ptrace.pid()) << ":\n\n" << ce.what());
	}
}

} // end ns
