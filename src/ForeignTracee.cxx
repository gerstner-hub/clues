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
	/*
	 * NOTE: the approach using `sibling` for keeping track of process
	 * data sharing is relatively simple at the moment but doesn't
	 * necessarily cover all situations.
	 * An application might explicitly add two threads of the same process
	 * to an Engine instance, in which case the process sharing
	 * relationship is lost. It's questionable whether such use cases
	 * should be supported at all, though.
	 *
	 * Another approach would be to parse the Tgid from each new Tracee's
	 * /proc/<pid>/status file. This involves a lot of additional
	 * complexity, however:
	 *
	 * - parsing the file can fail (e.g. the tracee disappeared in the
	 *   meanwhile).
	 * - parsing the file for each an every tracee adds additional
	 *   overhead (an file I/O for each attach could be especially
	 *   problematic).
	 * - the Engine would need to keep track of all existing thread groups
	 *   and their members, more data that can get out of sync.
	 *
	 * Thus, for the moment, stick to the simple `sibling` approach which
	 * should work well enough for most scenarios.
	 */
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
