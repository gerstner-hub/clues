// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/AutoAttachedTracee.hxx>
#include <clues/logger.hxx>

namespace clues {

AutoAttachedTracee::AutoAttachedTracee(Engine &engine, EventConsumer &consumer) :
		Tracee{engine, consumer} {
}

void AutoAttachedTracee::configure(const Tracee &parent, const cosmos::ProcessID pid) {
	setPID(pid);
	m_cmdline = parent.cmdLine();
	m_executable = parent.executable();
	m_flags.set(Flag::WAIT_FOR_ATTACH_STOP);
}

AutoAttachedTracee::~AutoAttachedTracee() {
	try {
		detach();
	} catch (const cosmos::CosmosError &ce) {
		LOG_DEBUG("Couldn't detach from PID " << cosmos::to_integral(m_ptrace.pid()) << ":\n\n" << ce.what());
	}
}

} // end ns
