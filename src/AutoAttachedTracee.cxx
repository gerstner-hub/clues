// cosmos
#include <cosmos/error/ApiError.hxx>
#include <cosmos/io/ILogger.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/AutoAttachedTracee.hxx>
#include <clues/logger.hxx>
#include <clues/syscalls/process.hxx>
#include <clues/sysnrs/generic.hxx>

namespace clues {

namespace {

bool shares_file_descriptors_with_parent(const SystemCall &sc) {

	/*
	 * In case of clone() with CLONE_FILES we need to share process data
	 * with the parent.
	 *
	 * In all other cases we need a deep-copy of process data (sharing of
	 * the file descriptor table ends).
	 *
	 * Note: clone() calls with SIGCHILD as exit signal can appear as
	 * regular fork events, clone() calls with CLONE_VFORK will appear as
	 * regular vfork events. This is the case even if SHARE_FILES is
	 * passed to clone(), which doesn't match the fork() semantics.
	 *
	 * For this reason we cannot rely on the ptrace event for this, but
	 * need to inspect the active system call exclusively.
	 */

	switch (sc.callNr()) {
		/*
		 * TODO: once we modeled the CLONE3 we need to cover that case
		 * as well.
		 */
		//case SystemCallNr::CLONE3:
		case SystemCallNr::CLONE: {
			// this throws if the cast fails, but this should never happen
			auto &clone_sc = dynamic_cast<const CloneSystemCall&>(sc);
			const auto flags = clone_sc.flags.flags();

			return flags[cosmos::CloneFlag::SHARE_FILES];
		}
		case SystemCallNr::FORK: /* fallthrough */
		case SystemCallNr::VFORK: return false;
		default:
			LOG_ERROR("PTRACE auto-attach event but last system call is not recognized?!");
			// we don't know what to do in this case, further tracing is
			// undefined, might be best to detach?
			return false;
	}
}

} // end anon ns

AutoAttachedTracee::AutoAttachedTracee(Engine &engine, EventConsumer &consumer, TraceePtr parent) :
		Tracee{engine, consumer, parent} {
}

void AutoAttachedTracee::configure(const cosmos::ProcessID pid, const cosmos::ptrace::Event event,
		const SystemCall &sc) {
	(void)event;
	setPID(pid);
	m_flags.set(Flag::WAIT_FOR_ATTACH_STOP);

	if (!shares_file_descriptors_with_parent(sc)) {
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
