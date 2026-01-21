// clues
#include <clues/format.hxx>
#include <clues/items/clone.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>
// private
#include <clues/private/utils.hxx>

namespace clues::item {

std::string CloneFlagsValue::str() const {
	BITFLAGS_FORMAT_START(m_flags);

	BITFLAGS_ADD(CLONE_CHILD_CLEARTID);
	BITFLAGS_ADD(CLONE_CHILD_SETTID);
	BITFLAGS_ADD(CLONE_CLEAR_SIGHAND);
	BITFLAGS_ADD(CLONE_DETACHED);
	BITFLAGS_ADD(CLONE_FILES);
	BITFLAGS_ADD(CLONE_FS);
	BITFLAGS_ADD(CLONE_INTO_CGROUP);
	BITFLAGS_ADD(CLONE_IO);
	BITFLAGS_ADD(CLONE_NEWCGROUP);
	BITFLAGS_ADD(CLONE_NEWIPC);
	BITFLAGS_ADD(CLONE_NEWNET);
	BITFLAGS_ADD(CLONE_NEWNS);
	BITFLAGS_ADD(CLONE_NEWNS);
	BITFLAGS_ADD(CLONE_NEWPID);
	BITFLAGS_ADD(CLONE_NEWUSER);
	BITFLAGS_ADD(CLONE_NEWUTS);
	BITFLAGS_ADD(CLONE_PARENT);
	BITFLAGS_ADD(CLONE_PARENT_SETTID);
	BITFLAGS_ADD(CLONE_PIDFD);
	BITFLAGS_ADD(CLONE_PTRACE);
	BITFLAGS_ADD(CLONE_SETTLS);
	BITFLAGS_ADD(CLONE_SIGHAND);
	BITFLAGS_ADD(CLONE_SYSVSEM);
	BITFLAGS_ADD(CLONE_THREAD);
	BITFLAGS_ADD(CLONE_UNTRACED);
	BITFLAGS_ADD(CLONE_VFORK);
	BITFLAGS_ADD(CLONE_VM);

	if (exit_signal) {
		BITFLAGS_STREAM() << format::signal(*exit_signal, /*verbose=*/false);
	}

	return BITFLAGS_STR();;
}

void CloneFlagsValue::processValue(const Tracee &) {
	if (m_call->callNr() == SystemCallNr::CLONE) {
		// child exit signal is piggy-backed in the low byte of flags
		const auto raw = valueAs<int>();
		// CloneFlags are based on uint64_t (type used in clone3()),
		// thus cast accordingly.
		m_flags = cosmos::CloneFlags{static_cast<uint64_t>(raw & (~0xFF))};
		exit_signal.emplace(cosmos::SignalNr{raw & 0xFF});
	} else {
		m_flags = valueAs<cosmos::CloneFlags>();
		exit_signal.reset();
	}
}

} // end ns
