// clues
#include <clues/syscalls/signals.hxx>
#include <clues/Tracee.hxx>

namespace clues {

void SignalFDSystemCall::updateFDTracking(const Tracee &proc) {
	if (fd.fd() == new_fd.fd()) {
		/*
		 * signalfd() has somewhat peculiar semantics, it is used for
		 * creationg new file descriptors but also for adjusting
		 * existing ones. in case the `fd` passed into the system call
		 * matches the "new" FD, no new file descriptor has been
		 * created at all
		 */
		return;
	}

	this->trackFD(proc, FDInfo{FDInfo::SIGNAL_FD, new_fd.fd()});
}

void SignalFD4SystemCall::updateFDTracking(const Tracee &proc) {
	if (fd.fd() == new_fd.fd()) {
		/* see above */
		return;
	}

	FDInfo info{FDInfo::SIGNAL_FD, new_fd.fd()};

	/* synthesize OpenFlags */
	info.flags.emplace();

	const auto sfd_flags = flags.flags();

	using Flag = cosmos::SignalFD::Flag;

	if (sfd_flags[Flag::CLOEXEC]) {
		info.flags->set(cosmos::OpenFlag::CLOEXEC);
	}
	if (sfd_flags[Flag::NONBLOCK]) {
		info.flags->set(cosmos::OpenFlag::NONBLOCK);
	}

	this->trackFD(proc, std::move(info));
}

} // end ns
