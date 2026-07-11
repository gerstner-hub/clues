// clues
#include <clues/syscalls/io.hxx>

namespace clues {

void PipeSystemCall::updateFDTracking(const Tracee &proc) {
	if (ends.haveEnds()) {
		FDInfo read_info{FDInfo::Type::PIPE, ends.readEnd()};
		FDInfo write_info{FDInfo::Type::PIPE, ends.writeEnd()};

		// model the read and write ends via appropriate OpenMode values
		read_info.mode = cosmos::OpenMode::READ_ONLY;
		write_info.mode = cosmos::OpenMode::WRITE_ONLY;

		trackFD(proc, std::move(read_info));
		trackFD(proc, std::move(write_info));
	}
}

void EventFDSystemCall::updateFDTracking(const Tracee &proc) {
	trackFD(proc, FDInfo{FDInfo::EVENT_FD, new_fd.fd()});
}

void EventFD2SystemCall::updateFDTracking(const Tracee &proc) {
	FDInfo info{FDInfo::EVENT_FD, new_fd.fd()};

	info.flags.emplace();

	using enum cosmos::EventFile::Flag;

	const auto evflags = this->flags.flags();
	if (evflags[CLOSE_ON_EXEC]) {
		info.flags->set(cosmos::OpenFlag::CLOEXEC);
	}
	if (evflags[NONBLOCK]) {
		info.flags->set(cosmos::OpenFlag::NONBLOCK);
	}

	trackFD(proc, std::move(info));
}

bool SelectSystemCall::isOldSelect() const {
	return abi() == ABI::I386 && callNr() == SystemCallNr::SELECT;
}

void SelectSystemCall::prepareNewSystemCall() {
	if (isOldSelect()) {
		if (!old_args) {
			old_args.emplace();
			setParameters(*old_args);
		}
	} else if (old_args) {
		old_args.reset();
		setParameters(nfds, readfds, writefds, exceptfds, timeout);
	}
}

bool SelectSystemCall::check2ndPass(const Tracee &proc) {
	if (isOldSelect()) {
		/*
		 * abuse this callback to feed the old select args struct into
		 * the individual new-style select parameters.
		 */
		const auto &old = *old_args;
		nfds.fill(proc, static_cast<Word>(old.numFDs()));
		readfds.fill(proc, static_cast<Word>(old.readSetPtr()));
		writefds.fill(proc, static_cast<Word>(old.writeSetPtr()));
		exceptfds.fill(proc, static_cast<Word>(old.exceptSetPtr()));
		timeout.fill(proc, static_cast<Word>(old.timeoutPtr()));
	}
	return false;
}

void SelectSystemCall::updateFromOldArgs(const Tracee &proc) {
	updateParameters(proc,
			{nfds, readfds, writefds, exceptfds, timeout});
}

} // end ns
