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

} // end ns
