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

} // end ns
