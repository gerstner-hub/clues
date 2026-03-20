// clues
#include <clues/syscalls/memory.hxx>

namespace clues {

bool MmapSystemCall::implementsOldMmap() const {
	switch (abi()) {
		case ABI::I386: return true;
		default: return false;
	}
}

void MmapSystemCall::prepareNewSystemCall() {
	/*
	 * setup parameters for legacy / new variant of mmap()
	 */
	if (callNr() == SystemCallNr::MMAP2 || !implementsOldMmap()) {
		old_args.reset();
		setParameters(hint, length, protection, flags, fd, offset);
	} else {
		old_args.emplace(item::OldMmapArgs{});
		setParameters(*old_args);
	}
}

} // end ns
