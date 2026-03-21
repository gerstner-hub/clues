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

bool MmapSystemCall::check2ndPass(const Tracee &proc) {
	/*
	 * we use this callback not for rearranging the parameters, but for
	 * synchronizing the regular mmap arguments with the legacy struct
	 * mmap data.
	 */
	if (isOldMmap()) {
		const auto &args = *old_args;
		hint.fill(proc, Word{cosmos::to_integral(args.addr())});
		length.fill(proc, Word{args.length()});
		protection.fill(proc, Word{static_cast<elf_greg_t>(args.prot().raw())});
		flags.fill(proc, Word{static_cast<elf_greg_t>(cosmos::to_integral(args.type()) | args.flags().raw())});
		fd.fill(proc, Word{static_cast<elf_greg_t>(cosmos::to_integral(args.fd()))});
		offset.fill(proc, Word{args.offset()});
	}
	return false;
}

} // end ns
