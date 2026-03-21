#pragma once

// clues
#include <clues/SystemCall.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/items.hxx>
#include <clues/items/mmap.hxx>
#include <clues/sysnrs/generic.hxx>

namespace clues {

/* note that this is called brk() in man pages and some other spots, while
 * `man break` refers to an unsupported system call */
struct CLUES_API BreakSystemCall :
		public SystemCall {
	BreakSystemCall() :
			SystemCall{SystemCallNr::BREAK},
			req_addr{"req_addr", "requested data segment end"},
			ret_addr{"ret_addr", "actual data segment end", ItemType::RETVAL} {
		setReturnItem(ret_addr);
		setParameters(req_addr);
	}

	item::GenericPointerValue req_addr;
	item::GenericPointerValue ret_addr;
};

/// Type for mmap() / mmap2() system calls.
/**
 * SYS_mmap and SYS_mmap2 are unfortunate with regards to tracing. SYS_mmap
 * can refer to two different variants of mmap() depending on ABI.
 *
 * The well-known modern mmap() call taking six parameters is found in
 * SYS_mmap on modern systems and in SYS_mmap2 on older ABIs.
 *
 * SYS_mmap on older ABIs like I386 takes a single `struct mmap_args`
 * parameter. Thus when SYS_mmap occurs during tracing, in an abstract
 * application not considering the ABI, it can be either the modern mmap() or
 * the legacy mmap(). To ease handling these difference this type covers both
 * SYS_mmap and SYS_mmap2 on all ABIs. Even on older ABIs the six member
 * corresponding to the modern mmap() system call will be filled. This way
 * applications can process both types of mmap system calls in a unified way.
 *
 * For completeness, in case of the legacy SYS_mmap() the `isOldMmap()` member
 * function will return `true` and the original data structure passed to the
 * kernel is available in `old_args`.
 **/
struct CLUES_API MmapSystemCall :
		public SystemCall {

public: // functions

	explicit MmapSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			hint{"hint", "address placement hint"},
			length{"len", "length"},
			offset{"offset"},
			addr{"addr", "mapped memory address", ItemType::RETVAL} {
		setReturnItem(addr);
	}

	bool isOldMmap() const {
		return old_args.has_value();
	}

protected: // functions

	void prepareNewSystemCall() override;

	bool implementsOldMmap() const;

	bool check2ndPass(const Tracee&) override;

public: // data

	/* parameters for new mmap() / mmap2() */
	item::GenericPointerValue hint;
	item::SizeValue length;
	item::MemoryProtectionParameter protection;
	item::MapFlagsParameter flags;
	item::FileDescriptor fd;
	item::ValueInParameter offset;

	/* parameters for old mmap() */
	std::optional<item::OldMmapArgs> old_args;

	/* return value */
	item::GenericPointerValue addr;
};

struct CLUES_API MunmapSystemCall :
		public SystemCall {

	MunmapSystemCall() :
			SystemCall{SystemCallNr::MUNMAP},
			addr{"addr", "address to unmap"},
			length{"len", "length"} {
		setReturnItem(result);
		setParameters(addr, length);
	}

	/* parameters */
	item::GenericPointerValue addr;
	item::ValueInParameter length;

	/* return value */
	item::SuccessResult result;
};

struct CLUES_API MprotectSystemCall :
		public SystemCall {
	MprotectSystemCall() :
			SystemCall{SystemCallNr::MPROTECT},
			addr{"addr"},
			length{"length"} {
		setReturnItem(result);
		setParameters(addr, length, protection);
	}

	/* parameters */
	item::GenericPointerValue addr;
	item::ValueInParameter length;
	item::MemoryProtectionParameter protection;

	/* return value */
	item::SuccessResult result;
};

} // end ns
