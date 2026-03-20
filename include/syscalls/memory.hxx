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

struct CLUES_API MmapSystemCall :
		public SystemCall {
	MmapSystemCall() :
			SystemCall{SystemCallNr::MMAP},
			hint{"hint", "address placement hint"},
			length{"len", "length"},
			offset{"offset"},
			addr{"addr", "mapped memory address", ItemType::RETVAL} {
		setReturnItem(addr);
		setParameters(hint, length, protection, flags, fd, offset);
	}

	/* parameters */
	item::GenericPointerValue hint;
	item::SizeValue length;
	item::MemoryProtectionParameter protection;
	item::MapFlagsParameter flags;
	item::FileDescriptor fd;
	item::ValueInParameter offset;

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
