#pragma once

// clues
#include <clues/SystemCall.hxx>
#include <clues/items/fs.hxx>
#include <clues/sysnrs/generic.hxx>

namespace clues {

struct CLUES_API WriteSystemCall :
		public SystemCall {
	WriteSystemCall() :
			SystemCall{SystemCallNr::WRITE},
			fd{},
			buf{count, ItemType::PARAM_IN, "buf", "source buffer"},
			count{"count", "buffer length"},
			written{"bytes", "bytes written"} {
		setReturnItem(written);
		setParameters(fd, buf, count);
	}

	item::FileDescriptor fd;
	item::BufferPointer buf;
	item::ValueInParameter count;
	item::ReturnValue written;
};

struct CLUES_API ReadSystemCall :
		public SystemCall {
	ReadSystemCall() :
			SystemCall{SystemCallNr::READ},
			fd{},
			buf{read, ItemType::PARAM_OUT, "buf", "target buffer"},
			count{"count", "buffer length"},
			read{"bytes", "bytes read"} {
		setReturnItem(read);
		setParameters(fd, buf, count);
	}

	item::FileDescriptor fd;
	item::BufferPointer buf;
	item::ValueInParameter count;
	item::ReturnValue read;
};

// TODO: the number of parameters can vary here.
// can we find out during runtime if additional parameters
// have been passed?
// some well-known commands could be interpreted, but we don't
// know of what type a file descriptor is, or do we?
//
// the request integer can be interpreted in a generic way by use of some
// macros (e.g.: in/out/in-out operation, size of next parameter), but the man
// page says that this is unreliable, due to legacy APIs.
struct CLUES_API IoCtlSystemCall :
		public SystemCall {

	IoCtlSystemCall() :
			SystemCall{SystemCallNr::IOCTL},
			request{"request", "ioctl request number"} {
		setReturnItem(result);
		setParameters(fd, request);
	}

	item::FileDescriptor fd;
	item::GenericPointerValue request;
	item::SuccessResult result;
};

} // end ns
