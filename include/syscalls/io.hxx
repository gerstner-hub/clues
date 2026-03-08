#pragma once

// clues
#include <clues/SystemCall.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/io.hxx>
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

/// The classic `pipe()` system call without flags.
struct PipeSystemCall :
		public SystemCall {

	explicit PipeSystemCall(const SystemCallNr nr = SystemCallNr::PIPE) :
			SystemCall{nr} {
		setReturnItem(result);
		setParameters(ends);
		/*
		 * XXX: some architectures like IA64, Alpha, MIPS, Sparc,
		 * SuperH return the two file descriptors as return values in
		 * two registers. This still needs to be covered once one of
		 * the respective ABIs is supported.
		 */
	}

	item::PipeEnds ends;
	item::SuccessResult result;

protected: // functions

	void updateFDTracking(const Tracee &proc) override;
};

struct Pipe2SystemCall :
		public PipeSystemCall {

	explicit Pipe2SystemCall() :
			PipeSystemCall{SystemCallNr::PIPE2} {
		addParameters(flags);
	}

	item::PipeFlags flags;
};

} // end ns
