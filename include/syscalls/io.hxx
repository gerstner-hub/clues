#pragma once

// clues
#include <clues/SystemCall.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/io.hxx>
#include <clues/sysnrs/generic.hxx>

namespace clues {

struct CLUES_API WriteSystemCall :
		public SystemCall {
	explicit WriteSystemCall(const SystemCallNr nr = SystemCallNr::WRITE) :
			SystemCall{nr},
			fd{},
			buf{count, ItemType::PARAM_IN, "buf", "source buffer"},
			count{"count", "buffer length"},
			written{"bytes", "bytes written", ItemType::RETVAL} {
		setReturnItem(written);
		setParameters(fd, buf, count);
	}

	item::FileDescriptor fd;
	item::BufferPointer buf;
	item::SizeValue count;
	item::SizeValue written;
};

struct CLUES_API ReadSystemCall :
		public SystemCall {
	explicit ReadSystemCall(const SystemCallNr nr = SystemCallNr::READ) :
			SystemCall{nr},
			fd{},
			buf{read, ItemType::PARAM_OUT, "buf", "target buffer"},
			count{"count", "buffer length"},
			read{"bytes", "bytes read", ItemType::RETVAL} {
		setReturnItem(read);
		setParameters(fd, buf, count);
	}

	item::FileDescriptor fd;
	item::BufferPointer buf;
	item::SizeValue count;
	item::SizeValue read;
};

/// vector read system call using a range of struct iovec.
struct CLUES_API ReadVSystemCall :
		public SystemCall {

	explicit ReadVSystemCall(const SystemCallNr nr = SystemCallNr::READV) :
			SystemCall{nr},
			fd{},
			iov{iov_count, read},
			iov_count{"iovcnt", "number of struct iovec*"},
			read{"bytes", "bytes read", ItemType::RETVAL} {
		setReturnItem(read);
		setParameters(fd, iov, iov_count);
	}

	item::FileDescriptor fd;
	item::ReadVector iov;
	item::IntValue iov_count;
	item::SizeValue read;
};

/// vector write system call using a range of struct iovec.
struct CLUES_API WriteVSystemCall :
		public SystemCall {

	explicit WriteVSystemCall(const SystemCallNr nr = SystemCallNr::WRITEV) :
			SystemCall{nr},
       			fd{},
			iov{iov_count},
			iov_count{"iovcnt", "number of struct iovec*"},
			written{"bytes", "bytes written", ItemType::RETVAL} {
		setReturnItem(written);
		setParameters(fd, iov, iov_count);
	}

	item::FileDescriptor fd;
	item::WriteVector iov;
	item::IntValue iov_count;
	item::SizeValue written;
};

/// pread64 read from file at position system call.
/**
 * This has the same signature as read(), only with an added `off_t` parameter.
 **/
struct CLUES_API PRead64SystemCall :
		public ReadSystemCall {
	PRead64SystemCall() :
			ReadSystemCall{SystemCallNr::PREAD64},
       			offset{"offset", "read offset"} {
		addParameters(offset);
	}

	item::OffsetValue offset;
};

/// pwrite64 write to file at position system call.
/**
 * This has the same signature as write(), only with an added `off_t` parameter.
 **/
struct CLUES_API PWrite64SystemCall :
		public WriteSystemCall {
	PWrite64SystemCall() :
			WriteSystemCall{SystemCallNr::PWRITE64},
       			offset{"offset", "write offset"} {
		addParameters(offset);
	}

	item::OffsetValue offset;
};

/// Vector read system call using a range of struct iovec at a given offset.
/**
 * This has the same signature as ReadVSystemCall, only with an additional
 * `off_t`.
 **/
struct CLUES_API PReadVSystemCall :
		public ReadVSystemCall {

	explicit PReadVSystemCall(const SystemCallNr nr = SystemCallNr::PREADV) :
			ReadVSystemCall{nr},
			offset{"offset", "read offset"} {
		addParameters(offset);
	}

	item::OffsetValue offset;
};

/// Vector write system call using a range of struct iovec at a given offset.
/**
 * This has the same signature as WriteVSystemCall, only with an additional
 * `off_t`.
 **/
struct CLUES_API PWriteVSystemCall :
		public WriteVSystemCall {

	explicit PWriteVSystemCall(const SystemCallNr nr = SystemCallNr::PWRITEV) :
			WriteVSystemCall{nr},
			offset{"offset", "write offset"} {
		addParameters(offset);
	}

	item::OffsetValue offset;
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
//
// combined with file descriptor tracking we could route to specializations
// for file descriptor specific operations. But this might not always work
// perfectly (e.g. when attaching to a ForeignTracee).
struct CLUES_API IoCtlSystemCall :
		public SystemCall {

	IoCtlSystemCall() :
			SystemCall{SystemCallNr::IOCTL},
			request{"request", "ioctl request number"} {
		setReturnItem(result);
		setParameters(fd, request);
	}

	item::FileDescriptor fd;
	// this should be a 32-bit `int`, but many request codes set the
	// highest bit, making it signed, causing comparison against
	// preproessor defines to fail. Thus make it unsigned.
	item::UintValue request;
	/*
	 * operation-specific parameters to be done
	 */
	item::SuccessResult result;
};

/// The classic `pipe()` system call without flags.
struct CLUES_API PipeSystemCall :
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

struct CLUES_API Pipe2SystemCall :
		public PipeSystemCall {

	explicit Pipe2SystemCall() :
			PipeSystemCall{SystemCallNr::PIPE2} {
		addParameters(flags);
	}

	item::PipeFlags flags;
};

} // end ns
