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
			offset{offset_lower},
			offset_lower{} {
		addParameters(offset_lower, offset);
	}

	item::CombinedOffsetValue offset;

protected: // data

	/// The low order bits used by `offset`.
	item::UnusedItem offset_lower;
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
			offset{offset_lower},
			offset_lower{} {
		addParameters(offset_lower, offset);
	}

	item::CombinedOffsetValue offset;

protected: // data

	/// The low order bits used by `offset`.
	item::UnusedItem offset_lower;
};

/// Variant of PReadVSystemCall accepting additional flags.
/**
 * This wraps preadv2(), which accepts additional flags allowing more precise
 * control over the read operation.
 **/
struct CLUES_API PReadV2SystemCall :
		public PReadVSystemCall {

	explicit PReadV2SystemCall() :
			PReadVSystemCall{SystemCallNr::PREADV2} {
		addParameters(flags);
	}

	item::ReadWriteFlags flags;
};

/// Variant of PWriteVSystemCall accepting additional flags.
/**
 * This wraps pwritev2(), which accepts additional flags allowing more precise
 * control over the write operation.
 **/
struct CLUES_API PWriteV2SystemCall :
		public PWriteVSystemCall {

	explicit PWriteV2SystemCall() :
			PWriteVSystemCall{SystemCallNr::PWRITEV2} {
		addParameters(flags);
	}

	item::ReadWriteFlags flags;
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

struct CLUES_API LSeekSystemCall :
		public SystemCall {

	explicit LSeekSystemCall() :
			SystemCall{SystemCallNr::LSEEK},
			offset{"offset", "seek offset"},
			new_offset{"offset", "resulting offset", ItemType::RETVAL} {
		setParameters(fd, offset, whence);
		setReturnItem(new_offset);
	}

	item::FileDescriptor fd;
	item::OffsetValue offset;
	item::Whence whence;
	item::OffsetValue new_offset;
};

/// Legacy llseek() system call for 32-bit ABIs.
/**
 * Since 32-bit ABIs cannot pass 64-bit offsets in a register, this system
 * call uses two registers to combine two 32-bit values into a 64-bit offset
 * (long long). Similarly, to report back the new offset, an out parameter is
 * used to write it into user space memory.
 **/
struct CLUES_API LLSeekSystemCall :
		public SystemCall {

	explicit LLSeekSystemCall() :
			SystemCall{SystemCallNr::LLSEEK},
			offset{offset_lower, /*needs_defer=*/true},
			new_offset{"result", "new 64-bit offset"} {
		setParameters(fd, offset, offset_lower, new_offset, whence);
		setReturnItem(result);
	}

	item::FileDescriptor fd;
	item::CombinedOffsetValue offset;
	item::PointerToScalar<off_t> new_offset;
	item::Whence whence;
	item::SuccessResult result;

protected: // data

	/// The low order bits used by `offset`.
	item::UnusedItem offset_lower;
};

} // end ns
