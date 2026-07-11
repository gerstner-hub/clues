#pragma once

// clues
#include <clues/SystemCall.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/io.hxx>
#include <clues/items/time.hxx>
#include <clues/sysnrs/generic.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

struct WriteSystemCall :
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

struct ReadSystemCall :
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
struct ReadVSystemCall :
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
struct WriteVSystemCall :
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
struct PRead64SystemCall :
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
struct PWrite64SystemCall :
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
struct PReadVSystemCall :
		public ReadVSystemCall {

	explicit PReadVSystemCall(const SystemCallNr nr = SystemCallNr::PREADV) :
			ReadVSystemCall{nr},
			offset{} {
		addParameters(offset.lowerPar(), offset);
	}

public: // data

	item::CombinedOffsetValue offset;
};

/// Vector write system call using a range of struct iovec at a given offset.
/**
 * This has the same signature as WriteVSystemCall, only with an additional
 * `off_t`.
 **/
struct PWriteVSystemCall :
		public WriteVSystemCall {

	explicit PWriteVSystemCall(const SystemCallNr nr = SystemCallNr::PWRITEV) :
			WriteVSystemCall{nr},
			offset{} {
		addParameters(offset.lowerPar(), offset);
	}

public: // data

	item::CombinedOffsetValue offset;
};

/// Variant of PReadVSystemCall accepting additional flags.
/**
 * This wraps preadv2(), which accepts additional flags allowing more precise
 * control over the read operation.
 **/
struct PReadV2SystemCall :
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
struct PWriteV2SystemCall :
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
struct IoCtlSystemCall :
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

struct LSeekSystemCall :
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
struct LLSeekSystemCall :
		public SystemCall {

	explicit LLSeekSystemCall() :
			SystemCall{SystemCallNr::LLSEEK},
			offset{item::CombinedOffsetValue::HIGH_THEN_LOW},
			new_offset{"result", "new 64-bit offset"} {
		setParameters(fd, offset, offset.lowerPar(), new_offset, whence);
		setReturnItem(result);
	}

	item::FileDescriptor fd;
	item::CombinedOffsetValue offset;
	item::PointerToScalar<off_t> new_offset;
	item::Whence whence;
	item::SuccessResult result;
};

struct EventFDSystemCall :
		public SystemCall {

	explicit EventFDSystemCall(const SystemCallNr nr = SystemCallNr::EVENTFD) :
			SystemCall{nr},
			initval{"initval", "initial value"},
			new_fd{ItemType::RETVAL} {
		setParameters(initval);
		setReturnItem(new_fd);
	}

	item::UintValue initval;

	item::FileDescriptor new_fd;

protected: // functions

	void updateFDTracking(const Tracee &) override;
};

struct EventFD2SystemCall :
		public EventFDSystemCall {

	explicit EventFD2SystemCall() :
			EventFDSystemCall{SystemCallNr::EVENTFD2} {
		addParameters(flags);
	}

	item::EventFDFlags flags;

protected: // functions

	void updateFDTracking(const Tracee &) override;
};

/// select() system call handling.
/**
 * This type covers the single select() system call on x86_64 and other 64-bit
 * ABIs as well as the "old" and "new" select() on i386. The old select()
 * uses an argument struct which is transparently copied over by the
 * implementation to the split member items to allow seamless processing of
 * all types of select() by applications.
 *
 * For completeness `old_args` contains the actual combined select argument
 * struct in case of the old select system call. The system call numbers map
 * as follows depending on ABI:
 *
 * - SystemCallNr::SELECT: "old" select on ABI::I386, new select otherwise.
 * - SystemCallNr::NEWSELECT: new select on ABI::I386, not available on other
 *   ABIs.
 **/
struct SelectSystemCall :
		public SystemCall {

	explicit SelectSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			nfds{"nfds", "highest numbered fd + 1"},
			readfds{nfds, "readfds", "readable fd set"},
			writefds{nfds, "writefds", "writable fd set"},
			exceptfds{nfds, "exceptfds", "exceptional fd set"},
			timeout{"timeout", "maximum wait time",
				ItemType::PARAM_IN_OUT,
				item::RemainSemantics{true}},
			nready{"nready", "number of fds in all set that are ready", ItemType::RETVAL} {
		setReturnItem(nready);
		addParameters(nfds, readfds, writefds, exceptfds, timeout);
	}

	/// Returns whether this is the "old" select() system call on 32-bit ABIs.
	/**
	 * On 32-bit ABIs like I386 there exists an "old" select() system call
	 * which has SystemCallNr::SELECT like on newer ABIs, but actually
	 * uses a single struct as parameter, similar to the "old mmap" system
	 * call. The modern select() has SystemCallNr::NEWSELECT instead.
	 *
	 * This type provides a generic view on both variants of select() such
	 * that applications don't need to care about these details. If
	 * necessary the original structure of the "old" select can be looked
	 * up in the `old_args` member.
	 **/
	bool isOldSelect() const;

	item::IntValue nfds;
	item::FDSet readfds;
	item::FDSet writefds;
	item::FDSet exceptfds;
	item::TimeValParameter timeout;

	std::optional<item::OldSelectArgs> old_args;

	item::IntValue nready;

protected: // functions

	void prepareNewSystemCall() override;

	bool check2ndPass(const Tracee&) override;

	friend class item::OldSelectArgs;

	void updateFromOldArgs(const Tracee&);
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
