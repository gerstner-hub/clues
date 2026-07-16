#pragma once

// clues
#include <clues/items/items.hxx>
#include <clues/items/limits.hxx>
#include <clues/items/other.hxx>
#include <clues/items/process.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

/// A system call which is not yet implemented in libclues.
/**
 * A basically valid system call nr was encountered, but libclues does not yet
 * provide support for this particular system call.
 **/
struct CLUES_API NotImplementedSystemCall :
		public SystemCall {
	explicit NotImplementedSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			result{ItemCfg{.label = "result"}} {
		setReturnItem(result);
		addParameters(item);
	}

	item::ReturnValue result;
	item::UnsupportedItem item;
};

/// A system call which is unknown to libclues.
/**
 * A system call number not known by libclues was encountered. This can mean
 * one of two things:
 *
 * - a new system call was implemented in the kernel libclues does not yet know
 *   of.
 * - an invalid system call number was passed by the tracee.
 **/
struct CLUES_API UnknownSystemCall :
		public SystemCall {
	explicit UnknownSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			result{ItemCfg{.label = "result"}} {
		setReturnItem(result);
		addParameters(item);
	}

	item::ReturnValue result;
	item::UnknownItem item;
};

/// A system call no longer supported by the kernel.
/**
 * This type is used for dropped system call numbers that still have a system
 * call number assigned, but that are no longer implemented in the kernel.
 **/
struct CLUES_API DroppedSystemCall :
		public SystemCall {
	explicit DroppedSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			result{ItemCfg{.label = "result"}} {
		setReturnItem(result);
		addParameters(item);
	}

	item::ReturnValue result;
	item::DroppedItem item;
};

// This covers both getrlimit() and setrlimit() which use the same data structures
template <SystemCallNr LIMIT_SYS_NR>
struct CLUES_API LimitSystemCallT :
		public SystemCall {

	LimitSystemCallT() :
			SystemCall{LIMIT_SYS_NR},
			limit{ItemCfg{LIMIT_SYS_NR == SystemCallNr::GETRLIMIT ?
					ItemType::PARAM_OUT :
					ItemType::PARAM_IN}} {
		setReturnItem(result);
		setParameters(type, limit);
	}

	item::ResourceType type;
	item::ResourceLimit limit;
	item::SuccessResult result;
};

using GetRlimitSystemCall = LimitSystemCallT<SystemCallNr::GETRLIMIT>;
using SetRlimitSystemCall = LimitSystemCallT<SystemCallNr::SETRLIMIT>;

struct CLUES_API Prlimit64SystemCall :
		public SystemCall {

	Prlimit64SystemCall() :
			SystemCall{SystemCallNr::PRLIMIT64},
			pid{ItemCfg{.desc = "target process"}},
			limit{ItemCfg{ItemType::PARAM_IN}},
			old_limit{ItemCfg{ItemType::PARAM_OUT, "old_limit"}} {
		setReturnItem(result);
		setParameters(pid, type, limit, old_limit);
	}

	item::ProcessID pid;
	item::ResourceType type;
	item::ResourceLimit limit;
	item::ResourceLimit old_limit;
	item::SuccessResult result;
};

struct CLUES_API RestartSystemCall :
		public SystemCall {

	RestartSystemCall() :
			SystemCall{SystemCallNr::RESTART_SYSCALL} {
		setReturnItem(result);
	}

	item::SuccessResult result;
};

template <SystemCallNr NR>
/// Template type for exit() style system calls.
/**
 * Usually exit_group() is called these days by libc, but the older exit()
 * system call still exists, which only exits the calling thread, not the
 * complete process. Apart from the semantics the system call arguments are
 * the same.
 **/
struct ExitSystemCallT :
		public SystemCall {

	ExitSystemCallT() :
			SystemCall{NR},
			status{ItemCfg{.type = ItemType::PARAM_IN, .desc = "exit code"}} {
		setReturnItem(result);
		setParameters(status);
	}

	item::ExitStatus status;
	item::SuccessResult result; // actually it never returns
};

using ExitGroupSystemCall = ExitSystemCallT<SystemCallNr::EXIT_GROUP>;
using ExitSystemCall = ExitSystemCallT<SystemCallNr::EXIT>;

struct CLUES_API GetRandomSystemCall :
		public SystemCall {

	GetRandomSystemCall() :
			SystemCall{SystemCallNr::GETRANDOM},
			buf{count, ItemCfg{ItemType::PARAM_OUT, "buf", "buffer"},
			/*is_binary=*/true},
			count{ItemCfg{.label = "size"}},
			flags{},
			obtained{ItemCfg{ItemType::RETVAL, "bytes", "bytes obtained"}} {
		setParameters(buf, count, flags);
		setReturnItem(obtained);
	}

	item::BufferPointer buf; ///< buffer where to store random data.
	item::SizeValue count; ///< number of bytes to store into buffer.
	item::GetRandomFlagsValue flags;
	item::SizeValue obtained; ///< number of bytes actually placed into buffer.
};

/// Restartable sequences system call.
/**
 * This is a low-level system call usually only used by the C library. It
 * establishes a per-thread data structure which is used for efficient reading
 * and setting of per-thread information without requiring locking or atomic
 * operations.
 *
 * Due to the low level nature of this system call libclues currently only
 * provides raw access to the `struct rseq` used in the RSeqParameter.
 **/
struct CLUES_API RSeqSystemCall :
		public SystemCall {

	explicit RSeqSystemCall() :
			SystemCall{SystemCallNr::RSEQ},
			rseq_len{make_item_cfg("rseq_len", "size of struct rseq")},
			signature{make_item_cfg("signature", "abort handler signature")} {
		signature.setBase(Base::HEX);
		setParameters(rseq, rseq_len, flags, signature);
		setReturnItem(result);
	}

	/// `struct rseq` of `rseq_len` bytes size.
	item::RSeqParameter rseq;
	/// The length of `rseq`, at least 32 bytes.
	item::Uint32Value rseq_len;
	/// Flags currently used for registering/unregistering struct rseq.
	item::RSeqFlagsValue flags;
	/// A signature expected before "abort handler code".
	item::Uint32Value signature;
	item::SuccessResult result;
};

/// Uname system information system call.
/**
 * This type covers three variants of uname() system calls present in Linux.
 * item::UnameStruct will provide access to a cosmos::Uname structure to
 * inspect the individual fields returned by the kernel. In case an older
 * uname system call was used, unused fields will be empty.
 **/
struct CLUES_API UnameSystemCall :
		public SystemCall {

	explicit UnameSystemCall(const SystemCallNr nr) :
			SystemCall{nr} {
		setReturnItem(result);
		addParameters(utsname);
	}

	item::UnameStruct utsname;

	item::SuccessResult result;
};

} // end ns
