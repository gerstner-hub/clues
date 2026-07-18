#pragma once

// C++
#include <variant>

// clues
#include <clues/items/fs.hxx>
#include <clues/items/io.hxx>
#include <clues/items/signal.hxx>
#include <clues/items/strings.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCall.hxx>

namespace clues {

CLUES_DEFAULT_VISIBILITY_ON;

struct AccessSystemCall :
		public SystemCall {

	AccessSystemCall() :
			SystemCall{SystemCallNr::ACCESS},
			path{ItemCfg{.label = "path"}} {
		setReturnItem(result);
		setParameters(path, mode);
	}

	item::StringData path;
	item::AccessModeParameter mode;
	item::SuccessResult result;
};

// this is an earlier variant of faccessat() which doesn't take a flags argument
struct FAccessAtSystemCall :
		public SystemCall {

	explicit FAccessAtSystemCall(const SystemCallNr nr = SystemCallNr::FACCESSAT) :
			SystemCall{nr},
			dirfd{{}, item::AtSemantics{true}},
			path{ItemCfg{.label = "path"}} {
		setReturnItem(result);
		setParameters(dirfd, path, mode);
	}

	item::FileDescriptor dirfd;
	item::StringData path;
	item::AccessModeParameter mode;
	item::SuccessResult result;
};

// follow-up variant of faccessat() supporting an additional flags argument, introduced in Linux 5.8
struct FAccessAt2SystemCall :
		public FAccessAtSystemCall {

	FAccessAt2SystemCall() :
			FAccessAtSystemCall{SystemCallNr::FACCESSAT2} {
		addParameters(flags);
	}

	item::AtFlagsValue flags;
};

struct FcntlSystemCall :
		public SystemCall {

	explicit FcntlSystemCall(const SystemCallNr sysnr) :
			SystemCall{sysnr} {
		// these two parameters are always present
		setParameters(fd, operation);
	}

	/* fixed parameters */
	item::FileDescriptor fd;
	item::FcntlOperation operation;

	/* context dependent parameters */
	std::optional<item::FileDescriptor> dup_lowest; ///< for DUPFD, DUPFD_CLOEXEC
	std::optional<item::FileDescFlagsValue> fd_flags_arg; ///< for SETFD
	std::optional<item::OpenFlagsValue> status_flags_arg; ///< for SETFL
	std::optional<item::FLockParameter> flock_arg; ///< for F_SETLK, F_SETLKW, F_GETLK, F_OFD_*
	std::optional<item::FileDescOwner> owner_arg; ///< for SETOWN
	std::optional<item::ExtFileDescOwner> ext_owner_arg; ///< for SETOWN_EX, GETOWN_EX
	std::optional<item::SignalNumber> io_signal_arg; ///< for SETSIG
	std::optional<item::LeaseType> lease_arg; ///< for SETLEASE
	std::optional<item::DNotifySettings> dnotify_arg; ///< for NOTIFY
	std::optional<item::IntValue> pipe_size_arg; ///< for SETPIPE_SZ
	std::optional<item::FileSealSettings> file_seals_arg; ///< for ADD_SEALS
	std::optional<item::ReadWriteHint> rw_hint_arg; ///< for {GET,SET}_[FILE]_RW_HINT

	/* context dependent return values */
	std::optional<item::SuccessResult> result; ///< for all other cases
	std::optional<item::FileDescriptor> ret_dupfd; ///< for DUPFD, DUPFD_CLOEXEC
	std::optional<item::FileDescFlagsValue> ret_fd_flags; ///< for GETFD
	std::optional<item::OpenFlagsValue> ret_status_flags; ///< for GETFL
	std::optional<item::FileDescOwner> ret_owner; ///< for GET_OWNER
	std::optional<item::SignalNumber> ret_io_signal; ///< for GETSIG
	std::optional<item::LeaseType> ret_lease; ///< for GETLEASE
	std::optional<item::IntValue> ret_pipe_size; ///< for GETPIPE_SZ, SETPIPE_SZ
	std::optional<item::FileSealSettings> ret_seals; ///< for GET_SEALS

protected: // functions

	void clear();

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;

	void updateFDTracking(const Tracee &proc) override;
};

struct FstatSystemCall :
		public SystemCall {

	explicit FstatSystemCall(const SystemCallNr nr) :
			SystemCall{nr} {
		setReturnItem(result);
		setParameters(fd, statbuf);
	}

	item::FileDescriptor fd;
	item::StatParameter statbuf;
	item::SuccessResult result;
};

struct FstatAtSystemCall :
		public SystemCall {

	explicit FstatAtSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
       			dirfd{{}, item::AtSemantics{true}} {
		setReturnItem(result);
		setParameters(dirfd, path, statbuf, flags);
	}

	item::FileDescriptor dirfd;
	item::StringData path;
	item::StatParameter statbuf;
	item::AtFlagsValue flags;
	item::SuccessResult result;
};

// This covers both stat() and lstat(), they only differ in semantics
struct StatSystemCallT :
		public SystemCall {

	explicit StatSystemCallT(const SystemCallNr nr) :
			SystemCall{nr},
			path{ItemCfg{.label = "path"}} {
		setReturnItem(result);
		setParameters(path, statbuf);
	}

	item::StringData path;
	item::StatParameter statbuf;
	item::SuccessResult result;
};

using StatSystemCall = StatSystemCallT;
using LstatSystemCall = StatSystemCallT;

/// Type to handle statfs() and statfs64().
struct StatFSSystemCall :
		public SystemCall {

	explicit StatFSSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			path{ItemCfg{.label = "path"}} {
		setReturnItem(result);
		setParameters(path, buf);
	}

	item::StringData path;
	/* for statfs64 this contains the size of `buf` */
	std::optional<item::SizeValue> size;
	item::StatFSParameter buf;

	item::SuccessResult result;

protected: // functions

	void prepareNewSystemCall() override;
};

/// Type to handle fstatfs() and fstatfs64().
struct FStatFSSystemCall :
		public SystemCall {

	explicit FStatFSSystemCall(const SystemCallNr nr) :
			SystemCall{nr} {
		setReturnItem(result);
		setParameters(fd, buf);
	}

	item::FileDescriptor fd;
	/* for fstatfs64 this contains the size of `buf` */
	std::optional<item::SizeValue> size;
	item::StatFSParameter buf;

	item::SuccessResult result;

protected: // functions

	void prepareNewSystemCall() override;
};

struct OpenSystemCall :
		public SystemCall {

	OpenSystemCall() :
			SystemCall{SystemCallNr::OPEN},
			filename{ItemCfg{.label = "filename"}},
			new_fd{ItemCfg{.type = ItemType::RETVAL}} {
		setReturnItem(new_fd);
		setParameters(filename, flags);
	}

	/* parameters */
	item::StringData filename;
	item::OpenFlagsValue flags;
	std::optional<item::FileModeParameter> mode;

	/* return value */
	item::FileDescriptor new_fd;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;

	void updateFDTracking(const Tracee &) override;
};

struct OpenAtSystemCall :
		public SystemCall {

	OpenAtSystemCall() :
			SystemCall{SystemCallNr::OPENAT},
			fd{{}, item::AtSemantics{true}},
			filename{ItemCfg{.label = "filename"}},
			new_fd{ItemCfg{.type = ItemType::RETVAL}} {
		setReturnItem(new_fd);
		setParameters(fd, filename, flags);
	}

	/* parameters */
	item::FileDescriptor fd;
	item::StringData filename;
	item::OpenFlagsValue flags;
	std::optional<item::FileModeParameter> mode;

	/* return value */
	item::FileDescriptor new_fd;

protected: // functions

	bool check2ndPass(const Tracee&) override;

	void prepareNewSystemCall() override;

	void updateFDTracking(const Tracee &) override;
};

struct CloseSystemCall :
		public SystemCall {

	CloseSystemCall() :
			SystemCall{SystemCallNr::CLOSE} {
		setReturnItem(result);
		setParameters(fd);
	}

	item::FileDescriptor fd;
	item::SuccessResult result;

protected: // functions

	void updateFDTracking(const Tracee &) override;
};

struct GetDentsSystemCall :
		public SystemCall {

	explicit GetDentsSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
			size{make_item_cfg("size", "dirent size in bytes")},
			ret_bytes{ItemCfg{ItemType::RETVAL, "bytes", "bytes returned in dirent"}} {
		setReturnItem(ret_bytes);
		setParameters(fd, dirent, size);
	}

	item::FileDescriptor fd; ///< directory FD.
	item::DirEntries dirent; ///< struct linux_dirent*.
	item::UintValue size; ///< size of `dirent` buffer provided by tracee.
	item::SizeValue ret_bytes; ///< number of bytes filled in `dirent` buffer.
};

/// Type to handle various flavors of `fadvise()`.
/**
 * There exist three variants of the system call which differ in the type of
 * the `size` argument. The reason is an ABI glitch which happened in the
 * FADVISE64 system call on I386, where the 32-bit `size_t` was used, which is
 * not 64-bit capable, obviously. Therefore on I386 FADVISE64_64 exists, which
 * uses an actual `off_t` for `size`.
 *
 * Furthermore there exist different orderings on different ABIs, e.g. on
 * AARCH64 the order is different than on X86.
 *
 * To seamlessly access the size and offset in an ABI-agnostic manner, utilize
 * the `size()` and `offset()` member functions.
 **/
struct FAdviseSystemCall :
		public SystemCall {

	explicit FAdviseSystemCall(const SystemCallNr nr);

	off_t offset() const;

	off_t size() const;

	item::FileDescriptor fd; // I/O file descriptor.
	std::variant<item::OffsetValue, item::CombinedOffsetValue, std::monostate> off_variant; ///< starting point of the data area the advice is for.
	std::variant<item::SizeValue, item::CombinedOffsetValue, std::monostate> size_variant; ///< length of the data area the advice is for.
	item::AccessAdvice advice; ///< the actual advice.

	item::SuccessResult result;

protected:

	/// Sets up the canonical native 64-bit variant of the system call.
	void setupPars64();

	void prepareNewSystemCall() override;

	bool m_is_native_64 = true;
};

struct UmaskSystemCall :
		public SystemCall {

	explicit UmaskSystemCall() :
			SystemCall{SystemCallNr::UMASK},
			new_mask{make_item_cfg("mask", "new umask value")},
			old_mask{ItemCfg{ItemType::RETVAL, "old_mask", "old umask value"}} {
		addParameters(new_mask);
		setReturnItem(old_mask);
	}

	/// The new umask to apply.
	item::FileModeParameter new_mask;

	/// Return value containing the previous mask in effect.
	item::FileModeParameter old_mask;
};

struct ReadLinkSystemCall :
		public SystemCall {

	explicit ReadLinkSystemCall(const SystemCallNr nr = SystemCallNr::READLINK) :
			SystemCall{nr},
			filled_bytes{ItemCfg{ItemType::RETVAL, "bytes", "number of bytes placed into buf"}},
			path{ItemCfg{.label = "path"}},
			buf{filled_bytes, make_item_cfg("buf", "buffer to place symlink target into")},
			bufsiz{make_item_cfg("bufsiz", "size of buf")} {
		setReturnItem(filled_bytes);
		setParameters(path, buf, bufsiz);
	}

	/* return value */
	/// number of bytes placed into `buf`.
	item::SizeValue filled_bytes;

	/* parameters */
	item::StringData path;
	/// This buffer will store `filled_bytes` characters upon system call exit.
	item::StringBuffer buf;
	/// The capacity of the tracee memory pointed at by `buf`.
	item::SizeValue bufsiz;
};

struct ReadLinkAtSystemCall :
		public ReadLinkSystemCall {

	explicit ReadLinkAtSystemCall() :
			ReadLinkSystemCall{SystemCallNr::READLINKAT},
			dirfd{{}, item::AtSemantics{true}} {
		setParameters(dirfd, path, buf, bufsiz);
	}

	item::FileDescriptor dirfd;

};

/// The oldest dup() system call.
struct DupSystemCall :
		public SystemCall {

	explicit DupSystemCall(const SystemCallNr nr = SystemCallNr::DUP) :
			SystemCall{nr},
			oldfd{ItemCfg{.label = "oldfd"}},
			retfd{ItemCfg{ItemType::RETVAL}} {
		addParameters(oldfd);
		setReturnItem(retfd);
	}

	item::FileDescriptor oldfd;
	item::FileDescriptor retfd;

protected: // functions

	void updateFDTracking(const Tracee &proc) override;
};

/// The dup2() system call taking an explicit new file descriptor parameter.
struct Dup2SystemCall :
		public DupSystemCall {

	explicit Dup2SystemCall(const SystemCallNr nr = SystemCallNr::DUP2) :
			DupSystemCall{nr},
			newfd{ItemCfg{.label = "newfd"}} {
		addParameters(newfd);
	}

	/// The desired duplicated file descriptor number for `oldfd`.
	item::FileDescriptor newfd;
};

/// The dup3() system call taking additional flags.
struct Dup3SystemCall :
		public Dup2SystemCall {

	explicit Dup3SystemCall() :
			Dup2SystemCall{SystemCallNr::DUP3} {
		addParameters(flags);
	}

	item::DupFlags flags;
};

CLUES_DEFAULT_VISIBILITY_OFF;

} // end ns
