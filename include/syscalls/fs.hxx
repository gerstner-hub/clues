#pragma once

// clues
#include <clues/SystemCall.hxx>
#include <clues/items/fs.hxx>
#include <clues/items/signal.hxx>
#include <clues/items/strings.hxx>
#include <clues/sysnrs/generic.hxx>

namespace clues {

struct CLUES_API AccessSystemCall :
		public SystemCall {

	AccessSystemCall() :
			SystemCall{SystemCallNr::ACCESS},
			path{"path"} {
		setReturnItem(result);
		setParameters(path, mode);
	}

	item::StringData path;
	item::AccessModeParameter mode;
	item::SuccessResult result;
};

// this is an earlier variant of faccessat() which doesn't take a flags argument
struct CLUES_API FAccessAtSystemCall :
		public SystemCall {

	explicit FAccessAtSystemCall(const SystemCallNr nr = SystemCallNr::FACCESSAT) :
			SystemCall{nr},
			dirfd{ItemType::PARAM_IN, item::AtSemantics{true}},
			path{"path"} {
		setReturnItem(result);
		setParameters(dirfd, path, mode);
	}

	item::FileDescriptor dirfd;
	item::StringData path;
	item::AccessModeParameter mode;
	item::SuccessResult result;
};

// follow-up variant of faccessat() supporting an additional flags argument, introduced in Linux 5.8
struct CLUES_API FAccessAt2SystemCall :
		public FAccessAtSystemCall {

	FAccessAt2SystemCall() :
			FAccessAtSystemCall{SystemCallNr::FACCESSAT2} {
		addParameters(flags);
	}

	item::AtFlagsValue flags;
};

struct CLUES_API FcntlSystemCall :
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
	std::optional<item::FLockParameter> flock_arg; ///< for F_SETLK, F_SETLKW, F_GETLK
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

	bool check2ndPass() override;

	void prepareNewSystemCall() override;

	void updateFDTracking(const Tracee &proc) override;
};

struct CLUES_API FstatSystemCall :
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

struct CLUES_API FstatAtSystemCall :
		public SystemCall {

	explicit FstatAtSystemCall(const SystemCallNr nr) :
			SystemCall{nr},
       			dirfd{ItemType::PARAM_IN, item::AtSemantics{true}} {
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
			path{"path"} {
		setReturnItem(result);
		setParameters(path, statbuf);
	}

	item::StringData path;
	item::StatParameter statbuf;
	item::SuccessResult result;
};

using StatSystemCall = StatSystemCallT;
using LstatSystemCall = StatSystemCallT;

struct CLUES_API OpenSystemCall :
		public SystemCall {

	OpenSystemCall() :
			SystemCall{SystemCallNr::OPEN},
			filename{"filename"},
			new_fd{ItemType::RETVAL} {
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

	bool check2ndPass() override;

	void prepareNewSystemCall() override;

	void updateFDTracking(const Tracee &) override;
};

struct CLUES_API OpenAtSystemCall :
		public SystemCall {

	OpenAtSystemCall() :
			SystemCall{SystemCallNr::OPENAT},
			fd{ItemType::PARAM_IN, item::AtSemantics{true}},
			filename{"filename"},
			new_fd{ItemType::RETVAL} {
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

	bool check2ndPass() override;

	void prepareNewSystemCall() override;

	void updateFDTracking(const Tracee &) override;
};

struct CLUES_API CloseSystemCall :
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

struct CLUES_API GetDentsSystemCall :
		public SystemCall {

	GetDentsSystemCall() :
			SystemCall{SystemCallNr::GETDENTS},
			size{"size", "dirent size in bytes"},
			ret_bytes{"bytes", "bytes returned in dirent"} {
		setReturnItem(ret_bytes);
		setParameters(fd, dirent, size);
	}

	item::FileDescriptor fd; ///< directory FD.
	item::DirEntries dirent; ///< struct linux_dirent*.
	item::ValueInParameter size; ///< size of `dirent` buffer provided by tracee.
	item::ReturnValue ret_bytes; ///< number of bytes filled in `dirent` buffer.
};

} // end ns
