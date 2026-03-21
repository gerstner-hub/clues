#pragma once

// C++
#include <limits>
#include <optional>

// cosmos
#include <cosmos/fs/FileDescriptor.hxx>
#include <cosmos/fs/FileLock.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/items/items.hxx>

namespace clues::item {

class CLUES_API FcntlOperation :
		public item::ValueInParameter {
public: // types

	FcntlOperation() :
			ValueInParameter{"op", "operation"} {
	}

	/// All possible arguments for the `op` parameter to `fcntl(2)`.
	enum class Oper : int {
		DUPFD         = F_DUPFD,
		DUPFD_CLOEXEC = F_DUPFD_CLOEXEC,
		GETFD         = F_GETFD,
		SETFD         = F_SETFD,
		GETFL         = F_GETFL,
		SETFL         = F_SETFL,
		/*
		 * We cannot rely on the preprocessor definitions exported by
		 * the userspace headers due to a lot of magic going on. See
		 * the implementation of the str() method and FLockParameter
		 * for more details.
		 */
		GETLK         = 5, /* F_GETLK */
		SETLK         = 6, /* F_SETLK */
		SETLKW        = 7, /* F_SETLKW */
		GETLK64       = 12, /* F_GETLK64 */
		SETLK64       = 13, /* F_SETLK64 */
		SETLKW64      = 14, /* F_SETLKW64 */
		OFD_SETLK     = F_OFD_SETLK,
		OFD_SETLKW    = F_OFD_SETLKW,
		OFD_GETLK     = F_OFD_GETLK,
		GETOWN        = F_GETOWN,
		SETOWN        = F_SETOWN,
		GETOWN_EX     = F_GETOWN_EX,
		SETOWN_EX     = F_SETOWN_EX,
		GETSIG        = F_GETSIG,
		SETSIG        = F_SETSIG,
		SETLEASE      = F_SETLEASE,
		GETLEASE      = F_GETLEASE,
		NOTIFY        = F_NOTIFY,
		SETPIPE_SZ    = F_SETPIPE_SZ,
		GETPIPE_SZ    = F_GETPIPE_SZ,
		ADD_SEALS     = F_ADD_SEALS,
		GET_SEALS     = F_GET_SEALS,
		GET_RW_HINT   = F_GET_RW_HINT,
		SET_RW_HINT   = F_SET_RW_HINT,
		GET_FILE_RW_HINT = F_GET_FILE_RW_HINT,
		SET_FILE_RW_HINT = F_SET_FILE_RW_HINT,
		// DUPFD is already 0, thus we need a different invalid value
		INVALID       = std::numeric_limits<int>::max()
	};

	using enum Oper;

public: // functions

	std::string str() const override;

	Oper operation() const {
		return m_op;
	}

	/// Returns whether the operation is one of the LK64 operations.
	bool isLock64() const {
		return cosmos::in_list(m_op, {Oper::GETLK64, Oper::SETLK64, Oper::SETLKW64});
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	Oper m_op = INVALID;
};

/// Flags used with `fcntl()` to set and get file descriptor flags.
struct CLUES_API FileDescFlagsValue :
		public SystemCallItem {
	explicit FileDescFlagsValue(ItemType type) :
			SystemCallItem{type, "fdflags", "file descriptor flags"} {
	}

	std::string str() const override;

	cosmos::FileDescriptor::DescFlags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	cosmos::FileDescriptor::DescFlags m_flags;
};

/// Corresponds to `struct flock` Used with fcntl() `F_*LK` operations.
class CLUES_API FLockParameter :
		public PointerValue {
public: // functions
	explicit FLockParameter() :
			// this can be PARAM_IN and PARAM_IN_OUT, but we
			// simply claim it's always IN_OUT
			PointerValue{ItemType::PARAM_IN_OUT, "flock", "struct flock"} {
	}

	std::string str() const override;

	/// Access to the extracted FileLock data.
	/**
	 * This can be unassigned in case no system call was yet executed, or
	 * if fetching the data from the Tracee failed for some reason.
	 **/
	const std::optional<cosmos::FileLock>& lock() const {
		return m_lock;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

	void updateData(const Tracee &proc) override;

protected: // data

	std::optional<cosmos::FileLock> m_lock;
};

/// The value used with the F_GETOWN and F_SETOWN `fcntl()` operations.
/**
 * This can either be a PID (positive value) or a PGID (negative value).
 * Accordingly the type contains either a cosmos::ProcessID or
 * cosmos::ProcessGroupID.
 **/
class CLUES_API FileDescOwner :
		public SystemCallItem {
public: // functions

	explicit FileDescOwner(const ItemType type) :
			SystemCallItem{type} {
	}

	std::string str() const override;

	std::optional<cosmos::ProcessID> pid() const {
		return m_pid;
	}

	std::optional<cosmos::ProcessGroupID> pgid() const {
		return m_pgid;
	}

	bool isPid() const {
		return m_pid.has_value();
	}

	bool isPgid() const {
		return m_pgid.has_value();
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<cosmos::ProcessID> m_pid;
	std::optional<cosmos::ProcessGroupID> m_pgid;
};

/// The structure used with the F_GETOWN_EX and F_SETOWN_EX `fcntl()` operations.
class CLUES_API ExtFileDescOwner :
		public SystemCallItem {
public: // functions
	explicit ExtFileDescOwner(const ItemType type) :
			SystemCallItem{type, "owner_ex", "struct f_owner_ex"} {
	}

	std::string str() const override;

	const std::optional<cosmos::FileDescriptor::Owner>& owner() const {
		return m_owner;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<cosmos::FileDescriptor::Owner> m_owner;
};

/// The value used with F_GETLEASE and F_SETLEASE `fcntl()` operations.
class CLUES_API LeaseType :
		public SystemCallItem {
public: // functions

	explicit LeaseType(const ItemType type) :
			SystemCallItem{type, "lease", "lease type"} {
	}

	std::string str() const override;

	auto& lease() const {
		return m_lease;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	cosmos::FileDescriptor::LeaseType m_lease{std::numeric_limits<int>::max()};
};

/// The value used with F_NOTIFY `fcntl()` operations.
class CLUES_API DNotifySettings :
		public ValueInParameter {
public: // types

	enum class Setting : int {
		ACCESS = DN_ACCESS,
		MODIFY = DN_MODIFY,
		CREATE = DN_CREATE,
		DELETE = DN_DELETE,
		RENAME = DN_RENAME,
		ATTRIB = DN_ATTRIB
	};

	using enum Setting;

	using Settings = cosmos::BitMask<Setting>;

public: // functions

	explicit DNotifySettings() :
			ValueInParameter{"events", "dnotify event bitmask"} {
	}

	auto settings() const {
		return m_settings;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	Settings m_settings;
};

/// The enum value used with file seal operations in the `fcntl()` system call.
class CLUES_API FileSealSettings :
		public ValueParameter {
public: // functions

	explicit FileSealSettings(const ItemType type) :
			ValueParameter{type, "flags", "seal flags"} {
	}

	/// Returns the currently stored SealFlags
	auto flags() const {
		return m_flags;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	cosmos::FileDescriptor::SealFlags m_flags;
};

/// The read/write hint value used with R/W hint operations in the `fcntl()` system call.
/**
 * The `fcntl()` data type used for this is an `uint64_t*`. For some reason a
 * 64-bit wide integer has been selected here, for which the usual `int`
 * values do not provide enough space on 32-bit platforms. Probably for this
 * reason both GET and SET operations operate on pointers to `uint64_t` passed
 * in a second `fcntl()` argument.
 **/
class CLUES_API ReadWriteHint :
		public SystemCallItem {
public: // types

	using Hint = cosmos::FileDescriptor::ReadWriteHint;

public: // functions

	explicit ReadWriteHint(const ItemType type) :
			SystemCallItem{type, "rw_hint", "read/write lifetime hint"} {
	}

	Hint hint() const {
		return m_hint;
	}

	std::string str() const override;

protected: // functions

	void processValue(const Tracee &proc) override;

protected:

	Hint m_hint = Hint::LIFE_NOT_SET;
};

} // end ns
