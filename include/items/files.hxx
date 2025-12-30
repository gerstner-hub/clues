#pragma once

// C++
#include <optional>

// Linux
#include <sys/stat.h>

// cosmos
#include <cosmos/fs/FileDescriptor.hxx>
#include <cosmos/fs/FileLock.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/SystemCallItem.hxx>
#include <clues/items/items.hxx>

namespace clues::item {

using AtSemantics = cosmos::NamedBool<struct at_semantics_t, false>;

/// Base class for file descriptor system call items.
class CLUES_API FileDescriptor :
		public SystemCallItem {

public: // functions

	/**
	 * \param[in] at_semantics
	 * 	If set then the file descriptor is considered to be part of an
	 * 	*at() type system call i.e. the special file descriptor
	 * 	AT_FDCWD can occur.
	 **/
	explicit FileDescriptor(const ItemType type = ItemType::PARAM_IN,
				const AtSemantics at_semantics = AtSemantics{false},
				const std::string_view short_name = "fd",
				const std::string_view long_name = "file descriptor") :
			SystemCallItem{type, short_name, long_name},
			m_at_semantics{at_semantics} {
	}

	std::string str() const override;

protected: // data

	const AtSemantics m_at_semantics = AtSemantics{false};
};

/// The flags passed to calls like open().
class CLUES_API OpenFlagsValue :
		public SystemCallItem {
public:
	explicit OpenFlagsValue(const ItemType type = ItemType::PARAM_IN) :
			SystemCallItem{type, "flags", "open flags"} {
	}

	std::string str() const override;

	cosmos::OpenMode mode() const {
		return m_mode;
	}

	cosmos::OpenFlags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	cosmos::OpenMode m_mode;
	cosmos::OpenFlags m_flags;
};

/// Flags for system calls with at semantics like linkat(), faccessat().
class CLUES_API AtFlagsValue :
		public SystemCallItem {
public: // types

	enum class AtFlag : int {
		EMPTY_PATH       = AT_EMPTY_PATH,
		SYMLINK_NOFOLLOW = AT_SYMLINK_NOFOLLOW,
		SYMLINK_FOLLOW   = AT_SYMLINK_FOLLOW,
		REMOVEDIR        = AT_REMOVEDIR, ///< only used with unlinkat
		EACCESS          = AT_EACCESS ///< only used with faccessat2
	};

	using AtFlags = cosmos::BitMask<AtFlag>;

public: // functions

	AtFlagsValue() :
			SystemCallItem{ItemType::PARAM_IN, "flags", "*at flags"} {
	}

	std::string str() const override;

	AtFlags flags() const {
		return m_flags;
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	AtFlags m_flags;
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

/// The mode parameter in access().
class AccessModeParameter :
		public item::ValueInParameter {
public:
	explicit AccessModeParameter() :
			item::ValueInParameter{"check", "access check"} {
	}

	std::string str() const override;
};

/// File access mode passed e.g. to open(), chmod().
class FileModeParameter :
		public item::ValueInParameter {
public:

	FileModeParameter() :
			item::ValueInParameter{"mode", "file-mode"} {
	}

	std::string str() const override;
};

/// The stat structure used in stat() & friends.
class CLUES_API StatParameter :
		public PointerOutValue {
public: // functions
	explicit StatParameter() :
			PointerOutValue{"stat", "struct stat"} {
	}

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	std::optional<struct ::stat> m_stat;
};

/// A range of directory entries from getdents().
class CLUES_API DirEntries :
		public PointerOutValue {
public: // functions

	explicit DirEntries() :
			PointerOutValue{"dirent", "struct linux_dirent"}
	{}

	std::string str() const override;

protected: // functions

	void updateData(const Tracee &proc) override;

protected: // data

	std::vector<std::string> m_entries;
};

class FcntlOperation :
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
		SETLK         = F_SETLK,
		SETLKW        = F_SETLKW,
		GETLK         = F_GETLK,
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
		SET_FILE_RW_HINT = F_SET_FILE_RW_HINT
	};

	using enum Oper;

public: // functions

	std::string str() const override;

	Oper operation() const {
		return *m_op;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<Oper> m_op;
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

	auto pid() const {
		return m_pid;
	}

	auto pgid() const {
		return m_pgid;
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

	const auto& owner() const {
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

	const auto& lease() const {
		return m_lease;
	}

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<cosmos::FileDescriptor::LeaseType> m_lease;
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

} // end ns
