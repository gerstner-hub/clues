#pragma once

// C++
#include <optional>

// Linux
#include <sys/stat.h>

// cosmos
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
				const AtSemantics at_semantics = AtSemantics{false}) :
			SystemCallItem{type, "fd", "file descriptor"},
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
};

/// Flags for system calls with at semantics like linkat(), faccessat().
class CLUES_API AtFlagsValue :
		public SystemCallItem {
public:
	AtFlagsValue() :
			SystemCallItem{ItemType::PARAM_IN, "flags", "*at flags"} {
	}

	std::string str() const override;
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

protected: // functions

	void processValue(const Tracee &proc) override;

protected: // data

	std::optional<Oper> m_op;
};

} // end ns
