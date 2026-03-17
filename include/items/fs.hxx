#pragma once

// C++
#include <optional>
#include <string_view>

// Linux
#include <sys/stat.h>

// cosmos
#include <cosmos/fs/DirEntry.hxx>
#include <cosmos/fs/FileStatus.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/items/fcntl.hxx>
#include <clues/items/items.hxx>
#include <clues/SystemCallItem.hxx>
#include <clues/types.hxx>

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

	auto fd() const {
		return m_fd;
	}

protected: // functions

	void processValue(const Tracee &) override;

protected: // data

	cosmos::FileNum m_fd;

	std::optional<FDInfo> m_info; ///< filled if FormatFlag::FD_INFO is set.

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
		EACCESS          = AT_EACCESS, ///< only used with faccessat2
		NO_AUTOMOUNT     = AT_NO_AUTOMOUNT, ///< only used with fstatat()
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

/// The mode parameter in access().
class CLUES_API AccessModeParameter :
		public item::ValueInParameter {
public:
	explicit AccessModeParameter() :
			item::ValueInParameter{"check", "access check"} {
	}

	std::string str() const override;

	std::optional<cosmos::fs::AccessChecks> checks() const {
		return m_checks;
	}

protected: // functions

	void processValue(const Tracee&) override;

protected: // data

	std::optional<cosmos::fs::AccessChecks> m_checks;
};

/// File access mode passed e.g. to open(), chmod().
class CLUES_API FileModeParameter :
		public item::ValueInParameter {
public:

	FileModeParameter() :
			item::ValueInParameter{"mode", "file-mode"} {
	}

	std::string str() const override;

	auto mode() const {
		return m_mode;
	}

protected: // functions

	void processValue(const Tracee&) override {
		m_mode = cosmos::FileMode{valueAs<cosmos::ModeT>()};
	}

protected: // data

	cosmos::FileMode m_mode;
};

/// The stat structure used in stat() & friends.
class CLUES_API StatParameter :
		public PointerOutValue {
public: // functions
	explicit StatParameter() :
			PointerOutValue{"stat", "struct stat"} {
	}

	std::string str() const override;

	const auto& status() const {
		return *m_stat;
	}

protected: // functions

	void updateData(const Tracee &proc) override;

	/// Whether this is related to one of the OLDSTAT family of system calls.
	bool isOldStat() const;

	/// Whether this is related to one of the STAT64 family of system calls.
	bool isStat64() const;

	/// Whether this is related to one of the STAT family of system calls.
	bool isRegularStat() const;

protected: // data

	std::optional<cosmos::FileStatus> m_stat;
};

/// A range of directory entries from getdents().
class CLUES_API DirEntries :
		public PointerOutValue {
public: // types

	struct Entry {
		uint64_t inode;
		/* for getdents() this is an unsigned type, for getdents64()
		 * it is a signed type. I guess using a signed type (off_t)
		 * makes sense. */
		int64_t offset;
		std::string_view name;
		cosmos::DirEntry::Type type;
	};

public: // functions

	explicit DirEntries() :
			PointerOutValue{"dirent", "struct linux_dirent"}
	{}

	std::string str() const override;

	const auto& entries() const {
		return m_entries;
	}

protected: // functions

	void updateData(const Tracee &proc) override;

	/// Parses the dirent structures from m_buffer.
	/**
	 * to make up for differently sized structures when dealing with
	 * 32-bit emulation we need a template type here.
	 **/
	template <typename DIRENT>
	void parseEntries32(const size_t bytes);

	/// Parses the dirent structures for getdents64().
	void parseEntries64(const size_t bytes);

protected: // data

	std::vector<Entry> m_entries;
	///! the raw buffer backing m_entries
	std::unique_ptr<char[]> m_buffer;
};

} // end ns
