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

} // end ns
