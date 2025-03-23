#pragma once

// clues
#include <clues/SystemCallItem.hxx>

namespace clues::item {

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
	explicit FileDescriptor(
		const Type type,
		const bool at_semantics = false) :
			SystemCallItem{type, "fd", "file descriptor"},
			m_at_semantics{at_semantics} {
	}

	std::string str() const override;

protected: // data

	const bool m_at_semantics = false;
};

/// A file descriptor input parameter.
class FileDescriptorParameter :
		public FileDescriptor {
public: // functions
	explicit FileDescriptorParameter(const bool at_semantics = false) :
			FileDescriptor{Type::PARAM_IN, at_semantics} {
	}
};

/// A file descriptor return value with added errno semantics.
class CLUES_API FileDescriptorReturnValue :
		public FileDescriptor {
public: // functions
	explicit FileDescriptorReturnValue() :
			FileDescriptor{Type::RETVAL, false} {
	}

protected: // functions

	std::string str() const override;
};

} // end ns
