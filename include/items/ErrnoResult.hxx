#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/error/errno.hxx>

// clues
#include <clues/SystemCallItem.hxx>

namespace clues::item {

/// An errno system call result.
/**
 * Often system call return values are dual natured: a negative return value
 * denotes an errno, a positive return value denotes some kind of identifier
 * like a PID, for example.
 * 
 * `first_valid` therefore denotes the smallest integer value that is still
 * to be interpreted as a data item, while any smaller value denotes an error
 * number.
 * TODO: maybe we should model dual natured return values like: PIDReturnValue
 * that outputs an errno in case of error, and alike, like is currently done
 * in FileDescriptorReturnValue.
 **/
class CLUES_API ErrnoResult :
		public ReturnValue {
public: // functions
	ErrnoResult(
		const int first_valid = 0,
		const char *short_label = "errno",
		const char *long_label = nullptr) :
			ReturnValue{short_label, long_label},
			m_first_valid{first_valid} {
	}

	std::string str() const override;

	std::optional<cosmos::Errno> errcode() const;

	std::optional<KernelErrno> kernelErrcode() const;

protected: // data

	int m_first_valid;
};

} // end ns
