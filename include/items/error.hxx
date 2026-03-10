#pragma once

// clues
#include <clues/items/items.hxx>

namespace clues::item {

/// An always-success return value.
/**
 * Since errors are reported separately in PTRACE_GET_SYSCALL_INFO, there are
 * a lot of system calls that can otherwise only return 0 as a legit value.
 * This type exists to model this.
 **/
class CLUES_API SuccessResult :
		public ReturnValue {
public:
	SuccessResult(
		const std::string_view short_label = "success",
		const std::string_view long_label = {}) :
			ReturnValue{short_label, long_label} {
	}

	std::string str() const override;

	/// Checks whether the success value actually is a success value.
	/**
	 * Should the return value for some reason not be zero, as expected,
	 * then this function returns `false`.,
	 **/
	bool valid() const {
		return m_val == Word::ZERO;
	}
};

} // end ns
