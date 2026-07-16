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
	SuccessResult(const ItemCfg &cfg = {}) :
			ReturnValue{
				ItemCfg{
					ItemType::RETVAL,
					cfg.label.value_or("success"),
					cfg.desc.value_or("")}} {
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
