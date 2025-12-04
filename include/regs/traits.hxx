#pragma once

// clues
#include <clues/regs/i386.hxx>
#include <clues/regs/x86_64.hxx>
#include <clues/types.hxx>

namespace clues {

/// Traits which will be overridden by template specializations per ABI.
template <ABI abi>
struct RegisterDataTraits {
	/// the proper RegisterData type for this ABI.
	/**
	 * This primary template should never be instantiated, it only serves
	 * a documentation purpose.
	 **/
	using type = std::nullptr_t;
};

template <>
struct RegisterDataTraits<ABI::I386> {
	using type = RegisterDataI386;
};

template <>
struct RegisterDataTraits<ABI::X86_64> {
	using type = RegisterDataX64;
};

template <>
struct RegisterDataTraits<ABI::X32> {
	using type = RegisterDataX32;
};

} // end ns
