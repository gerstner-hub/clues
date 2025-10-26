#pragma once

// cosmos
#include <cosmos/proc/ptrace.hxx>

// clues
#include <clues/sysnrs/types.hxx>
#include <clues/types.hxx>

namespace clues {

/// Extended ptrace system call state information.
/**
 * This type additionally contains the type safe generic SystemCallNr and
 * SystemCallnrVariant denoting the ABI-specific system call nr.
 *
 * Furthermore the exact ABI the system call is for is determined and
 * available via abi().
 **/
class CLUES_API SystemCallInfo :
		public cosmos::ptrace::SyscallInfo {
public: // functions

	SystemCallInfo();

	auto sysNr() const {
		return m_generic;
	}

	SystemCallNrVariant nativeSysNr() const {
		return m_native;
	}

	/// Update m_generic and m_native based on the raw system call nr.
	/**
	 * This call is only valid upon system call entry. The raw system call
	 * number will be translated into `m_generic` and `m_native`.
	 **/
	void updateSysNr();

	ABI abi() const {
		return m_abi;
	}

protected: // data

	SystemCallNr m_generic;
	SystemCallNrVariant m_native;
	ABI m_abi = ABI::UNKNOWN;
};

} // end ns
