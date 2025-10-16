#pragma once

// cosmos
#include <cosmos/proc/ptrace.hxx>

// clues
#include <clues/sysnrs/types.hxx>

namespace clues {

/// Extended ptrace system call state information.
/**
 * This type additionally contains the type safe generic SystemCallNr and
 * SystemCallnrVariant denoting the ABI-specific system call nr.
 **/
class CLUES_API SystemCallInfo :
		public cosmos::ptrace::SyscallInfo {
public: // functions
	auto sysNr() const {
		return m_generic;
	}

	SystemCallNrVariant nativeSysNr() const {
		return m_native;
	}

	void updateSysNr();

protected: // data

	SystemCallNr m_generic;
	SystemCallNrVariant m_native;
};

} // end ns
