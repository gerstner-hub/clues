#pragma once

// cosmos
#include <cosmos/proc/ptrace.hxx>

// clues
#include <clues/dso_export.h>
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

	AnySystemCallNr nativeSysNr() const {
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

	Word argAsWord(const size_t nr) const {
		if (!isEntry()) {
			throw cosmos::UsageError{"Not an EntryInfo"};
		}

		const auto args = entryInfo()->args();

		if (nr >= args.size()) {
			throw cosmos::UsageError{"Bad arg nr."};
		}

		/* the ptrace API always uses a 64-bit system call argument
		 * type here, while our `Word` is based on the native ABI and
		 * can be 32-bits in size */
		return static_cast<Word>(args[nr]);
	}

protected: // data

	SystemCallNr m_generic;
	AnySystemCallNr m_native;
	ABI m_abi = ABI::UNKNOWN;
};

} // end ns
