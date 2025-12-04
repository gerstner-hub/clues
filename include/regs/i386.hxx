#pragma once

// clues
#include <clues/regs/RegisterData.hxx>
#include <clues/sysnrs/i386.hxx>

namespace clues {

/// Native register data for the I386 32-bit X86 ABI.
/**
 * The kernel definition of this is found in `user_regs_struct` in
 * x86/include/asm/user_32.h (last seen in linux 6.12).
 **/
struct RegisterDataI386 :
		public RegisterData<uint32_t, 6> {
public: // constants

	static constexpr auto NUM_REGS = 17;

public: // functions

	SystemCallNrI386 syscallNr() const {
		return SystemCallNrI386{orig_eax};
	}

	auto syscallRes() const {
		return eax;
	}

	SystemCallPars syscallPars() const {
		return SystemCallPars{
			ebx, ecx, edx, esi, edi, ebp
		};
	}

	void clear() {
		cosmos::zero_object(*this);
	}

	/// Returns the human-readable names for the registers in the order found in `array()`
	static auto registerNames() {
		return std::array<const char*, NUM_REGS>({
			"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax",
			"xds", "xes", "xfs", "xgs", "orig_eax", "eip", "xcs",
			"eflags", "esp", "xss"
		});
	}

	/// Returns a std::array offering index-based access to registers.
	auto array() const {
		return std::array<register_t, NUM_REGS>({
			ebx, ecx, edx, esi, edi, ebp, eax, xds,
			xes, xfs, xgs, orig_eax, eip, xcs, eflags,
			esp, xss
		});
	}

public: // data

        register_t ebx;
        register_t ecx;
        register_t edx;
        register_t esi;
        register_t edi;
        register_t ebp;
        register_t eax;
        register_t xds;
        register_t xes;
        register_t xfs;
        register_t xgs;
        register_t orig_eax;
        register_t eip;
        register_t xcs;
        register_t eflags;
        register_t esp;
        register_t xss;
};

} // end ns
