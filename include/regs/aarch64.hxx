#pragma once

// C++
#include <limits>

// clues
#include <clues/regs/RegisterData.hxx>
#include <clues/sysnrs/aarch64.hxx>

namespace clues {

/// Native register data for the aarch64 ABI.
struct RegisterDataAARCH64 :
		public RegisterData<uint64_t, 6> {
public: // constants

	static constexpr auto NUM_REGS = 34;

	SystemCallNrAARCH64 syscallNr() const {
		// w8 (32-bit wide register access) contains the system call
		// number, thus make sure the upper 4 bytes are ignored to be
		// on the safe side.
		return SystemCallNrAARCH64{regs[8] & std::numeric_limits<uint32_t>::max()};
	}

	auto syscallRes() const {
		return regs[0];
	}

	SystemCallPars syscallPars() const {
		return SystemCallPars{
			regs[0], regs[1], regs[2], regs[3], regs[4], regs[5]
		};
	}

	void clear() {
		cosmos::zero_object(*this);
	}

	static auto registerNames() {
		return std::array<const char*, NUM_REGS>({
			"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
			"x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
			"x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
			"sp", "pc", "pstate"
		});
	}

	auto array() const {
		return std::array<register_t, NUM_REGS>({
			regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[8],
			regs[9], regs[10], regs[11], regs[12], regs[13], regs[14], regs[15], regs[16],
			regs[17], regs[18], regs[19], regs[20], regs[21], regs[22], regs[23], regs[24],
			regs[25], regs[26], regs[27], regs[28], regs[29], regs[30],
			sp, pc, pstate
		});
	}

public: // functions

public: // data

	// this is based on `struct user_pt_regs` found in ptrace.h for arm64.

	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
};

} // end ns
