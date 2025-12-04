#pragma once

// clues
#include <clues/regs/RegisterData.hxx>
#include <clues/sysnrs/x32.hxx>
#include <clues/sysnrs/x64.hxx>

namespace clues {

/// Native register data for the X86_64 and X32 ABIs.
/**
 * The register set is the same for both ABIs, but the system call numbers
 * differ. Hence this is templated.
 **/
template <typename SYSCALLNR>
struct RegisterDataX86_64_T :
		public RegisterData<uint64_t, 6> {
public: // constants

	static constexpr auto NUM_REGS = 27;

public: // functions

	auto syscallRes() const {
		return rax;
	}

	SYSCALLNR syscallNr() const {
		return SYSCALLNR{orig_rax};
	}

	SystemCallPars syscallPars() const {
		return SystemCallPars{
			rdi, rsi, rdx, r10, r8, r9
		};
	}

	void clear() {
		cosmos::zero_object(*this);
	}

	static auto registerNames() {
		return std::array<const char*, NUM_REGS>({
			"r15", "r14", "r13", "r12", "rbp", "rbx", "r11",
			"r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
			"orig_rax", "rip", "cs", "flags", "rsp", "ss",
			"fs_base", "gs_base", "ds", "es", "fs", "gs"
		});
	}

	auto array() const {
		return std::array<register_t, NUM_REGS>({
			r15, r14, r13, r12, rbp, rbx, r11,
			r10, r9, r8, rax, rcx, rdx, rsi,
			orig_rax, rip, cs, flags, rsp, ss,
			fs_base, gs_base, ds, es, fs, gs
		});
	}

public: // data

        register_t r15;
        register_t r14;
        register_t r13;
        register_t r12;
        register_t rbp;
        register_t rbx;
        register_t r11;
        register_t r10;
        register_t r9;
        register_t r8;
        register_t rax;
        register_t rcx;
        register_t rdx;
        register_t rsi;
        register_t rdi;
        register_t orig_rax;
        register_t rip;
        register_t cs;
        register_t flags;
        register_t rsp;
        register_t ss;
        register_t fs_base;
        register_t gs_base;
        register_t ds;
        register_t es;
        register_t fs;
        register_t gs;
};

struct RegisterDataX64 :
	public RegisterDataX86_64_T<SystemCallNrX64> {

};

struct RegisterDataX32 :
	public RegisterDataX86_64_T<SystemCallNrX32> {
};

} // end ns
