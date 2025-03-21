#pragma once

// C++
#include <cstdlib>

// cosmos
#include <cosmos/compiler.hxx>

// Linux
#ifdef COSMOS_X86
// provides offsets into the ptrace register data structure
// does only seem to exist on x86/64, on ARM it's simply 18 GP registers from
// 0 to 18.
// sys/user.h also has a structure for that instead of elf_gregset_t. But
// elf_gregset_t is based on the structure and the array is easier to access
// for our purposes.
#	include <sys/reg.h>
#elif defined(COSMOS_ARM)
// for arm some R* constants are found in this header. The constants are
// actually just names for the numbers 0 ... 15 but it is still somewhat
// clearer to read this way.
#	include <sys/ucontext.h>
#endif

/*
 * this header provides facilities to abstract some of the architectural
 * differences regarding registers & friends
 */

namespace clues {

/*
 * orig_eax saves the original system call number during a system call,
 * because the actual eax is used to return the system call result.
 *
 * On 64 bit the register used is correspondingly rax.
 *
 * The syscall ABI is documented in man(2) syscall
 */

#ifdef COSMOS_X86_64
constexpr int SYSCALL_MAX_PARS = 6;
constexpr int SYSCALL_NR_REG   = ORIG_RAX;
constexpr int SYSCALL_RES_REG  = RAX;
constexpr int SYSCALL_PAR1_REG = RDI;
constexpr int SYSCALL_PAR2_REG = RSI;
constexpr int SYSCALL_PAR3_REG = RDX;
constexpr int SYSCALL_PAR4_REG = R10;
constexpr int SYSCALL_PAR5_REG = R8;
constexpr int SYSCALL_PAR6_REG = R9;
#elif defined(COSMOS_I386)
constexpr int SYSCALL_MAX_PARS = 6;
constexpr int SYSCALL_NR_REG   = ORIG_EAX;
constexpr int SYSCALL_RES_REG  = EAX;
constexpr int SYSCALL_PAR1_REG = EBX;
constexpr int SYSCALL_PAR2_REG = ECX;
constexpr int SYSCALL_PAR3_REG = EDX;
constexpr int SYSCALL_PAR4_REG = ESI;
constexpr int SYSCALL_PAR5_REG = EDI;
constexpr int SYSCALL_PAR6_REG = EBP;
#elif defined(COSMOS_ARM)
constexpr int SYSCALL_MAX_PARS = 7;
constexpr int SYSCALL_NR_REG   = REG_R7;
constexpr int SYSCALL_RES_REG  = REG_R0;
constexpr int SYSCALL_PAR1_REG = REG_R0;
constexpr int SYSCALL_PAR2_REG = REG_R1;
constexpr int SYSCALL_PAR3_REG = REG_R2;
constexpr int SYSCALL_PAR4_REG = REG_R3;
constexpr int SYSCALL_PAR5_REG = REG_R4;
constexpr int SYSCALL_PAR6_REG = REG_R5;
constexpr int SYSCALL_PAR7_REG = REG_R6;
#define HAVE_PAR7_REG
#else
#	error "not yet supported architecture"
#endif

/// Register table for system call parameters.
/**
 * To get the register offset to the register for system call parameter N
 * access SYSCALL_PAR_REGISTER[N]
 **/
static constexpr int SYSCALL_PAR_REGISTER[] = {
	SYSCALL_PAR1_REG,
	SYSCALL_PAR2_REG,
	SYSCALL_PAR3_REG,
	SYSCALL_PAR4_REG,
	SYSCALL_PAR5_REG,
	SYSCALL_PAR6_REG,
	// only few architectures have a 7th system call parameter register
#ifdef HAVE_PAR7_REG
	SYSCALL_PAR7_REG,
#endif
};

/// Returns a human readable name for the given platform specific register number in a RegisterSet.
const char* get_register_name(const size_t nr);

} // end ns
