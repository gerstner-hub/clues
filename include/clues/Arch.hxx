#ifndef CLUES_ARCH_HXX
#define CLUES_ARCH_HXX

// Linux
#include <sys/reg.h> // provides offsets into the register data structure

/*
 * this header provides facilities to abstract some of the architectural
 * differences regarding registers & friends
 */

namespace clues
{

inline bool isx86_64()
{
#ifdef __x86_64__
	return true;
#else
	return false;
#endif
}

inline bool isx86()
{
#ifdef __i386__
	return true;
#else
	return false;
#endif
}

inline bool isi386()
{
	return isx86();
}

/*
 * orig_eax saves the original system call number during a system call,
 * because the actual eax is used to return the system call result.
 *
 * On 64 bit the register used is rax.
 *
 * The syscall ABI is documented in man(2) syscall
 */

#ifdef __x86_64__
static const int SYSCALL_MAX_PARS = 6;
static const int SYSCALL_NR_REG = ORIG_RAX;
static const int SYSCALL_RES_REG = RAX;
static const int SYSCALL_PAR1_REG = RDI;
static const int SYSCALL_PAR2_REG = RSI;
static const int SYSCALL_PAR3_REG = RDX;
static const int SYSCALL_PAR4_REG = R10;
static const int SYSCALL_PAR5_REG = R8;
static const int SYSCALL_PAR6_REG = R9;
#elif defined(__i386__)
static const int SYSCALL_MAX_PARS = 6;
static const int SYSCALL_NR_REG = ORIG_EAX;
static const int SYSCALL_RES_REG = EAX;
static const int SYSCALL_PAR1_REG = EBX;
static const int SYSCALL_PAR2_REG = ECX;
static const int SYSCALL_PAR3_REG = EDX;
static const int SYSCALL_PAR4_REG = ESI;
static const int SYSCALL_PAR5_REG = EDI;
static const int SYSCALL_PAR6_REG = EBP;
#else
#	error "not yet supported architecture"
#endif

static const int MAX_SYSCALL_PARS = 6;

/**
 * \brief
 * 	register table for system call parameters
 * \details
 * 	To get the register offset to the register for system call parameter N
 * 	access SYSCALL_PAR_REGISTER[N]
 **/
static const int SYSCALL_PAR_REGISTER[] =
{
	SYSCALL_PAR1_REG,
	SYSCALL_PAR2_REG,
	SYSCALL_PAR3_REG,
	SYSCALL_PAR4_REG,
	SYSCALL_PAR5_REG,
	SYSCALL_PAR6_REG
};

/**
 * \brief
 * 	Returns a human readable name for the given platform specific
 * 	register number in a register set
 **/
const char* getRegisterName(const size_t nr);

} // end ns

#endif // inc. guard

