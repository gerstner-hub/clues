#ifndef CLUES_REGISTERSET_HXX
#define CLUES_REGISTERSET_HXX

// C++
#include <iosfwd>

// Linux
#include <sys/uio.h> // struct iov
#include <sys/procfs.h> // the elf_greg_t & friends are in here
// unclear what the official headers for these are ...
#include <elf.h> // NT_PRSTATUS is in here

// cosmos
#include "cosmos/errors/UsageError.hxx"

// clues
#include "clues/Arch.hxx"

using namespace cosmos;

namespace clues
{

/**
 * \brief
 *	Holds a set of registers for the hosts CPU architecture
 * \details
 * 	This type is able to hold data for each of the host's CPU specific
 * 	registers.
 **/
class RegisterSet
{
public: // types

	//! an integer being able to hold a word for the current architecture
	typedef elf_greg_t Word;

public: // functions

	explicit RegisterSet(bool zero_init = false)
	{
		if( zero_init )
		{
			for( size_t reg = 0; reg < numRegisters(); reg++ )
			{
				m_regs[reg] = 0;
			}
		}
	}

	/**
	 * \brief
	 * 	Enters the necessary data in \c iov for doing a ptrace system
	 * 	call PTRACE_GETREGSET
	 **/
	void fillIov(struct iovec &iov)
	{
		iov.iov_len = sizeof(m_regs);
		iov.iov_base = &m_regs;
	}

	//! the type to pass to PTRACE_GETREGSET for obtaining the gp-registers
	static int registerType() { return NT_PRSTATUS; }

	//! returns the active system call number on entry to a syscall
	Word syscall() const { return m_regs[SYSCALL_NR_REG]; }

	//! returns the system call result on exit from a syscall
	Word syscallRes() const { return m_regs[SYSCALL_RES_REG]; }

	/**
	 * \brief
	 * 	Returns the content of the given system call parameter
	 * 	register
	 * \details
	 * 	The current architecture can pass up to SYSCALL_MAX_PARS
	 * 	registers to system calls. To get the n'th system call
	 * 	parameter register content pass (n - 1) as \c number (i.e.
	 * 	counting starts at zero).
	 **/
	Word syscallParameter(const size_t number) const
	{
		if( number >= SYSCALL_MAX_PARS )
		{
			cosmos_throw( UsageError("invalid system call parameter nr.") );
		}

		return m_regs[SYSCALL_PAR_REGISTER[number]];
	}

	/**
	 * \brief
	 * 	Returns the content of the given register number
	 * \details
	 * 	The exact order of registers is platform and architecture
	 * 	dependent. See sys/regs.h for the index offsets for the
	 * 	various registers.
	 *
	 * 	You can also use getRegisterName() to get a friendly name for
	 * 	a register number.
	 **/
	Word registerValue(const size_t number) const
	{
		if( number >= numRegisters() )
		{
			cosmos_throw( UsageError("invalid register nr.") );
		}

		return m_regs[number];
	}

	//! returns the number of registers available in a RegisterSet
	static size_t numRegisters()
	{
		return ELF_NGREG;
	}

protected: // data

	/**
	 * \brief
	 * 	The raw data structure holding the registers
	 * \details
	 * 	it's actually just an array of words with each word
	 * 	representing a register. It doesn't necessarily match the
	 * 	hardware register order but is a data structure used in the
	 * 	kernel when system calls are performed.
	 *
	 * 	The offsets of what register is where are found in reg.h. The
	 * 	data type is in elf.h (?)
	 *
	 * 	Regarding the ABI for system calls on different architectures
	 * 	man(2) syscall is helpful.
	 **/
	elf_gregset_t m_regs;
};

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::RegisterSet &rs);

#endif // inc. guard

