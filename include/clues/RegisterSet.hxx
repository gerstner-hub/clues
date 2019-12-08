#ifndef TUXTRACE_REGISTERSET_HXX
#define TUXTRACE_REGISTERSET_HXX

// C++
#include <iosfwd>

// Linux
#include <sys/uio.h> // struct iov
#include <sys/procfs.h> // the elf_greg_t & friend are in here
// unclear what the official headers for these are ...
#include <elf.h> // NT_PRSTATUS is in here

// clues
#include "clues/Arch.hxx"
#include "clues/UsageError.hxx"

namespace tuxtrace
{

/**
 * \brief
 *	Holds a set of registers for the architecture in question
 **/
class RegisterSet
{
public: // types

	//! an integer being able to hold a word for the current architecture
	typedef elf_greg_t Word;

public: // functions


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
	 * 	The current architecture can pass up to MAX_SYSCALL_PARS
	 * 	registers to system calls. To get the n'th system call
	 * 	parameter register content pass (n - 1) as \c number (i.e.
	 * 	counting starts at zero).
	 **/
	Word syscallParameter(const size_t number) const
	{
		if( number >= MAX_SYSCALL_PARS )
		{
			clues_throw( UsageError("invalid system call parameter nr.") );
		}

		return m_regs[SYSCALL_PAR_REGISTER[number]];
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

std::ostream& operator<<(std::ostream &o, const tuxtrace::RegisterSet &res);

#endif // inc. guard

