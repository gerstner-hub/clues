#pragma once

// C++
#include <iosfwd>

// Linux
#include <sys/uio.h> // struct iov
#include <sys/procfs.h> // the elf_greg_t & friends are in here
// unclear what the official headers for these are ...
#include <elf.h> // NT_PRSTATUS is in here

// cosmos
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/error/UsageError.hxx>
#include <cosmos/io/iovector.hxx>
#include <cosmos/proc/ptrace.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/Arch.hxx>
#include <clues/types.hxx>

// generated
#include <clues/syscallnrs.h>

namespace clues {

/// Holds a set of registers for the host's CPU architecture.
/**
 * This type is able to hold data for each of the host's CPU specific
 * registers.
 **/
class RegisterSet {
public: // types

	/// An integer being able to hold a word for the current architecture.
	using Word = elf_greg_t;
	using ZeroInit = cosmos::NamedBool<struct zero_init_t, false>;

public: // functions

	explicit RegisterSet(const ZeroInit zero_init = ZeroInit{false}) {
		if (zero_init) {
			for (size_t reg = 0; reg < numRegisters(); reg++) {
				m_regs[reg] = 0;
			}
		}
	}

	/// Prepares `iov` for doing a ptrace system call TraceRequest::GETREGSET.
	void fillIov(cosmos::InputMemoryRegion &iov) {
		iov.setBase(&m_regs);
		iov.setLength(sizeof(m_regs));
	}

	/// Verify data received from a ptrace system call TraceRequest::GETREGSET.
	void iovFilled(const cosmos::InputMemoryRegion &iov) {
		if (iov.getLength() < sizeof(m_regs)) {
			cosmos_throw(cosmos::RuntimeError("received incomplete register set"));
		}
	}

	/// The type to pass to TraceRequest::GETREGSET for obtaining the general purpose registers.
	static constexpr cosmos::RegisterType registerType() { return cosmos::RegisterType::GENERAL_PURPOSE; }

	/// Returns the active system call number on entry to a syscall.
	SystemCallNr syscall() const { return SystemCallNr{m_regs[SYSCALL_NR_REG]}; }

	/// Returns the system call result on exit from a syscall
	Word syscallRes() const { return m_regs[SYSCALL_RES_REG]; }

	/// Returns the content of the given system call parameter register.
	/**
	 * The current architecture can pass up to SYSCALL_MAX_PARS registers
	 * to system calls. To get the n'th system call parameter register
	 * content, pass (n - 1) as \c number (i.e. counting starts at zero).
	 **/
	Word syscallParameter(const size_t number) const {
		if (number >= SYSCALL_MAX_PARS) {
			cosmos_throw (cosmos::UsageError("invalid system call parameter nr."));
		}

		return m_regs[SYSCALL_PAR_REGISTER[number]];
	}

	/// Returns the content of the given register number.
	/**
	 * The exact order of registers is platform and architecture
	 * dependent. See sys/regs.h for the index offsets for the various
	 * registers.
	 * 
	 * You can also use getRegisterName() to get a friendly name for a
	 * register number.
	 **/
	Word registerValue(const size_t number) const {
		if (number >= numRegisters()) {
			cosmos_throw(cosmos::UsageError("invalid register nr."));
		}

		return m_regs[number];
	}

	/// Returns the number of registers available in a RegisterSet.
	static constexpr size_t numRegisters() {
		return ELF_NGREG;
	}

protected: // data

	/// The raw data structure holding the registers.
	/**
	 * This is actually just an array of words with each word representing
	 * a register. It doesn't necessarily match the hardware register
	 * order but is a data structure used in the kernel when system calls
	 * are performed.
	 * 
	 * The offsets of what register is where, are found in reg.h. The data
	 * type is in elf.h (?).
	 * 
	 * Regarding the ABI for system calls on different architectures
	 * man(2) syscall is helpful.
	 **/
	elf_gregset_t m_regs;
};

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::RegisterSet &rs);
