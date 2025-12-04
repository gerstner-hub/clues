#pragma once

// C++
#include <array>

// cosmos
#include <cosmos/memory.hxx> // for use in derived classes


namespace clues {

/// Base class for ABI specific register data.
/**
 * This family of data structures relates to the PTRACE_GETREGSET operation.
 * Specializations of this type exist for each supported ABI.
 *
 * Regarding the different system call ABIs `man(2) syscall` is helpful.
 *
 * The exact data structures returned from the kernel are not well documented
 * and can be looked up in the kernel headers. We are duplicating these data
 * structures in these classes, since we need to be able to support multiple
 * ABIs in the same binary (e.g. I386 emulation on X86_64), and the
 * compilation environment provides us with no way to obtain the definitions
 * for ABIs/architectures other than our own.
 *
 * `REGISTER_T` relates to the primitive type stored in a register.
 * `NUM_SYSCALL_PARS` defines the maximum number of system call parameters
 * that can be passed on the target ABI.
 *
 * By contract each derived type needs to implement a set of functions like:
 *
 * - syscallNr(): returns the ABI specific system call number.
 * - syscallRes(): returns the content of the system call return value
 *   register.
 * - syscallPars(): returns a std::array containing the contents of the system
 *   call parameter registers, in order of use.
 * - clear(): zeroes all register content.
 **/
template <typename REGISTER_T, size_t _NUM_SYSCALL_PARS>
struct RegisterData {
public: // constants

	static constexpr auto NUM_SYSCALL_PARS = _NUM_SYSCALL_PARS;

public: // types

	using register_t = REGISTER_T;
	/// This type is used to return the values of all system call parameter values in order of occurrence.
	using SystemCallPars = std::array<register_t, NUM_SYSCALL_PARS>;
};

} // end ns
