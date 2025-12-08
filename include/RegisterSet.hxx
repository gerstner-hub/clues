#pragma once

// C++
#include <iosfwd>
#include <variant>

// Linux
#include <sys/uio.h> // struct iov

// cosmos
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/error/UsageError.hxx>
#include <cosmos/io/iovector.hxx>
#include <cosmos/proc/ptrace.hxx>
#include <cosmos/types.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/regs/traits.hxx>
#include <clues/sysnrs/fwd.hxx>
#include <clues/types.hxx>

namespace clues {

/// Holds a set of registers for the given ABI.
/**
 * This type holds and manages data for each of the ABI specific RegisterData
 * types.
 **/
template <ABI abi>
class RegisterSet {
public: // types

	/// This is the concrete type holding the raw register data for this ABI.
	using ABIRegisterData = RegisterDataTraits<abi>::type;
	static constexpr auto ABI = abi;
	using register_t = ABIRegisterData::register_t;

public: // functions

	explicit RegisterSet(const cosmos::no_init_t &) {
	}

	RegisterSet() {
		m_regs.clear();
	}

	/// Prepares `iov` for doing a ptrace system call of type ptrace::Request::GETREGSET.
	void fillIov(cosmos::InputMemoryRegion &iov) {
		// This makes sure the RegisterData wrapper is not bigger than
		// the expected amount of register data.
		static_assert(sizeof(m_regs) == sizeof(typename ABIRegisterData::register_t) * ABIRegisterData::NUM_REGS);
		iov.setBase(&m_regs);
		iov.setLength(sizeof(m_regs));
	}

	/// Verify data received from a ptrace system call of type ptrace::Request::GETREGSET.
	void iovFilled(const cosmos::InputMemoryRegion &iov) {
		if (iov.getLength() < sizeof(m_regs)) {
			throw cosmos::RuntimeError{"received incomplete register set"};
		}
	}

	/// The type to pass to ptrace::Request::GETREGSET for obtaining the general purpose registers.
	static constexpr cosmos::ptrace::RegisterType registerType() {
		return cosmos::ptrace::RegisterType::GENERAL_PURPOSE;
	}

	/// Returns the ABI-specific system call number on entry to a syscall.
	auto abiSyscallNr() const { return m_regs.syscallNr(); }

	/// Returns the generic SystemCallNr on entry to a syscall.
	SystemCallNr syscallNr() const {
		return to_generic(abiSyscallNr());
	}

	/// Returns the system call result on exit from a syscall
	register_t syscallRes() const { return m_regs.syscallRes(); }

	/// Returns the content of the given system call parameter register.
	/**
	 * The current ABI can pass up to ABIRegisterData::NUM_SYSCALL_PARS
	 * registers to system calls. To get the n'th system call parameter
	 * register content, pass (n - 1) as `number` (i.e. counting starts at
	 * zero).
	 **/
	register_t syscallParameter(const size_t number) const {
		auto pars = m_regs.syscallPars();
		if (number >= pars.size()) {
			throw cosmos::UsageError{"invalid system call parameter nr."};
		}

		return pars[number];
	}

	/// Provides access to the raw RegisterData based data structure.
	auto& raw() const {
		return m_regs;
	}

protected: // data

	/// The raw data structure holding the ABI specific register data.
	ABIRegisterData m_regs;
};

/// A variant to hold any of the ABI-specific RegisterSet types.
using AnyRegisterSet = std::variant<
	RegisterSet<ABI::I386>,
	RegisterSet<ABI::X86_64>,
	RegisterSet<ABI::X32>,
	RegisterSet<ABI::AARCH64>>;

} // end ns

template <clues::ABI abi>
CLUES_API std::ostream& operator<<(std::ostream &o, const clues::RegisterSet<abi> &rs);
