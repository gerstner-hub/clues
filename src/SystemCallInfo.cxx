// cosmos
#include <cosmos/error/RuntimeError.hxx>

// clues
#include <clues/SystemCallInfo.hxx>
#include <clues/sysnrs/all.hxx>

namespace clues {

SystemCallInfo::SystemCallInfo() :
	m_generic{SystemCallNr::UNKNOWN} {
}

void SystemCallInfo::updateSysNr() {
	if (!isEntry()) {
		throw cosmos::RuntimeError{"bad SysCallInfo state"};
	}

	using Arch = cosmos::ptrace::Arch;
	const auto native = entryInfo()->syscallNr();

	switch (arch()) {
		case Arch::X86_64: {
			if (isX32()) {
				m_abi = ABI::X32;
				const auto x32_syscall = SystemCallNrX32{native};
				m_native = x32_syscall;
				m_generic = to_generic(x32_syscall);
			} else {
				m_abi = ABI::X86_64;
				const auto x64_syscall = SystemCallNrX64{native};
				m_native = x64_syscall;
				m_generic = to_generic(x64_syscall);
			}
			break;
		}
		case Arch::I386: {
			const auto i386_syscall = SystemCallNrI386{native};
			m_native = i386_syscall;
			m_generic = to_generic(i386_syscall);
			m_abi = ABI::I386;
			break;
		}
		case Arch::AARCH64: {
			const auto aarch64_syscall = SystemCallNrAARCH64{native};
			m_native = aarch64_syscall;
			m_generic = to_generic(aarch64_syscall);
			m_abi = ABI::AARCH64;
			break;
		}
	default:
		throw cosmos::RuntimeError("unsupported ARCH");
		break;
	}
}

} // end ns
