// cosmos
#include <cosmos/error/RuntimeError.hxx>

// clues
#include <clues/SystemCallInfo.hxx>
#include <clues/sysnrs/all.hxx>

namespace clues {

void SystemCallInfo::updateSysNr() {
	if (!isEntry()) {
		throw cosmos::RuntimeError{"bad SysCallInfo state"};
	}

	using Arch = cosmos::ptrace::Arch;
	const auto native = entryInfo()->syscallNr();

	switch (arch()) {
		case Arch::X86_64: {
			// TODO: this could also be X32 ABI
			const auto x64_syscall = SystemCallNrX64{native};
			m_native = x64_syscall;
			m_generic = to_generic(x64_syscall);
			break;
		}
		case Arch::I386: {
			const auto i386_syscall = SystemCallNrI386{native};
			m_native = i386_syscall;
			m_generic = to_generic(i386_syscall);
			break;
		}
	default:
		throw cosmos::RuntimeError("unsupported ARCH");
		break;
	}
}

} // end ns
