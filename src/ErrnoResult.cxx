// cosmos
#include <cosmos/formatting.hxx>
#include <cosmos/utils.hxx>

// clues
#include <clues/ErrnoResult.hxx>
#include <clues/utils.hxx>

namespace clues {

ErrnoResult::ErrnoResult(const cosmos::Errno code) {
	const auto kernel_code = KernelErrno{cosmos::to_integral(code)};

	if (kernel_code >= KernelErrno::RESTART_SYS &&
			kernel_code <= KernelErrno::RESTART_RESTARTBLOCK) {
		m_kernel_errno = kernel_code;
	} else {
		m_errno = code;
	}
}

std::string ErrnoResult::str() const {

	if (m_errno) {
		const auto code = *m_errno;
		return cosmos::sprintf("%d (%s)",
				cosmos::to_integral(code), get_errno_label(code));
	} else {
		const auto code = *m_kernel_errno;
		return cosmos::sprintf("%d (%s)",
				cosmos::to_integral(code), get_kernel_errno_label(code));
	}
}

} // end ns
