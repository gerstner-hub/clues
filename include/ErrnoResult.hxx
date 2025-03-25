#pragma once

// C++
#include <optional>

// cosmos
#include <cosmos/error/errno.hxx>

// clues
#include <clues/types.hxx>

namespace clues {

/// An errno system call result.
/**
 * When a system call fails then the kernel provides a dedicated errno result
 * via PTRACE_GET_SYSCALL_INFO. This type wraps the information provided by
 * the kernel.
 *
 * During tracing error codes can appear that aren't usually visible in user
 * space. These are modeled via the dedicated KernelErrno type. For this
 * reason only std::optional returns are provided.
 **/
class CLUES_API ErrnoResult {
public: // functions

	explicit ErrnoResult(const cosmos::Errno code);

	std::string str() const;

	std::optional<cosmos::Errno> errorCode() const {
		return m_errno;
	}

	std::optional<KernelErrno> kernelErrorCode() const {
		return m_kernel_errno;
	}

	bool hasErrorCode() const {
		return m_errno != std::nullopt;
	}

	bool hasKernelErrorCode() const {
		return m_kernel_errno != std::nullopt;
	}

protected: // data

	std::optional<cosmos::Errno> m_errno;
	std::optional<KernelErrno> m_kernel_errno;
};

} // end ns
