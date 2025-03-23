// C++
#include <iostream>

// clues
#include <clues/utils.hxx>

// generated
#include <clues/errnodb.h>

// cosmos
#include <cosmos/utils.hxx>

namespace clues {

const char* get_errno_label(const cosmos::Errno err) {
	const auto num = cosmos::to_integral(err);
	if (num < 0 || num >= ERRNO_NAMES_MAX)
		return "E<INVALID>";

	return ERRNO_NAMES[num];
}

const char* get_kernel_errno_label(const KernelErrno err) {
	switch (err) {
	case KernelErrno::RESTART_SYS: return "RESTART_SYS";
	case KernelErrno::RESTART_NOINTR: return "RESTART_NOINTR";
	case KernelErrno::RESTART_NOHAND: return "RESTART_NOHAND";
	case KernelErrno::RESTART_RESTARTBLOCK: return "RESTART_RESTARTBLOCK";
	default: return "?INVALID?";
	}
}

} // end ns
