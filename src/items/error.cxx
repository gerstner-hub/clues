// cosmos
#include <cosmos/formatting.hxx>

// clues
#include <clues/items/error.hxx>
#include <clues/utils.hxx>

namespace clues::item {

std::string ErrnoResult::str() const {
	if (const auto kernerr = kernelErrcode(); kernerr != std::nullopt) {
		return cosmos::sprintf("%d (%s)", valueAs<int>(), get_kernel_errno_label(*kernerr));
	} else if (const auto err = errcode(); err != std::nullopt) {
		return cosmos::sprintf("%d (%s)", valueAs<int>(), get_errno_label(*err));
	} else {
		return cosmos::sprintf("%d", valueAs<int>());
	}
}

std::optional<cosmos::Errno> ErrnoResult::errcode() const {
	if (const auto res = valueAs<int>(); res >= m_first_valid) {
		return std::nullopt;
	} else {
		return cosmos::Errno{res < 0 ? -res : res};
	}
}

std::optional<KernelErrno> ErrnoResult::kernelErrcode() const {
	if (!errcode())
	       return {};

	auto code = *errcode();

	auto kernel_code = KernelErrno{cosmos::to_integral(code)};

	if (kernel_code >= KernelErrno::RESTART_SYS &&
			kernel_code <= KernelErrno::RESTART_RESTARTBLOCK) {
		return kernel_code;
	}

	return {};
}

} // end ns
