#pragma once

#include <stdint.h>

namespace clues {

/// native struct iovec* as used in the kernel ABI
struct iovec {
	uintptr_t iov_base;
	size_t iov_len;
};

/// variant of struct iovec* as used in 64-bit <-> 32-bit cross ABI tracing.
struct iovec32 {
	uint32_t iov_base;
	uint32_t iov_len;
};

} // end ns
