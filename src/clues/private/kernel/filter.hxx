#pragma once

namespace clues {

extern "C" {

/// Variant of sruct sock_fprog for 64-bit <-> 32-bit cross ABI tracing.
struct sock_fprog32 {
	unsigned short len;
	// 32-bit pointer
	uint32_t filter;
};

} // end extern

} // end ns
