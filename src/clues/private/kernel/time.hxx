#pragma once

// C++
#include <cstdint>

namespace clues {

extern "C" {

struct timespec32 {
	uint32_t tv_sec;
	uint32_t tv_nsec;
};

/* useful for calling TIME64 variants of system calls on I386 ABI */
struct timespec64 {
	int64_t tv_sec;
	int64_t tv_nsec;
};

struct timeval32 {
	int32_t tv_sec;
	int32_t tv_usec;
};

} // end extern

} // end ns
