#pragma once

// C++
#include <cstdint>

namespace clues {

extern "C" {

struct timespec32 {
	uint32_t tv_sec;
	uint32_t tv_nsec;
};

struct timeval32 {
	int32_t tv_sec;
	int32_t tv_usec;
};

} // end extern

} // end ns
