#pragma once

// C++
#include <cstdint>

namespace clues {

extern "C" {

/// Original Linux stat data structure for SystemCallNr::OLDSTAT, OLDLSTAT and OLDFSTAT.
struct timespec32 {
	uint32_t tv_sec;
	uint32_t tv_nsec;
};

} // end extern

} // end ns
