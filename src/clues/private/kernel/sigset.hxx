#pragma once

namespace clues {

extern "C" {

/// combined sigset_t* & size_t for pselect6() & friends.
struct sigset_argpack {
	void *sigset_p;
	size_t size;
};

/* for 64 <-> 32 bit cross tracing */
struct sigset_argpack32{
	uint32_t sigset_p;
	uint32_t size;
};

} // end extern

} // end ns
