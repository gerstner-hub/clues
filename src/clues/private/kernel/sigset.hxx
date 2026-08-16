#pragma once

// C
#include <stddef.h>
#include <stdint.h>

// clues
#include <clues/private/kernel/types.hxx>

namespace clues {

extern "C" {

/// combined sigset_t* & size_t for pselect6() & friends.
struct sigset_argpack {
	void *sigset;
	size_t size;
};

/* for 64 <-> 32 bit cross tracing */
struct sigset_argpack32{
	compat_uptr_t sigset;
	uint32_t size;
};

} // end extern

} // end ns
