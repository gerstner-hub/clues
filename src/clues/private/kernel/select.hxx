#pragma once

// C
#include <stdint.h>

// clues
#include <clues/private/kernel/types.hxx>

namespace clues {

extern "C" {

struct select_arg_struct {
	uint32_t nfds;
	compat_uptr_t readset;
	compat_uptr_t writeset;
	compat_uptr_t exceptset;
	compat_uptr_t timeval;
};

} // end extern

} // end ns
