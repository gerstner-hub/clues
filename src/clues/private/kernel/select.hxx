#pragma once

namespace clues {

extern "C" {

struct select_arg_struct {
	uint32_t nfds;
	uint32_t readset_p;
	uint32_t writeset_p;
	uint32_t exceptset_p;
	uint32_t timeval_p;
};

} // end extern

} // end ns
