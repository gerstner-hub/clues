// C++
#include <iostream>

// Clues
#include <clues/utils.hxx>
#include <clues/errnodb.h> // generated

// cosmos
#include <cosmos/utils.hxx>

namespace clues {

const char* get_errno_label(const cosmos::Errno err) {
	const auto num = cosmos::to_integral(err);
	if (num < 0 || num >= ERRNO_NAMES_MAX)
		return "E<INVALID>";

	return ERRNO_NAMES[num];
}

} // end ns
