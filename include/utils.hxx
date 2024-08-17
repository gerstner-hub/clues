#pragma once

// C++
#include <string>

// cosmos
#include <cosmos/error/errno.hxx>

namespace clues {

/// Returns a short errno label like `ENOENT` for the given errno integer.
const char* get_errno_label(const cosmos::Errno err);

} // end ns
