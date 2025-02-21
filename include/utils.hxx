#pragma once

// C++
#include <string>
#include <iosfwd>

// cosmos
#include <cosmos/error/errno.hxx>

// clues
#include <clues/types.hxx>

namespace clues {

/// Returns a short errno label like `ENOENT` for the given errno integer.
const char* get_errno_label(const cosmos::Errno err);

const char* get_state_label(const TraceState state);

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::TraceState &state);
