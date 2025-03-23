#pragma once

// cosmos
#include <cosmos/proc/types.hxx>

namespace clues::format {

/// Returns a string like "SIGINT (Interrupted)" for the given signal number.
std::string signal(const cosmos::SignalNr signal);

} // end ns
