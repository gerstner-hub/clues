#pragma once

// cosmos
#include <cosmos/proc/types.hxx>

namespace clues::format {

/// Returns a string like "SIGINT (Interrupted)" for the given signal number.
std::string signal(const cosmos::SignalNr signal);

/// Returns a string like "{SIGINT (Interrupted), SIGQUIT (Quit), ...}".
std::string signal_set(const sigset_t &set);

/// Returns a string like "SA_NOCLDSTOP|SA_NOCLDWAIT|..."
std::string saflags(const int flags);

} // end ns
