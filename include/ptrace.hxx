#pragma once

// C++
#include <optional>

// libcosmos
#include <cosmos/proc/ptrace.hxx>
#include <cosmos/proc/Signal.hxx>
#include <cosmos/proc/types.hxx>

// clues
#include <clues/dso_export.h>

namespace cosmos {
	class InputMemoryRegion;
};

namespace clues::ptrace {

/// Continues a traced process, optionally delivering `signal`.
void CLUES_API cont(const cosmos::ProcessID proc,
		const cosmos::ContinueMode mode, const std::optional<cosmos::Signal> signal = {});

/// Return the event message for the current stop event.
/**
 * Interpretation of this differs between different stop contexts.
 **/
unsigned long CLUES_API get_event_msg(const cosmos::ProcessID proc);

/// Interrupt the tracee.
void CLUES_API interrupt(const cosmos::ProcessID proc);

/// Seize a tracee.
void CLUES_API seize(const cosmos::ProcessID proc);

/// Set tracing options for the given tracee.
void CLUES_API set_options(const cosmos::ProcessID proc, const cosmos::TraceFlags flags);

/// Retrieve a set of register from the given tracee.
void CLUES_API get_register_set(const cosmos::ProcessID, const cosmos::RegisterType type, cosmos::InputMemoryRegion &iovec);

/// Detach from the given tracee.
void CLUES_API detach(const cosmos::ProcessID proc);

long CLUES_API get_data(const cosmos::ProcessID proc, const long *addr);

} // end ns
