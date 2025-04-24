#pragma once

// cosmos
#include <cosmos/error/errno.hxx>
#include <cosmos/proc/ptrace.hxx>

// clues
#include <clues/types.hxx>

namespace clues {

/// Returns a short errno label like `ENOENT` for the given errno integer.
const char* get_errno_label(const cosmos::Errno err);
/// Returns a short errno label for extended KernelErrno codes.
const char* get_kernel_errno_label(const KernelErrno err);
/// Returns a string label for the given event
const char* get_ptrace_event_str(const cosmos::ptrace::Event event);

} // end ns
