#pragma once

// cosmos
#include <cosmos/error/errno.hxx>

// clues
#include <clues/types.hxx>

namespace clues {

/// Returns a short errno label like `ENOENT` for the given errno integer.
const char* get_errno_label(const cosmos::Errno err);
/// Returns a short errno label for extended KernelErrno codes.
const char* get_kernel_errno_label(const KernelErrno err);

} // end ns
