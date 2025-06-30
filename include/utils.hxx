#pragma once

// C++
#include <set>
#include <vector>

// cosmos
#include <cosmos/error/errno.hxx>
#include <cosmos/fs/types.hxx>
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

/// Returns the currently open file descriptors according to /proc/<pid>/fd
/**
 * This function can throw a cosmos::ApiError in case the process is no longer
 * accessible in /proc.
 **/
std::set<cosmos::FileNum> get_currently_open_fds(const cosmos::ProcessID pid);

/// Obtain detailed information about currently open file descriptors according to /proc/<pid>/fd.
/**
 * This function can throw a cosmos::ApiError in case the process is no longer
 * accessible in /proc.
 **/
std::vector<FDInfo> get_fd_infos(const cosmos::ProcessID pid);

} // end ns
