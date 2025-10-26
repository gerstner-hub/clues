#pragma once

// C++
#include <optional>
#include <set>
#include <vector>

// cosmos
#include <cosmos/error/errno.hxx>
#include <cosmos/fs/types.hxx>
#include <cosmos/proc/ptrace.hxx>

// clues
#include <clues/types.hxx>
#include <clues/sysnrs/fwd.hxx>

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

/// Returns the SystemCallNr for the given system call name, if it exists.
CLUES_API std::optional<SystemCallNr> lookup_system_call(
		const std::string_view name);

/// Returns whether the given ABI is default ABI for this system.
/**
 * The `abi` is checked against the compile time architecture to determine
 * whether this is the default native ABI, or not.
 *
 * For example ABI::I386 in a tracer compiled tor X86_64 would not be
 * the default ABI.
 **/
CLUES_API bool is_default_abi(const ABI abi);

CLUES_API const char* get_abi_label(const ABI abi);

} // end ns
