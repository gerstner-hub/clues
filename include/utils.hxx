#pragma once

// C++
#include <array>
#include <functional>
#include <optional>
#include <set>
#include <vector>

// cosmos
#include <cosmos/compiler.hxx>
#include <cosmos/error/errno.hxx>
#include <cosmos/fs/types.hxx>
#include <cosmos/proc/ptrace.hxx>

// clues
#include <clues/fwd.hxx>
#include <clues/sysnrs/fwd.hxx>
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

/// Returns the default ABI for this system.
constexpr ABI get_default_abi() {
	if (cosmos::arch::X32)
		return ABI::X32;
	else if (cosmos::arch::X86_64)
		return ABI::X86_64;
	else if (cosmos::arch::I386)
		return ABI::I386;
	else if (cosmos::arch::AARCH64)
		return ABI::AARCH64;

	return ABI::UNKNOWN;
}

#ifdef COSMOS_X86_64
constexpr inline size_t SUPPORTED_ABIS = 3;
#elif defined(COSMOS_I386)
constexpr inline size_t SUPPORTED_ABIS = 1;
#elif defined(COSMOS_AARCH64)
constexpr inline size_t SUPPORTED_ABIS = 1;
#else
#error "no configuration yet for this platform"
#endif

CLUES_API const char* get_abi_label(const ABI abi);

/// Returns a list of ABIs supported on the current platform.
CLUES_API std::array<ABI, SUPPORTED_ABIS> get_supported_abis();

/// Returns whether the given ABI is supported on the current platform.
inline bool is_supported_abi(const ABI abi) {
	for (const auto supported: get_supported_abis()) {
		if (supported == abi)
			return true;
	}

	return false;
}

/// Parse a proc file of the given process using the given functor.
/**
 * This function performs a line-wise read of the file found in
 * /proc/<pid>/<subpath> and calls `parser` for each line. When the function
 * returns `true` then parsing ends and the function call returns, otherwise
 * further lines will be passed to `parser` until the end of file is
 * encountered.
 *
 * If opening or reading the file fails then a cosmos::RuntimeError is thrown.
 **/
void CLUES_API parse_proc_file(const cosmos::ProcessID pid, const std::string_view subpath, std::function<bool(const std::string&)> parser);

/// Parse proc file of the given Tracee.
/**
 * This is just a shorthand to parse a proc file of the given tracee.
 **/
void CLUES_API parse_proc_file(const Tracee &tracee, const std::string_view subpath, std::function<bool(const std::string&)> parser);

} // end ns
