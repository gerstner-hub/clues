#pragma once

// cosmos
#include <cosmos/utils.hxx>

// clues
#include <clues/syscalls/sockopt.hxx>

namespace clues {

/* system call factory functions used by SystemCallDB & friends */

CLUES_DEFAULT_VISIBILITY_ON;

using IsSocketCall = cosmos::NamedBool<struct is_socket_call_t, false>;

SystemCallPtr create_socket_opt_syscall(const int optname, const SockOptType type, const IsSocketCall is_socket_call = IsSocketCall{false});

/// Factory function to create a concrete PrCtlSystemCall() instance.
SystemCallPtr create_prctl_syscall(const Tracee&, const SystemCallInfo &info);

SystemCallPtr create_socket_call_syscall(const Tracee &tracee, const SystemCallInfo &info);

SystemCallPtr create_getsockopt_syscall(const Tracee &, const SystemCallInfo &info);
SystemCallPtr create_setsockopt_syscall(const Tracee &, const SystemCallInfo &info);

CLUES_DEFAULT_VISIBILITY_OFF;

}
