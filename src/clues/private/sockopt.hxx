#pragma once

// cosmos
#include <cosmos/utils.hxx>

// clues
#include <clues/syscalls/sockopt.hxx>

namespace clues {

/* helpers which are reused by socketcall */

CLUES_DEFAULT_VISIBILITY_ON;

using IsSocketCall = cosmos::NamedBool<struct is_socket_call_t, false>;

SystemCallPtr create_set_socket_opt_syscall(const int optname, const IsSocketCall is_socket_call = IsSocketCall{false});
SystemCallPtr create_get_socket_opt_syscall(const int optname, const IsSocketCall is_socket_call = IsSocketCall{false});

CLUES_DEFAULT_VISIBILITY_OFF;

}
