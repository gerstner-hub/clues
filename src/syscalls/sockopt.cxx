// clues
#include <clues/dso_export.h>
#include <clues/logger.hxx>
#include <clues/private/sockopt.hxx>
#include <clues/syscalls/socketcall.hxx>
#include <clues/syscalls/sockopt.hxx>
#include <clues/Tracee.hxx>

namespace clues {

using OptLevel = item::SockOptLevel::Level;

SystemCallPtr create_get_socket_opt_syscall(const int optname,
		const IsSocketCall is_socket_call) {
	using enum item::SockOptName::SocketOption;

	switch (item::SockOptName::SocketOption{optname}) {
	case ACCEPTCONN:
	case DONTROUTE:
	case BROADCAST:
	case BSDCOMPAT:
	case DEBUG:
	case KEEPALIVE:
	case LOCK_FILTER:
	case OOBINLINE:
		return is_socket_call ?
			std::make_shared<SocketCall_GetBoolSockOpt>() :
			std::make_shared<GetBoolSockOptSystemCall>();
	default: break;
	}

	return nullptr;
}

SystemCallPtr create_set_socket_opt_syscall(const int optname,
		const IsSocketCall is_socket_call) {
	using enum item::SockOptName::SocketOption;

	switch (item::SockOptName::SocketOption{optname}) {
	case ACCEPTCONN:
	case DONTROUTE:
	case BROADCAST:
	case BSDCOMPAT:
	case DEBUG:
	case KEEPALIVE:
	case LOCK_FILTER:
	case OOBINLINE:
		return is_socket_call ?
			std::make_shared<SocketCall_SetBoolSockOpt>() :
			std::make_shared<SetBoolSockOptSystemCall>();
	default: break;
	}

	return nullptr;
}

SystemCallPtr create_getsockopt_syscall(const Tracee &,
		const SystemCallInfo &info) {
	const auto optlevel = OptLevel{(int)info.entryInfo().value().args()[1]};
	const int optname = info.entryInfo().value().args()[2];

	switch (optlevel) {
		case OptLevel::SOCKET: {
			if (auto sc = create_get_socket_opt_syscall(optname); sc) {
				return sc;
			}
		}
		default: break;
	}

	LOG_WARN("unknown getsockopt() level/optname encountered. falling back to generic type.");
	return std::make_shared<GetUnknownSockOptSystemCall>();
}

SystemCallPtr create_setsockopt_syscall(const Tracee &,
		const SystemCallInfo &info) {
	const auto optlevel = OptLevel{(int)info.entryInfo().value().args()[1]};
	const int optname = info.entryInfo().value().args()[2];

	switch (optlevel) {
		case OptLevel::SOCKET: {
			if (auto sc = create_set_socket_opt_syscall(optname); sc) {
				return sc;
			}
		}
		default: break;
	}

	LOG_WARN("unknown setsockopt() level/optname encountered. falling back to generic type.");
	return std::make_shared<SetUnknownSockOptSystemCall>();
}

} // end ns
