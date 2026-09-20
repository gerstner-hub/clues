// clues
#include <clues/dso_export.h>
#include <clues/logger.hxx>
#include <clues/private/syscall_factories.hxx>
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
		case BROADCAST:
		case BSDCOMPAT:
		case DEBUG:
		case DONTROUTE:
		case KEEPALIVE:
		case LOCK_FILTER:
		case OOBINLINE:
		case PASSCRED:
		case PASSSEC:
		case REUSEADDR:
		case REUSEPORT:
		case RXQ_OVFL:
		case SELECT_ERR_QUEUE:
			return is_socket_call ?
				std::make_shared<SocketCall_GetBoolSockOpt>() :
				std::make_shared<GetBoolSockOptSystemCall>();
		case BUSY_POLL:
		case INCOMING_CPU:
		case INCOMING_NAPI_ID:
		case MARK:
		case PEEK_OFF:
		case PRIORITY:
		case RCVBUF:
		case RCVBUFFORCE:
		case RCVLOWAT:
		case SNDBUF:
		case SNDBUFFORCE:
		case SNDLOWAT:
			return is_socket_call ?
				std::make_shared<SocketCall_GetIntSockOpt>() :
				std::make_shared<GetIntSockOptSystemCall>();
		/* these take no option argument at all, use unknown option
		 * type for them */
		case DETACH_BPF:
			return is_socket_call ?
				std::make_shared<SocketCall_GetUnknownSockOpt>() :
				std::make_shared<GetUnknownSockOptSystemCall>();
		default: break;
	}

	return nullptr;
}

SystemCallPtr create_set_socket_opt_syscall(const int optname,
		const IsSocketCall is_socket_call) {
	using enum item::SockOptName::SocketOption;

	/*
	 * Note that we are also listing option names here which semantically
	 * don't allow modification. Since applications might wrongly attempt
	 * to do so it is still helpful to be able to trace these cases.
	 */

	switch (item::SockOptName::SocketOption{optname}) {
		case ACCEPTCONN:
		case BROADCAST:
		case BSDCOMPAT:
		case DEBUG:
		case DONTROUTE:
		case KEEPALIVE:
		case LOCK_FILTER:
		case OOBINLINE:
		case PASSCRED:
		case PASSSEC:
		case REUSEADDR:
		case REUSEPORT:
		case RXQ_OVFL:
		case SELECT_ERR_QUEUE:
			return is_socket_call ?
				std::make_shared<SocketCall_SetBoolSockOpt>() :
				std::make_shared<SetBoolSockOptSystemCall>();
		case BUSY_POLL:
		case INCOMING_CPU:
		case INCOMING_NAPI_ID:
		case MARK:
		case PEEK_OFF:
		case PRIORITY:
		case RCVBUF:
		case RCVBUFFORCE:
		case RCVLOWAT:
		case SNDBUF:
		case SNDBUFFORCE:
		case SNDLOWAT:
			return is_socket_call ?
				std::make_shared<SocketCall_SetIntSockOpt>() :
				std::make_shared<SetIntSockOptSystemCall>();
		/* these take no option argument at all, use unknown option
		 * type for them */
		case DETACH_BPF:
			return is_socket_call ?
				std::make_shared<SocketCall_SetUnknownSockOpt>() :
				std::make_shared<SetUnknownSockOptSystemCall>();
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
