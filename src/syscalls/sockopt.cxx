// clues
#include <clues/dso_export.h>
#include <clues/logger.hxx>
#include <clues/private/syscall_factories.hxx>
#include <clues/syscalls/socketcall.hxx>
#include <clues/syscalls/sockopt.hxx>
#include <clues/Tracee.hxx>

namespace clues {

using OptLevel = item::SockOptLevel::Level;

SystemCallPtr create_socket_opt_syscall(
		const int optname,
		const SockOptType type,
		const IsSocketCall is_socket_call) {

	auto create_unknown_call = [type, is_socket_call]() -> SystemCallPtr {
		if (type == SockOptType::GET) {
			return is_socket_call ?
				std::make_shared<SocketCall_GetUnknownSockOpt>() :
				std::make_shared<GetUnknownSockOptSystemCall>();
		} else {
			return is_socket_call ?
				std::make_shared<SocketCall_SetUnknownSockOpt>() :
				std::make_shared<SetUnknownSockOptSystemCall>();
		}
	};

	auto create_call = [type, is_socket_call, create_unknown_call]<
			class SOCKETCALL_GET_SC,
			class GET_SC,
			class SOCKETCALL_SET_SC=void,
			class SET_SC=void>() -> SystemCallPtr {
		if (type == SockOptType::GET) {
			constexpr bool is_void = std::is_void_v<SOCKETCALL_GET_SC>;
			if constexpr (is_void) {
				return create_unknown_call();
			}

			if constexpr (!is_void) {
				return is_socket_call ?
					std::make_shared<SOCKETCALL_GET_SC>() :
					std::make_shared<GET_SC>();
			}
		} else {
			constexpr bool is_void = std::is_void_v<SOCKETCALL_SET_SC>;
			if (is_void) {
				return create_unknown_call();
			}

			if constexpr (!is_void) {
				return is_socket_call ?
					std::make_shared<SOCKETCALL_SET_SC>() :
					std::make_shared<SET_SC>();
			}
		}
	};

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
		case TIMESTAMP:
		case TIMESTAMPNS:
			return create_call.operator()<SocketCall_GetBoolSockOpt, GetBoolSockOptSystemCall, SocketCall_SetBoolSockOpt, SetBoolSockOptSystemCall>();
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
			return create_call.operator()<
				SocketCall_GetIntSockOpt, GetIntSockOptSystemCall,
				SocketCall_SetIntSockOpt, SetIntSockOptSystemCall>();
		case BINDTODEVICE:
		case PEERSEC:
			return create_call.operator()<
				SocketCall_GetStringSockOpt, GetStringSockOptSystemCall,
				SocketCall_SetStringSockOpt, SetStringSockOptSystemCall>();
		case PEERCRED:
			/* only GET is meaningfully supported here */
			return create_call.operator()<
				SocketCall_GetPeerCredSockOpt, GetPeerCredSockOptSystemCall>();
		case ATTACH_FILTER:
			/* for getsockopt() the option is called
			 * SO_GET_FILTER, but it's the same literal
			 * constant. We need two different types here
			 * due to differing ABI semantics */
			return create_call.operator()<
				SocketCall_GetFilterSockOpt, GetFilterSockOptSystemCall,
				SocketCall_AttachFilterSockOpt, AttachFilterSockOptSystemCall>();
		case LINGER:
			return create_call.operator()<
				SocketCall_GetLingerSockOpt, GetLingerSockOptSystemCall,
				SocketCall_SetLingerSockOpt, SetLingerSockOptSystemCall>();
		/* makes no sense to call SET on the following */
		case DOMAIN:
			return create_call.operator()<
				SocketCall_GetDomainSockOpt, GetDomainSockOptSystemCall>();
		case TYPE:
			return create_call.operator()<
				SocketCall_GetTypeSockOpt, GetTypeSockOptSystemCall>();
		case PROTOCOL:
			return create_call.operator()<
				SocketCall_GetProtocolSockOpt, GetProtocolSockOptSystemCall>();
		case ERROR:
			/* it is not allowed to SET the errno */
			return create_call.operator()<
				SocketCall_GetErrorSockOpt, GetErrorSockOptSystemCall>();
		/* these take no option argument at all, use unknown option
		 * type for them */
		case DETACH_BPF: return create_unknown_call();
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
			if (auto sc = create_socket_opt_syscall(optname, SockOptType::GET); sc) {
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
			if (auto sc = create_socket_opt_syscall(optname, SockOptType::SET); sc) {
				return sc;
			}
		}
		default: break;
	}

	LOG_WARN("unknown setsockopt() level/optname encountered. falling back to generic type.");
	return std::make_shared<SetUnknownSockOptSystemCall>();
}

} // end ns
