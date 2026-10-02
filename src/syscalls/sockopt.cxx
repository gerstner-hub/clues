// clues
#include <clues/dso_export.h>
#include <clues/logger.hxx>
#include <clues/private/syscall_factories.hxx>
#include <clues/syscalls/socketcall.hxx>
#include <clues/syscalls/sockopt.hxx>
#include <clues/Tracee.hxx>

namespace clues {

using OptLevel = item::SockOptLevel::Level;

void GetSockOptSystemCall::updateFDTracking(const Tracee &proc) {
	using Level = item::SockOptLevel;

	auto track_pid_fd = [this, &proc]() -> void {
		auto &sc = dynamic_cast<
			const GetFileDescSockOptSystemCall&>(*this);

		const auto fd = *sc.optval.value();

		FDInfo info{FDInfo::PID_FD, fd};
		info.mode = cosmos::OpenMode::READ_WRITE;
		info.flags = cosmos::OpenFlags{cosmos::OpenFlag::CLOEXEC};
		trackFD(proc, std::move(info));
	};

	switch (level.level()) {
		case Level::SOCKET: {
			using Option = item::SockOptName::SocketOption;
			switch (std::get<Option>(name.option())) {
				case Option::PEERPIDFD: return track_pid_fd();
				default: break;
			}
			break;
		}
		default: break;
	}
}

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
		case PASSPIDFD:
		case PASSRIGHTS:
		case REUSEADDR:
		case REUSEPORT:
		case RXQ_OVFL:
		case SELECT_ERR_QUEUE:
		case TIMESTAMP:
		case TIMESTAMPNS:
		case NO_CHECK:
		case PREFER_BUSY_POLL:
		case TXREHASH:
		case RCVMARK:
		case RCVPRIORITY:
		case INQ:
		case WIFI_STATUS:
		case NOFCS:
		case ZEROCOPY:
		case RIGHTS_NOTRUNC:
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
		case BUSY_POLL_BUDGET:
		case RESERVE_MEM:
		case CNX_ADVICE:
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
		case BINDTOIFINDEX:
			return create_call.operator()<
				SocketCall_GetInterfaceIndexSockOpt, GetInterfaceIndexSockOptSystemCall,
				SocketCall_SetInterfaceIndexSockOpt, SetInterfaceIndexSockOptSystemCall>();
		case ATTACH_FILTER:
			/* for getsockopt() the option is called
			 * SO_GET_FILTER, but it's the same literal
			 * constant. We need two different types here
			 * due to differing ABI semantics */
			return create_call.operator()<
				SocketCall_GetFilterSockOpt, GetFilterSockOptSystemCall,
				SocketCall_SetClassicBPFSockOpt, SetClassicBPFSockOptSystemCall>();
		case ATTACH_REUSEPORT_CBPF:
			/* this one does not have a getter like ATTACH_FILTER */
			return create_call.operator()<
				void, void,
				SocketCall_SetClassicBPFSockOpt, SetClassicBPFSockOptSystemCall>();
		case ATTACH_BPF:
		case ATTACH_REUSEPORT_EBPF:
			/* no GET exists for these */
			return create_call.operator()<
				void, void,
				SocketCall_SetFileDescSockOpt, SetFileDescSockOptSystemCall>();
		case PEERPIDFD:
			/* no SET exists for these */
			return create_call.operator()<
				SocketCall_GetFileDescSockOpt, GetFileDescSockOptSystemCall,
				void, void>();
		case BUF_LOCK:
			return create_call.operator()<
				SocketCall_GetBufLockSockOpt, GetBufLockSockOptSystemCall,
				SocketCall_SetBufLockSockOpt, SetBufLockSockOptSystemCall>();
		case LINGER:
			return create_call.operator()<
				SocketCall_GetLingerSockOpt, GetLingerSockOptSystemCall,
				SocketCall_SetLingerSockOpt, SetLingerSockOptSystemCall>();
		case RCVTIMEO_OLD:
		case SNDTIMEO_OLD:
			return create_call.operator()<
				SocketCall_GetTimeValSockOpt, GetTimeValSockOptSystemCall,
				SocketCall_SetTimeValSockOpt, SetTimeValSockOptSystemCall>();
		case RCVTIMEO_NEW:
		case SNDTIMEO_NEW:
			return create_call.operator()<
				SocketCall_GetTimeSpecSockOpt, GetTimeSpecSockOptSystemCall,
				SocketCall_SetTimeSpecSockOpt, SetTimeSpecSockOptSystemCall>();
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
		case NETNS_COOKIE:
			return create_call.operator()<
				SocketCall_GetNetNSCookieSockOpt, GetNetNSCookieSockOptSystemCall>();
		case ERROR:
			/* it is not allowed to SET the errno */
			return create_call.operator()<
				SocketCall_GetErrorSockOpt, GetErrorSockOptSystemCall>();
		/* these take no option argument at all, use unknown option
		 * type for them */
		case DETACH_BPF:
		case DETACH_REUSEPORT_BPF: return create_unknown_call();
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
