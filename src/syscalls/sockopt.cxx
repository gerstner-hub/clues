// clues
#include <clues/dso_export.h>
#include <clues/logger.hxx>
#include <clues/syscalls/sockopt.hxx>
#include <clues/Tracee.hxx>

namespace clues {

using OptLevel = item::SockOptLevel::Level;

namespace {

SystemCallPtr create_get_socket_opt_syscall(const int optname) {
	using enum item::SockOptName::SocketOption;

	switch (item::SockOptName::SocketOption{optname}) {
	case ACCEPTCONN:
	case DONTROUTE:
		return std::make_shared<GetBoolSockOptSystemCall>();
	default: break;
	}

	return nullptr;
}

} // end anon ns

SystemCallPtr create_getsockopt_syscall(const Tracee &, const SystemCallInfo &info) {
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

} // end ns
