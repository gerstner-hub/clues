// clues
#include <clues/logger.hxx>
#include <clues/syscalls/net.hxx>
#include <clues/syscalls/sockopt.hxx>
#include <clues/SystemCallInfo.hxx>
#include <clues/Tracee.hxx>

// cosmos
#include <cosmos/net/unix/aux.hxx>

namespace clues {

namespace {

void add_socket_info(const Tracee &proc, FDInfo &info) {
	std::optional<item::SocketDomainEnum> domain;
	std::optional<item::SocketTypeEnum> type;
	/*
	 * there is no simple /proc information about this, so the most direct
	 * approach is to obtain the actual FD from the Tracee and to call
	 * getsockopt on it.
	 */
	proc.snatchFD(info.fd, [&domain, &type](const cosmos::FileDescriptor fd) {
		socklen_t len = sizeof(int);
		int out;
		if (::getsockopt(cosmos::to_integral(fd.raw()), SOL_SOCKET, SO_DOMAIN, &out, &len) == 0) {
			domain = item::SocketDomainEnum{out};
		}
		len = sizeof(int);
		if (::getsockopt(cosmos::to_integral(fd.raw()), SOL_SOCKET, SO_TYPE, &out, &len) == 0) {
			type = item::SocketTypeEnum{out};
		}
	});

	info.sock_domain = domain;
	info.sock_type = type;
}

FDInfo make_socket_info(const cosmos::FileNum fd,
		const item::SocketType::Flags flags,
		const std::optional<item::SocketDomain::Domain> domain = {},
		const std::optional<item::SocketType::Type> type = {}) {
	FDInfo info{FDInfo::Type::SOCKET, fd};
	info.flags.emplace();
	using enum item::SocketType::Flag;
	if (flags[NONBLOCK]) {
		info.flags->set(cosmos::OpenFlag::NONBLOCK);
	}
	if (flags[CLOEXEC]) {
		info.flags->set(cosmos::OpenFlag::CLOEXEC);
	}

	info.sock_domain = domain;
	info.sock_type = type;

	return info;
}

} // end anon ns

void SocketSystemCall::updateFDTracking(const Tracee &proc) {
	auto info = make_socket_info(new_fd.fd(),
			type.flags(),
			domain.domain(),
			type.type());
	trackFD(proc, std::move(info));
}

void SocketPairSystemCall::updateFDTracking(const Tracee &proc) {
	for (auto fd: pair.pair()) {
		auto info = make_socket_info(fd,
			type.flags(),
			domain.domain(),
			type.type());
		trackFD(proc, std::move(info));
	}
}

void AcceptSystemCall::updateFDTracking(const Tracee &proc) {
	const auto &info_map = proc.fdInfoMap();

	if (auto it = info_map.find(sockfd.fd()); it != info_map.end()) {
		const auto &fd_info = it->second;
		const auto domain = fd_info.sock_domain;
		const auto type = fd_info.sock_type;
		auto info = make_socket_info(new_fd.fd(),
				flags.flags(), domain, type);
		if (!info.sock_domain || !info.sock_type) {
			/*
			 * we have no info about the type of the socket we
			 * accepted on, so try to obtain the info from the
			 * Tracee directly.
			 * TODO: also add the info to `fd_info`.
			 */
			add_socket_info(proc, info);
		}
		trackFD(proc, std::move(info));
	} else {
		auto info = make_socket_info(new_fd.fd(), flags.flags());
		add_socket_info(proc, info);
		trackFD(proc, std::move(info));
	}
}

void RecvMsgSystemCall::updateFDTracking(const Tracee &proc) {
	if (msg.controlData().empty())
		return;

	const auto header_opt = msg.header();

	for (const auto &ctrl: *header_opt) {
		if (const auto type = cosmos::as_unix_message(ctrl); !type)
			continue;
		else if (type != cosmos::UnixMessage::RIGHTS)
			continue;

		cosmos::UnixRightsMessage rights;
		rights.deserialize(ctrl);
		cosmos::UnixRightsMessage::FileNumVector fds;
		rights.takeFDs(fds);

		for (const auto fd: fds) {
			track(cosmos::FileNum{fd}, proc);
		}
	}
}

void RecvMsgSystemCall::track(const cosmos::FileNum fd, const Tracee &proc) {
	/*
	 * we need to lookup the Tracee's file descriptors to find out about
	 * the type of FD that was received.
	 */
	try {
		for (auto &info: get_fd_infos(proc.pid())) {
			if (info.fd == fd) {
				trackFD(proc, std::move(info));
				return;
			}
		}
	} catch (...) {
		/*
		 * Probably the tracee died unexpectedly. Let's use an unknown
		 * FD type in this case.
		 */
		trackFD(proc, FDInfo{FDInfo::UNKNOWN, fd});
		return;
	}

	LOG_WARN("unable to lookup file descriptor passed via UNIX domain socket");
}

} // end ns
