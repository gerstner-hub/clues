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

FDInfo make_socket_info(const cosmos::FileNum fd,
		const item::SocketType::Flags flags) {
	FDInfo info{FDInfo::Type::SOCKET, fd};
	info.flags.emplace();
	using enum item::SocketType::Flag;
	if (flags[NONBLOCK]) {
		info.flags->set(cosmos::OpenFlag::NONBLOCK);
	}
	if (flags[CLOEXEC]) {
		info.flags->set(cosmos::OpenFlag::CLOEXEC);
	}

	return info;
}

} // end anon ns

void SocketSystemCall::updateFDTracking(const Tracee &proc) {
	auto info = make_socket_info(new_fd.fd(), type.flags());
	trackFD(proc, std::move(info));
}

void SocketPairSystemCall::updateFDTracking(const Tracee &proc) {
	for (auto fd: pair.pair()) {
		auto info = make_socket_info(fd, type.flags());
		trackFD(proc, std::move(info));
	}
}

void AcceptSystemCall::updateFDTracking(const Tracee &proc) {
	auto info = make_socket_info(new_fd.fd(), flags.flags());
	trackFD(proc, std::move(info));
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
