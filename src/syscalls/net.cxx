// clues
#include <clues/logger.hxx>
#include <clues/syscalls/net.hxx>
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

void SocketCall_Socket::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	domain.fill(proc, Word{vec[0]});
	type.fill(proc, Word{vec[1]});
	prot.fill(proc, Word{vec[2]});
}

void SocketCall_SocketPair::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	domain.fill(proc, Word{vec[0]});
	type.fill(proc, Word{vec[1]});
	prot.fill(proc, Word{vec[2]});
	pair.fill(proc, Word{vec[3]});
}

void SocketCall_Bind::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	/*
	 * fill len first, only then addr, which depends on len,
	 * this implicitly respects the DEFER flag set on `addr`
	 */
	addrlen.fill(proc, Word{vec[2]});
	addr.fill(proc, Word{vec[1]});
}

void SocketCall_Connect::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	/* respect DEFER requirement */
	addrlen.fill(proc, Word{vec[2]});
	addr.fill(proc, Word{vec[1]});
}

void SocketCall_Listen::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	backlog.fill(proc, Word{vec[1]});
}

void SocketCall_Accept::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	addrlen.fill(proc, Word{vec[2]});

	if (vec.size() > 3) {
		/* accept4() */
		flags.fill(proc, Word{vec[3]});
	}

	/* respect DEFER semantics */
	addr.fill(proc, Word{vec[1]});
}

void SocketCall_Shutdown::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	how.fill(proc, Word{vec[1]});
}

void SocketCall_GetSockName::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	addrlen.fill(proc, Word{vec[2]});
	/* respect DEFER */
	addr.fill(proc, Word{vec[1]});
}

void SocketCall_GetPeerName::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	addrlen.fill(proc, Word{vec[2]});
	/* respect DEFER */
	addr.fill(proc, Word{vec[1]});
}

void SocketCall_Recv::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	count.fill(proc, Word{vec[2]});
	flags.fill(proc, Word{vec[3]});

	/* respect DEFER */
	buf.fill(proc, Word{vec[1]});
}

void SocketCall_RecvFrom::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	count.fill(proc, Word{vec[2]});
	flags.fill(proc, Word{vec[3]});
	addrlen.fill(proc, Word{vec[5]});

	/* respect DEFER */
	addr.fill(proc, Word{vec[4]});
	buf.fill(proc, Word{vec[1]});
}

void SocketCall_Send::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	count.fill(proc, Word{vec[2]});
	flags.fill(proc, Word{vec[3]});

	/* respect DEFER */
	buf.fill(proc, Word{vec[1]});
}

void SocketCall_SendTo::transferValues(const Tracee &proc) {
	const auto &vec = args.args();
	sockfd.fill(proc, Word{vec[0]});
	count.fill(proc, Word{vec[2]});
	flags.fill(proc, Word{vec[3]});
	addrlen.fill(proc, Word{vec[5]});

	/* respect DEFER */
	addr.fill(proc, Word{vec[4]});
	buf.fill(proc, Word{vec[1]});
}

void SocketCall_RecvMsg::transferValues(const Tracee &proc) {
	const auto &vec = args.args();

	sockfd.fill(proc, Word{vec[0]});
	msg.fill(proc, Word{vec[1]});
	flags.fill(proc, Word{vec[2]});
}

template <typename BASE>
SocketCallBase<BASE>::SocketCallBase() :
		BASE{SystemCallNr::SOCKETCALL},
		args{call} {
	for (auto par: this->m_pars) {
		if (par->needsUpdate() && !par->deferFill()) {
			m_update_args.push_back(par);
		}
	}

	for (auto par: this->m_pars) {
		if (par->needsUpdate() && par->deferFill()) {
			m_update_args.push_back(par);
		}
	}

	BASE::setParameters(call, args);
}


template <typename BASE>
void SocketCallBase<BASE>::postSystemCall(const Tracee &proc) {
	for (auto arg: m_update_args) {
		arg->updateData(proc);
	}
}

SystemCallPtr create_socket_call_syscall(const SystemCallInfo &info) {
	using enum item::SocketCallType::Call;

	const auto subcall = item::SocketCallType::Call(info.entryInfo()->args()[0]);

	switch (subcall) {
	case SOCKET:     return std::make_shared<SocketCall_Socket>();
	case SOCKETPAIR: return std::make_shared<SocketCall_SocketPair>();
	case BIND:       return std::make_shared<SocketCall_Bind>();
	case CONNECT:    return std::make_shared<SocketCall_Connect>();
	case LISTEN:     return std::make_shared<SocketCall_Listen>();
	case ACCEPT:     [[ fallthrough ]];
	case ACCEPT4:    return std::make_shared<SocketCall_Accept>();
	case SHUTDOWN:   return std::make_shared<SocketCall_Shutdown>();
	case GETSOCKNAME:return std::make_shared<SocketCall_GetSockName>();
	case GETPEERNAME:return std::make_shared<SocketCall_GetPeerName>();
	case RECV:       return std::make_shared<SocketCall_Recv>();
	case RECVFROM:   return std::make_shared<SocketCall_RecvFrom>();
	case SEND:       return std::make_shared<SocketCall_Send>();
	case SENDTO:     return std::make_shared<SocketCall_SendTo>();
	case RECVMSG:    return std::make_shared<SocketCall_RecvMsg>();
	default: throw cosmos::RuntimeError{"unsupported socketcall() sub-call"};
	}
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
		if (const auto type = ctrl.asUnixMessage(); !type)
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
