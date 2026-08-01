// clues
#include <clues/syscalls/net.hxx>
#include <clues/SystemCallInfo.hxx>

namespace clues {

namespace {

FDInfo make_socket_info(const cosmos::FileNum fd, const item::SocketType &type) {
	FDInfo info{FDInfo::Type::SOCKET, fd};
	const auto flags = type.flags();
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
	auto info = make_socket_info(new_fd.fd(), type);
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

template <typename BASE>
SocketCallBase<BASE>::SocketCallBase() :
		BASE{SystemCallNr::SOCKETCALL},
		args{call} {
	for (auto par: this->m_pars) {
		if (par->needsUpdate()) {
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
		case SOCKET: return std::make_shared<SocketCall_Socket>();
		case SOCKETPAIR: return std::make_shared<SocketCall_SocketPair>();
		case BIND: return std::make_shared<SocketCall_Bind>();
		case CONNECT: return std::make_shared<SocketCall_Connect>();
		default: throw cosmos::RuntimeError{"unsupported socketcall() sub-call"};
	}
}

void SocketPairSystemCall::updateFDTracking(const Tracee &proc) {
	for (auto fd: pair.pair()) {
		auto info = make_socket_info(fd, type);
		trackFD(proc, std::move(info));
	}
}

} // end ns
