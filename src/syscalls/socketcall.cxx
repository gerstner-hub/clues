// C++
#include <memory>

// clues
#include <clues/items/net.hxx>
#include <clues/logger.hxx>
#include <clues/syscalls/socketcall.hxx>
#include <clues/Tracee.hxx>

namespace clues {

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

void SocketCall_SendMsg::transferValues(const Tracee &proc) {
	const auto &vec = args.args();

	sockfd.fill(proc, Word{vec[0]});
	msg.fill(proc, Word{vec[1]});
	flags.fill(proc, Word{vec[2]});
}

void SocketCall_RecvMMsg::transferValues(const Tracee &proc) {
	const auto &vec = args.args();

	sockfd.fill(proc, Word{vec[0]});
	/* respect DEFER flags of `msgvec` */
	num_msgs.fill(proc, Word{vec[2]});
	msgvec.fill(proc, Word{vec[1]});
	flags.fill(proc, Word{vec[3]});
	timeout.fill(proc, Word{vec[4]});
}

void SocketCall_SendMMsg::transferValues(const Tracee &proc) {
	const auto &vec = args.args();

	sockfd.fill(proc, Word{vec[0]});
	/* respect DEFER flags of `msgvec` */
	num_msgs.fill(proc, Word{vec[2]});
	msgvec.fill(proc, Word{vec[1]});
	flags.fill(proc, Word{vec[3]});
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

using OptLevel = item::SockOptLevel::Level;

namespace {

SystemCallPtr create_socket_call_get_socket_opt_syscall(const int optname) {
	using enum item::SockOptName::SocketOption;

	switch (item::SockOptName::SocketOption{optname}) {
	case ACCEPTCONN:
	case DONTROUTE:
		return std::make_shared<SocketCall_GetBoolSockOpt>();
	default: break;
	}

	return nullptr;
}

SystemCallPtr create_socket_call_getsockopt_syscall(const Tracee &tracee, const SystemCallInfo &info) {
	const auto call_args = item::SocketCallArgs::fetchArgs(tracee,
			info.abi(),
			item::SocketCallType::Call::GETSOCKOPT,
			ForeignPtr{info.entryInfo().value().args()[1]});
	const auto optlevel = OptLevel{(int)call_args[1]};
	const int optname = call_args[2];

	switch (optlevel) {
		case OptLevel::SOCKET: {
			if (auto sc = create_socket_call_get_socket_opt_syscall(optname); sc) {
				return sc;
			}
		}
		default: break;
	}

	LOG_WARN("unknown socketcall(GETSOCKOPT, ...) level/optname encountered. falling back to generic type.");
	return std::make_shared<SocketCall_UnknownSockOpt>();
}

} // end anon ns

SystemCallPtr create_socket_call_syscall(const Tracee &tracee, const SystemCallInfo &info) {
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
	case SENDMSG:    return std::make_shared<SocketCall_SendMsg>();
	case RECVMMSG:   return std::make_shared<SocketCall_RecvMMsg>();
	case SENDMMSG:   return std::make_shared<SocketCall_SendMMsg>();
	case GETSOCKOPT: return create_socket_call_getsockopt_syscall(tracee, info);
	default: throw cosmos::RuntimeError{"unsupported socketcall() sub-call"};
	}
}

template <typename BASE>
void SocketCallGetSockOptBase<BASE>::transferValues(const Tracee &proc) {
	const auto &vec = this->args.args();
	this->sockfd.fill(proc, Word{vec[0]});
	this->level.fill(proc, Word{vec[1]});
	this->name.fill(proc, Word{vec[2]});
	this->optlen.fill(proc, Word{vec[4]});

	/* respect DEFER_FILL */
	this->optval.fill(proc, Word{vec[3]});
}

/*
 * explicit template instantiations
 */

template class SocketCallGetSockOptBase<GetBoolSockOptSystemCall>;
template class SocketCallGetSockOptBase<GetUnknownSockOptSystemCall>;

} // end ns
