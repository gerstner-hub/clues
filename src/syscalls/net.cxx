// clues
#include <clues/syscalls/net.hxx>
#include <clues/SystemCallInfo.hxx>

namespace clues {

void SocketSystemCall::updateFDTracking(const Tracee &proc) {
	FDInfo info{FDInfo::Type::SOCKET, new_fd.fd()};
	const auto flags = type.flags();
	info.flags.emplace();
	using enum item::SocketType::Flag;
	if (flags[NONBLOCK]) {
		info.flags->set(cosmos::OpenFlag::NONBLOCK);
	}
	if (flags[CLOEXEC]) {
		info.flags->set(cosmos::OpenFlag::CLOEXEC);
	}
	trackFD(proc, std::move(info));
}

void SocketCall_Socket::transferValues(const Tracee &proc) {

	if (!args.valid()) {
		return;
	}

	const auto &vec = args.args();
	domain.fill(proc, Word{vec[0]});
	type.fill(proc, Word{vec[1]});
	prot.fill(proc, Word{vec[2]});
}

SystemCallPtr create_socket_call_syscall(const SystemCallInfo &info) {
	using enum item::SocketCallType::Call;

	const auto subcall = item::SocketCallType::Call(info.entryInfo()->args()[0]);

	switch (subcall) {
		case SOCKET: return std::make_shared<SocketCall_Socket>();
		default: throw cosmos::RuntimeError{"unsupported socketcall() sub-call"};
	}
}

} // end ns
