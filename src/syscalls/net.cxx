// clues
#include <clues/syscalls/net.hxx>

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

} // end ns
