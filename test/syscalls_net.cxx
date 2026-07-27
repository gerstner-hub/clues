// test
#include "utils/syscalls.hxx"

// clues
#include <clues/items/net.hxx>

// Linux
#include <sys/socket.h>

namespace {

const auto TESTS = std::array{
	TestSpec{SystemCallNr::SOCKET, []() {
			syscall(SYS_socket, AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
		}, ENTRY_VERIFY_CB(SocketSystemCall, {
			VERIFY(sc.domain.domain() == clues::item::SocketDomain::INET6);
			using SocketType = clues::item::SocketType;
			VERIFY(sc.type.type() == SocketType::STREAM);
			const auto flags = sc.type.flags();
			VERIFY(flags[SocketType::NONBLOCK]);
			VERIFY(!flags[SocketType::CLOEXEC]);
			VERIFY(sc.prot.raw() != 0);
			VERIFY(std::holds_alternative<clues::item::SocketProtocol::IPProtocol>(sc.prot.prot()));
		}), EXIT_VERIFY_CB(SocketSystemCall, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{}, []() {
				syscall32(SyscallNr32::SOCKET, AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
			})
		}
	},
};

} // end anon ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
