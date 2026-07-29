// test
#include "utils/syscalls.hxx"

// cosmos
#include <cosmos/compiler.hxx>

// clues
#include <clues/items/net.hxx>

// Linux
#include <sys/socket.h>
#include <linux/net.h>

namespace {

void check_socket_entry(const clues::SocketSystemCall &sc, bool &good) {
	VERIFY(sc.domain.domain() == clues::item::SocketDomain::INET6);
	using SocketType = clues::item::SocketType;
	VERIFY(sc.type.type() == SocketType::STREAM);
	const auto flags = sc.type.flags();
	VERIFY(flags[SocketType::NONBLOCK]);
	VERIFY(!flags[SocketType::CLOEXEC]);
	VERIFY(sc.prot.raw() != 0);
	VERIFY(std::holds_alternative<clues::item::SocketProtocol::IPProtocol>(sc.prot.prot()));
}

const auto TESTS = std::array{
	TestSpec{SystemCallNr::SOCKET, []() {
			syscall(SYS_socket, AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
		}, ENTRY_VERIFY_CB(SocketSystemCall, {
			check_socket_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketSystemCall, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{}, []() {
				syscall32(SyscallNr32::SOCKET, AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
			})
		}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			unsigned long args[3];
			args[0] = AF_INET6;
			args[1]= SOCK_STREAM|SOCK_NONBLOCK;
			args[2] = IPPROTO_TCP;
			syscall(SYS_socketcall, SYS_SOCKET, args);
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Socket, {
			check_socket_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_Socket, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto args = alloc32<uint32_t*>(sizeof(uint32_t) * 3);
				args[0] = AF_INET6;
				args[1]= SOCK_STREAM|SOCK_NONBLOCK;
				args[2] = IPPROTO_TCP;
				syscall32(SyscallNr32::SOCKETCALL, SYS_SOCKET, args);
			})
		},
		"socket()",
		{clues::ABI::I386}
	}
};

} // end anon ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
