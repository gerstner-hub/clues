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

void check_socketpair_entry(const clues::SocketPairSystemCall &sc, bool &good) {
	VERIFY(sc.domain.domain() == clues::item::SocketDomain::UNIX);
	using SocketType = clues::item::SocketType;
	VERIFY(sc.type.type() == SocketType::DGRAM);
	const auto flags = sc.type.flags();
	VERIFY(!flags[SocketType::NONBLOCK]);
	VERIFY(flags[SocketType::CLOEXEC]);
	VERIFY(sc.prot.raw() == 0);
}

#ifdef TEST_I386_EMU
uint32_t* alloc_args32(const size_t count) {
	return alloc32<uint32_t*>(sizeof(uint32_t) * count);
}
#endif

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
				auto args = alloc_args32(3);
				args[0] = AF_INET6;
				args[1]= SOCK_STREAM|SOCK_NONBLOCK;
				args[2] = IPPROTO_TCP;
				syscall32(SyscallNr32::SOCKETCALL, SYS_SOCKET, args);
			})
		},
		"socket()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::SOCKETPAIR, []() {
			int sv[2];
			syscall(SYS_socketpair, AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, sv);
		}, ENTRY_VERIFY_CB(SocketPairSystemCall, {
			check_socketpair_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketPairSystemCall, {
			VERIFY(sc.hasResultValue());
			auto pair = sc.pair.pair();
			VERIFY(pair[0] == FIRST_FD);
			VERIFY(pair[1] == SECOND_FD);
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto sv = alloc32<int*>(sizeof(int) * 2);
				syscall32(SyscallNr32::SOCKETPAIR, AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, sv);
			})
		}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			int sv[2];
			unsigned long args[4];
			args[0] = AF_UNIX;
			args[1]= SOCK_DGRAM|SOCK_CLOEXEC;
			args[2] = 0;
			args[3] = (unsigned long)sv;
			syscall(SYS_socketcall, SYS_SOCKETPAIR, args);
#endif
		}, ENTRY_VERIFY_CB(SocketCall_SocketPair, {
			check_socketpair_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_SocketPair, {
			VERIFY(sc.hasResultValue());
			auto pair = sc.pair.pair();
			VERIFY(pair[0] == FIRST_FD);
			VERIFY(pair[1] == SECOND_FD);
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto sv = alloc32<int*>(sizeof(int) * 2);
				auto args = alloc_args32(4);
				args[0] = AF_UNIX;
				args[1] = SOCK_DGRAM|SOCK_CLOEXEC;
				args[2] = 0;
				args[3] = (uint32_t)(uintptr_t)sv;
				syscall32(SyscallNr32::SOCKETCALL, SYS_SOCKETPAIR, args);
			})
		},
		"socketpair()",
		{clues::ABI::I386}
	}
};

} // end anon ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
