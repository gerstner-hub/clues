// test
#include "utils/syscalls.hxx"

// cosmos
#include <cosmos/compiler.hxx>

// clues
#include <clues/items/net.hxx>

// Linux
#include <sys/socket.h>
#include <linux/net.h>

using namespace std::literals;

namespace {

constexpr std::string_view UNIX_PATH{"\0clues-test"sv};

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

void check_bind_entry(const clues::BindSystemCall &sc, bool &good) {
	VERIFY(sc.sockfd.fd() == FIRST_FD);
	VERIFY(sc.addrlen.value() > 2);
	const auto &addr = sc.addr;
	VERIFY(addr.valid());
	VERIFY(addr.domain() == clues::item::SocketDomain::UNIX);
	const auto uaddr = std::get<cosmos::UnixAddress>(*addr.addr());
	VERIFY(uaddr.isAbstract());
	VERIFY(uaddr.getPath() == "clues-test");
}

void check_connect_entry(const clues::ConnectSystemCall &sc, bool &good) {
	VERIFY(sc.sockfd.fd() == FIRST_FD);
	VERIFY(sc.addrlen.value() == sizeof(sockaddr_in));
	const auto &addr = sc.addr;
	VERIFY(addr.valid());
	VERIFY(addr.domain() == clues::item::SocketDomain::INET);
	const auto ip4 = std::get<cosmos::IP4Address>(*addr.addr());
	VERIFY(ip4.addr().toHost() == INADDR_LOOPBACK);
	VERIFY(ip4.port().toHost() == 1234);
}

size_t setup_unixaddr(sockaddr_un &unix) {
	memset(&unix, 0, sizeof(unix));
	unix.sun_family = AF_UNIX;
	memcpy(unix.sun_path,
			UNIX_PATH.data(), UNIX_PATH.size());
	return sizeof(unix.sun_family) + UNIX_PATH.size();
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
			args[1] = SOCK_DGRAM|SOCK_CLOEXEC;
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
	},
	TestSpec{SystemCallNr::BIND, []() {
			int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
			sockaddr_un unix;
			const auto addrlen = setup_unixaddr(unix);
			if (syscall(SYS_bind, sock,
				(struct sockaddr*)&unix, addrlen) < 0) {

			}
		}, ENTRY_VERIFY_CB(BindSystemCall, {
			check_bind_entry(sc, good);
		}), EXIT_VERIFY_CB(BindSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
				auto unix = alloc_struct32<sockaddr_un>();
				const auto addrlen = setup_unixaddr(*unix);
				syscall32(SyscallNr32::BIND,
						sock, unix, addrlen);
			})
		}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
			struct sockaddr_un unix;
			const auto addrlen = setup_unixaddr(unix);
			unsigned long args[3];
			args[0] = sock;
			args[1] = reinterpret_cast<unsigned long>(&unix);
			args[2] = addrlen;
			syscall(SYS_socketcall, SYS_BIND, args);
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Bind, {
			check_bind_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_Bind, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
				auto args = alloc_args32(3);
				auto unix = alloc_struct32<struct sockaddr_un>();
				const auto addrlen = setup_unixaddr(*unix);
				args[0] = sock;
				args[1] = reinterpret_cast<unsigned long>(unix);
				args[2] = addrlen;
				syscall32(SyscallNr32::SOCKETCALL,
						SYS_BIND, args);
			})
		},
		"bind()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::CONNECT, []() {
			int sock = socket(AF_INET, SOCK_DGRAM, 0);
			sockaddr_in ip4;
			ip4.sin_family = AF_INET;
			ip4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			ip4.sin_port = htons(1234);
			if (syscall(SYS_connect, sock,
				(struct sockaddr*)&ip4, sizeof(ip4)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ConnectSystemCall, {
			check_connect_entry(sc, good);
		}), EXIT_VERIFY_CB(ConnectSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int sock = socket(AF_INET, SOCK_DGRAM, 0);
				auto ip4 = alloc_struct32<sockaddr_in>();
				ip4->sin_family = AF_INET;
				ip4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				ip4->sin_port = htons(1234);
				syscall32(SyscallNr32::CONNECT, sock, ip4,
						sizeof(*ip4));
			})
		}
	},
};

} // end anon ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
