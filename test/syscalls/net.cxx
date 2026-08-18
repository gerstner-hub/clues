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
const std::string_view UNIX_SENDER{"\0send", 5};
const std::string_view UNIX_RECEIVER{"\0recv", 5};
constexpr std::string_view SEND_DATA{"testdata"};

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

void check_recv_entry(const clues::RecvSystemCall &sc, bool &good) {
	VERIFY(sc.sockfd.fd() == SECOND_FD);
	VERIFY(sc.buf.availableBytes() == 0);
	VERIFY(sc.count.value() == 128);
	const auto flags = sc.flags.flags();
	VERIFY(flags.count() == 1);
	VERIFY(flags[clues::item::SendRecvFlags::NO_SIGNAL]);
}

void check_recv_exit(const clues::RecvSystemCall &sc, bool &good) {
	VERIFY(sc.hasResultValue());
	VERIFY(sc.buf.availableBytes() == 8);
	VERIFY(std::string_view{(const char*)sc.buf.data().data(), sc.buf.data().size()}
			== "testdata");
}

void check_send_entry(const clues::SendSystemCall &sc, bool &good) {
	VERIFY(sc.sockfd.fd() == FIRST_FD);
	VERIFY(sc.buf.availableBytes() == 8);
	const auto flags = sc.flags.flags();
	VERIFY(flags.count() == 1);
	VERIFY(flags[clues::item::SendRecvFlags::NO_SIGNAL]);
	VERIFY(std::string_view{(const char*)sc.buf.data().data(), sc.buf.data().size()}
			== "testdata");
}

void check_sendto_entry(const clues::SendToSystemCall &sc, bool &good) {
	check_send_entry(sc, good);
	VERIFY(sc.addr.valid());
	const auto addr = std::get<cosmos::UnixAddress>(*sc.addr.addr());
	VERIFY(addr.getPath() == "recv");
}

void check_send_exit(const clues::SendSystemCall &sc, bool &good) {
	VERIFY(sc.hasResultValue());
	VERIFY(sc.written.value() == 8);
}

void check_recvfrom_exit(const clues::RecvFromSystemCall &sc, bool &good) {
	check_recv_exit(sc, good);
	VERIFY(sc.addr.valid());
	const auto addr = std::get<cosmos::UnixAddress>(*sc.addr.addr());
	VERIFY(addr.getPath() == "send");
}

size_t setup_unixaddr(sockaddr_un &unix) {
	memset(&unix, 0, sizeof(unix));
	unix.sun_family = AF_UNIX;
	memcpy(unix.sun_path,
			UNIX_PATH.data(), UNIX_PATH.size());
	return sizeof(unix.sun_family) + UNIX_PATH.size();
}

void do_send_unix(std::function<void(int, int)> cb) {
	int socks[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) < 0) {
		return;
	}

	sockaddr_un unix;
	unix.sun_family = AF_UNIX;
	memcpy(unix.sun_path, UNIX_SENDER.data(), UNIX_SENDER.size());
	if (bind(socks[0], (sockaddr*)&unix, 2 + UNIX_SENDER.size()) < 0) {
		return;
	}

	memcpy(unix.sun_path, UNIX_RECEIVER.data(), UNIX_RECEIVER.size());
	if (bind(socks[1], (sockaddr*)&unix, 2 + UNIX_RECEIVER.size()) < 0) {
		return;
	}

	cb(socks[0], socks[1]);
}

/* performs 4 system calls, sends 8 byte of data, binds to '\0send'  */
void do_receive_unix(std::function<void(int)> cb) {
	do_send_unix([cb](int send_sock, int recv_sock) {
		syscall(SYS_sendto, send_sock, SEND_DATA.data(), SEND_DATA.size(),
				MSG_NOSIGNAL, nullptr, 0);

		cb(recv_sock);
	});
}

void accept_conn(std::function<void(int)> cb) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in ip4;
	ip4.sin_family = AF_INET;
	ip4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ip4.sin_port = 0;
	socklen_t len = sizeof(ip4);

	if (bind(sock, (sockaddr*)&ip4, sizeof(ip4)) == 0) {
		listen(sock, 15);
		syscall(SYS_getsockname, sock, (sockaddr*)&ip4, &len);
	}

	int client = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (connect(client, (sockaddr*)&ip4, sizeof(ip4)) < 0) {
		len = sizeof(ip4);
		cb(sock);
	}
}

void check_accept_entry(const clues::AcceptSystemCall &sc, bool &good) {
	VERIFY(sc.sockfd.fd() == FIRST_FD);
}

void check_accept_exit(const clues::AcceptSystemCall &sc, bool &good) {
	VERIFY(sc.hasResultValue());
	VERIFY(sc.new_fd.fd() == THIRD_FD);
	VERIFY(*sc.addrlen.available() == *sc.addrlen.filled());
	VERIFY(sc.addr.domain() == clues::item::SocketDomain::Domain::INET);
	VERIFY(sc.addr.domain() == clues::item::SocketDomain::Domain::INET);
	VERIFY(sc.addr.addr().has_value());
	VERIFY(std::holds_alternative<cosmos::IP4Address>(*sc.addr.addr()));
}

template <typename SC>
void check_getaddr_entry(const SC &sc, bool &good, socklen_t addrlen) {
	VERIFY(sc.sockfd.fd() == FIRST_FD);
	VERIFY(sc.addrlen.available() == addrlen);
	VERIFY(!sc.addr.addr());
}

template <typename SC>
void check_getaddr_exit(const SC &sc, bool &good) {
	VERIFY(sc.hasResultValue());
	VERIFY(sc.addr.addr());
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
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			int sock = socket(AF_INET, SOCK_DGRAM, 0);
			sockaddr_in ip4;
			ip4.sin_family = AF_INET;
			ip4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			ip4.sin_port = htons(1234);
			unsigned long args[3];
			args[0] = sock;
			args[1] = reinterpret_cast<unsigned long>(&ip4);
			args[2] = sizeof(ip4);
			syscall(SYS_socketcall, SYS_CONNECT, args);
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Connect, {
			check_connect_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_Connect, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int sock = socket(AF_INET, SOCK_DGRAM, 0);
				auto args = alloc_args32(3);
				auto ip4 = alloc_struct32<sockaddr_in>();
				ip4->sin_family = AF_INET;
				ip4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				ip4->sin_port = htons(1234);
				args[0] = sock;
				args[1] = reinterpret_cast<unsigned long>(ip4);
				args[2] = sizeof(*ip4);
				syscall32(SyscallNr32::SOCKETCALL,
						SYS_CONNECT, args);
			})
		},
		"connect()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::LISTEN, []() {
			int sock = socket(AF_UNIX, SOCK_STREAM, 0);
			sockaddr_un unix;
			const auto addrlen = setup_unixaddr(unix);
			if (bind(sock, (sockaddr*)&unix, addrlen) == 0) {
				syscall(SYS_listen, sock, 15);
			}
		}, ENTRY_VERIFY_CB(ListenSystemCall, {
			VERIFY(sc.sockfd.fd() == FIRST_FD);
			VERIFY(sc.backlog.value() == 15);
		}), EXIT_VERIFY_CB(ListenSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int sock = socket(AF_UNIX, SOCK_STREAM, 0);
				sockaddr_un unix;
				const auto addrlen = setup_unixaddr(unix);
				if (bind(sock, (sockaddr*)&unix, addrlen) == 0) {
					syscall32(SyscallNr32::LISTEN, sock, 15);
				}
			})
		}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			int sock = socket(AF_UNIX, SOCK_STREAM, 0);
			sockaddr_un unix;
			const auto addrlen = setup_unixaddr(unix);
			bind(sock, (sockaddr*)&unix, addrlen);
			unsigned long args[2];
			args[0] = sock;
			args[1] = 15;
			syscall(SYS_socketcall, SYS_LISTEN, args);
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Listen, {
			VERIFY(sc.sockfd.fd() == FIRST_FD);
			VERIFY(sc.backlog.value() == 15);
		}), EXIT_VERIFY_CB(SocketCall_Listen, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int sock = socket(AF_UNIX, SOCK_STREAM, 0);
				sockaddr_un unix;
				const auto addrlen = setup_unixaddr(unix);
				if (bind(sock, (sockaddr*)&unix, addrlen) < 0) {

				}
				auto args = alloc_args32(2);
				args[0] = sock;
				args[1] = 15;
				syscall32(SyscallNr32::SOCKETCALL,
						SYS_LISTEN, args);
			})
		},
		"listen()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::ACCEPT, []() {
#ifndef COSMOS_I386
			accept_conn([](int sock) {
				struct sockaddr_in addr;
				socklen_t len = sizeof(addr);
				syscall(SYS_accept, sock,
						(sockaddr*)&addr, &len);
			});
#endif
		}, ENTRY_VERIFY_CB(AcceptSystemCall, {
			check_accept_entry(sc, good);
			VERIFY(sc.flags.flags().none());
		}), EXIT_VERIFY_CB(AcceptSystemCall, {
			check_accept_exit(sc, good);
		}), IgnoreCalls{6}, {
			/* ACCEPT does not exist on I386, only ACCEPT4 */
		},
		{},
		{clues::ABI::X86_64, clues::ABI::AARCH64}
	},
	TestSpec{SystemCallNr::ACCEPT4, []() {
			accept_conn([](int sock) {
				struct sockaddr_in addr;
				socklen_t len = sizeof(addr);
				syscall(SYS_accept4, sock,
						(sockaddr*)&addr, &len,
						SOCK_CLOEXEC);
			});
		}, ENTRY_VERIFY_CB(AcceptSystemCall, {
			check_accept_entry(sc, good);
			const auto flags = sc.flags.flags();
			VERIFY(flags.count() == 1);
			VERIFY(flags[clues::item::AcceptFlags::Flag::CLOEXEC]);
		}), EXIT_VERIFY_CB(AcceptSystemCall, {
			check_accept_exit(sc, good);
		}), IgnoreCalls{6}, {
			I386_CROSS_ABI(IgnoreCalls{8}, []() {
				accept_conn([](int sock) {
					auto addr = alloc_struct32<sockaddr_in>();
					auto len = alloc_struct32<socklen_t>();
					*len = sizeof(*addr);
					syscall32(SyscallNr32::ACCEPT4, sock, addr, len, SOCK_CLOEXEC);
				});
			})
		}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			accept_conn([](int sock) {
				struct sockaddr_in addr;
				socklen_t len = sizeof(addr);
				unsigned long args[3];
				args[0] = sock;
				args[1] = (unsigned long)&addr;
				args[2] = (unsigned long)&len;
				syscall(SYS_socketcall, SYS_ACCEPT, args);
			});
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Accept, {
			check_accept_entry(sc, good);
			VERIFY(sc.flags.flags().none());
		}), EXIT_VERIFY_CB(SocketCall_Accept, {
			check_accept_exit(sc, good);
		}), IgnoreCalls{6}, {
			I386_CROSS_ABI(IgnoreCalls{9}, []() {
				accept_conn([](int sock) {
					auto addr = alloc_struct32<sockaddr_in>();
					auto len = alloc_struct32<socklen_t>();
					*len = sizeof(*addr);
					auto args = alloc_args32(3);
					args[0] = sock;
					args[1] = (unsigned long)addr;
					args[2] = (unsigned long)len;
					syscall32(SyscallNr32::SOCKETCALL, SYS_ACCEPT, args);
				});
			})
		},
		"accept()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			accept_conn([](int sock) {
				struct sockaddr_in addr;
				socklen_t len = sizeof(addr);
				unsigned long args[4];
				args[0] = sock;
				args[1] = (unsigned long)&addr;
				args[2] = (unsigned long)&len;
				args[3] = SOCK_CLOEXEC;
				syscall(SYS_socketcall, SYS_ACCEPT4, args);
			});
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Accept, {
			check_accept_entry(sc, good);
			const auto flags = sc.flags.flags();
			VERIFY(flags.count() == 1);
			VERIFY(flags[clues::item::AcceptFlags::Flag::CLOEXEC]);
		}), EXIT_VERIFY_CB(SocketCall_Accept, {
			check_accept_exit(sc, good);
		}), IgnoreCalls{6}, {
			I386_CROSS_ABI(IgnoreCalls{9}, []() {
				accept_conn([](int sock) {
					auto addr = alloc_struct32<sockaddr_in>();
					auto len = alloc_struct32<socklen_t>();
					*len = sizeof(*addr);
					auto args = alloc_args32(4);
					args[0] = sock;
					args[1] = (unsigned long)addr;
					args[2] = (unsigned long)len;
					args[3] = SOCK_CLOEXEC;
					syscall32(SyscallNr32::SOCKETCALL, SYS_ACCEPT4, args);
				});
			})
		},
		"accept4()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::SHUTDOWN, []() {
			accept_conn([](int sock) {
				sockaddr_in ip;
				socklen_t len = sizeof(ip);
				int sock2 = accept(sock, (sockaddr*)&ip, &len);
				syscall(SYS_shutdown, sock2, SHUT_WR);
			});
		}, ENTRY_VERIFY_CB(ShutdownSystemCall, {
			VERIFY(sc.sockfd.fd() == THIRD_FD);
			VERIFY(sc.how.direction() ==
					clues::item::ShutdownType::Direction::WRITE);
		}), EXIT_VERIFY_CB(ShutdownSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{7}, {
			I386_CROSS_ABI(IgnoreCalls{7}, []() {
				accept_conn([](int sock) {
					sockaddr_in ip;
					socklen_t len = sizeof(ip);
					int sock2 = accept(sock, (sockaddr*)&ip, &len);
					syscall32(SyscallNr32::SHUTDOWN, sock2, SHUT_WR);
				});
			})
		}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			accept_conn([](int sock) {
				struct sockaddr_in addr;
				socklen_t len = sizeof(addr);
				int conn = accept(sock, (sockaddr*)&addr, &len);
				unsigned long args[2];
				args[0] = conn;
				args[1] = SHUT_WR;
				syscall(SYS_socketcall, SYS_SHUTDOWN, args);
			});
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Shutdown, {
			VERIFY(sc.sockfd.fd() == THIRD_FD);
			VERIFY(sc.how.direction() ==
					clues::item::ShutdownType::Direction::WRITE);
		}), EXIT_VERIFY_CB(SocketCall_Shutdown, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{7}, {
			I386_CROSS_ABI(IgnoreCalls{8}, []() {
				accept_conn([](int sock) {
					struct sockaddr_in addr;
					socklen_t len = sizeof(addr);
					int conn = accept(sock, (sockaddr*)&addr, &len);
			
					auto args = alloc_args32(2);
					args[0] = conn;
					args[1] = SHUT_WR;
					syscall32(SyscallNr32::SOCKETCALL, SYS_SHUTDOWN, args);
				});
			})
		},
		"shutdown()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::GETSOCKNAME, []() {
			int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
			sockaddr_un unix;
			const auto addrlen = setup_unixaddr(unix);
			if (bind(sock, (struct sockaddr*)&unix, addrlen) == 0) {
				socklen_t len = sizeof(unix);
				syscall(SYS_getsockname, sock, &unix, &len);
			}
		}, ENTRY_VERIFY_CB(GetSockNameSystemCall, {
			check_getaddr_entry(sc, good, sizeof(sockaddr_un));
		}), EXIT_VERIFY_CB(GetSockNameSystemCall, {
			check_getaddr_exit(sc, good);
			auto addr = std::get<cosmos::UnixAddress>(*sc.addr.addr());
			// skip the null-byte
			VERIFY(addr.getPath() == UNIX_PATH.substr(1));
			VERIFY(*sc.addrlen.filled() > 2);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
				auto unix = alloc_struct32<sockaddr_un>();
				const auto bind_len = setup_unixaddr(*unix);
				if (bind(sock, (struct sockaddr*)unix, bind_len) == 0) {
					auto len = alloc_struct32<socklen_t>();
					*len = sizeof(struct sockaddr_un);
					syscall32(SyscallNr32::GETSOCKNAME, sock, unix, len);
				}
			})
		}
	},
	TestSpec{SystemCallNr::GETPEERNAME, []() {
			int sock = socket(AF_INET, SOCK_DGRAM, 0);
			sockaddr_in ip;
			ip.sin_family = AF_INET;
			ip.sin_port = htons(1234);
			ip.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

			if (connect(sock, (struct sockaddr*)&ip, sizeof(ip)) == 0) {
				socklen_t len = sizeof(ip);
				syscall(SYS_getpeername, sock, &ip, &len);
			}
		}, ENTRY_VERIFY_CB(GetPeerNameSystemCall, {
			check_getaddr_entry(sc, good, sizeof(sockaddr_in));
		}), EXIT_VERIFY_CB(GetPeerNameSystemCall, {
			check_getaddr_exit(sc, good);
			auto addr = std::get<cosmos::IP4Address>(
					*sc.addr.addr());
			VERIFY(addr.ipAsString() == "127.0.0.1");
			VERIFY(addr.port().toHost() == 1234);
			VERIFY(*sc.addrlen.filled() == sizeof(sockaddr_in));
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				int sock = socket(AF_INET, SOCK_DGRAM, 0);
				auto ip = alloc_struct32<sockaddr_in>();
				ip->sin_family = AF_INET;
				ip->sin_port = htons(1234);
				ip->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

				if (connect(sock, (struct sockaddr*)ip, sizeof(*ip)) == 0) {
					auto len = alloc_struct32<socklen_t>();
					*len = sizeof(*ip);
					syscall32(SyscallNr32::GETPEERNAME, sock, ip, len);
				}
			})
		}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
			sockaddr_un unix;
			const auto addrlen = setup_unixaddr(unix);
			if (bind(sock, (struct sockaddr*)&unix, addrlen) == 0) {
				socklen_t len = sizeof(unix);
				unsigned long args[3];
				args[0] = sock;
				args[1] = reinterpret_cast<unsigned long>(&unix);
				args[2] = reinterpret_cast<unsigned long>(&len);
				syscall(SYS_socketcall, SYS_GETSOCKNAME, args);
			}
#endif
		}, ENTRY_VERIFY_CB(SocketCall_GetSockName, {
			check_getaddr_entry(sc, good, sizeof(sockaddr_un));
		}), EXIT_VERIFY_CB(SocketCall_GetSockName, {
			check_getaddr_exit(sc, good);
			auto addr = std::get<cosmos::UnixAddress>(*sc.addr.addr());
			// skip the null-byte
			VERIFY(addr.getPath() == UNIX_PATH.substr(1));
			VERIFY(*sc.addrlen.filled() > 2);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{5}, []() {
				int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
				auto unix = alloc_struct32<sockaddr_un>();
				const auto bind_len = setup_unixaddr(*unix);
				if (bind(sock, (struct sockaddr*)unix, bind_len) == 0) {
					auto len = alloc_struct32<socklen_t>();
					*len = sizeof(struct sockaddr_un);
					auto args = alloc_args32(3);
					args[0] = sock;
					args[1] = reinterpret_cast<unsigned long>(unix);
					args[2] = reinterpret_cast<unsigned long>(len);
					syscall32(SyscallNr32::SOCKETCALL, SYS_GETSOCKNAME, args);
				}
			})
		},
		"getsockname()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
			int sock = socket(AF_INET, SOCK_DGRAM, 0);
			sockaddr_in ip;
			ip.sin_family = AF_INET;
			ip.sin_port = htons(1234);
			ip.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

			if (connect(sock, (struct sockaddr*)&ip, sizeof(ip)) == 0) {
				socklen_t len = sizeof(ip);
				unsigned long args[3];
				args[0] = sock;
				args[1] = reinterpret_cast<unsigned long>(&ip);
				args[2] = reinterpret_cast<unsigned long>(&len);
				syscall(SYS_socketcall, SYS_GETPEERNAME, args);
			}
#endif
		}, ENTRY_VERIFY_CB(SocketCall_GetPeerName, {
			check_getaddr_entry(sc, good, sizeof(sockaddr_in));
		}), EXIT_VERIFY_CB(SocketCall_GetPeerName, {
			check_getaddr_exit(sc, good);
			auto addr = std::get<cosmos::IP4Address>(
					*sc.addr.addr());
			VERIFY(addr.ipAsString() == "127.0.0.1");
			VERIFY(addr.port().toHost() == 1234);
			VERIFY(*sc.addrlen.filled() == sizeof(sockaddr_in));
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{5}, []() {
				int sock = socket(AF_INET, SOCK_DGRAM, 0);
				auto ip = alloc_struct32<sockaddr_in>();
				ip->sin_family = AF_INET;
				ip->sin_port = htons(1234);
				ip->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

				if (connect(sock, (struct sockaddr*)ip, sizeof(*ip)) == 0) {
					auto len = alloc_struct32<socklen_t>();
					*len = sizeof(*ip);
					auto args = alloc_args32(3);
					args[0] = sock;
					args[1] = reinterpret_cast<unsigned long>(ip);
					args[2] = reinterpret_cast<unsigned long>(len);
					syscall32(SyscallNr32::SOCKETCALL, SYS_GETPEERNAME, args);
				}
			})
		},
		"getpeername()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::RECVFROM, []() {
			do_receive_unix([](int sock) {
				sockaddr_un unix;
				unix.sun_family = AF_UNIX;
				char in_data[128];

				socklen_t addrlen = sizeof(unix);

				syscall(SYS_recvfrom, sock, in_data, sizeof(in_data),
						MSG_NOSIGNAL, (sockaddr*)&unix, &addrlen);
			});
		}, ENTRY_VERIFY_CB(RecvFromSystemCall, {
			check_recv_entry(sc, good);
		}), EXIT_VERIFY_CB(RecvFromSystemCall, {
			check_recvfrom_exit(sc, good);
		}), IgnoreCalls{4}, {
			I386_CROSS_ABI(IgnoreCalls{7}, []() {
				do_receive_unix([](int sock) {
					auto unix = alloc_struct32<sockaddr_un>();
					unix->sun_family = AF_UNIX;
					auto in_data = alloc32<char*>(128);
					auto addrlen = alloc_struct32<socklen_t>();
					*addrlen = sizeof(*unix);

					syscall32(SyscallNr32::RECVFROM, sock, in_data,
							128, MSG_NOSIGNAL, unix, addrlen);
				});
			})
		}
	},
	TestSpec{SystemCallNr::SENDTO, []() {
			do_send_unix([](int send_sock, int) {
				sockaddr_un unix;
				unix.sun_family = AF_UNIX;
				memcpy(unix.sun_path, UNIX_RECEIVER.data(), UNIX_RECEIVER.size());
				socklen_t addrlen = 2 + UNIX_RECEIVER.size();

				syscall(SYS_sendto, send_sock, SEND_DATA.data(), SEND_DATA.size(),
						MSG_NOSIGNAL, (sockaddr*)&unix, addrlen);
			});
		}, ENTRY_VERIFY_CB(SendToSystemCall, {
			check_sendto_entry(sc, good);
		}), EXIT_VERIFY_CB(SendToSystemCall, {
			check_send_exit(sc, good);
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls{5}, []() {
				do_send_unix([](int sock, int) {
					auto unix = alloc_struct32<sockaddr_un>();
					unix->sun_family = AF_UNIX;
					memcpy(unix->sun_path, UNIX_RECEIVER.data(), UNIX_RECEIVER.size());
					constexpr size_t SEND_DATA_SIZE = 8;
					auto send_data = alloc32<char*>(SEND_DATA_SIZE);
					memcpy(send_data, "testdata", SEND_DATA_SIZE);

					socklen_t addrlen = 2 + UNIX_RECEIVER.size();

					syscall32(SyscallNr32::SENDTO, sock, send_data,
							SEND_DATA_SIZE, MSG_NOSIGNAL, unix, addrlen);
				});
			})
		}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
		do_receive_unix([](int sock) {
			char in_data[128];

			unsigned long args[4];
			args[0] = sock;
			args[1] = reinterpret_cast<unsigned long>(in_data);
			args[2] = sizeof(in_data);
			args[3] = MSG_NOSIGNAL;

			syscall(SYS_socketcall, SYS_RECV, args);
		});
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Recv, {
			check_recv_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_Recv, {
			check_recv_exit(sc, good);
		}), IgnoreCalls{4}, {
			I386_CROSS_ABI(IgnoreCalls{6}, []() {
				do_receive_unix([](int sock) {
					auto in_data = alloc32<char*>(128);

					auto args = alloc_args32(4);
					args[0] = sock;
					args[1] = reinterpret_cast<unsigned long>(in_data);
					args[2] = 128;
					args[3] = MSG_NOSIGNAL;

					syscall32(SyscallNr32::SOCKETCALL, SYS_RECV, args);
				});
			})
		},
		"recv()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
		do_receive_unix([](int sock) {
			char in_data[128];
			sockaddr_un unix;
			unix.sun_family = AF_UNIX;
			socklen_t addrlen = sizeof(unix);

			unsigned long args[6];
			args[0] = sock;
			args[1] = reinterpret_cast<unsigned long>(in_data);
			args[2] = sizeof(in_data);
			args[3] = MSG_NOSIGNAL;
			args[4] = reinterpret_cast<unsigned long>(&unix);
			args[5] = reinterpret_cast<unsigned long>(&addrlen);

			syscall(SYS_socketcall, SYS_RECVFROM, args);
		});
#endif
		}, ENTRY_VERIFY_CB(SocketCall_RecvFrom, {
			check_recv_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_RecvFrom, {
			check_recvfrom_exit(sc, good);
		}), IgnoreCalls{4}, {
			I386_CROSS_ABI(IgnoreCalls{8}, []() {
				do_receive_unix([](int sock) {
					auto in_data = alloc32<char*>(128);
					auto unix = alloc_struct32<sockaddr_un>();;
					unix->sun_family = AF_UNIX;
					auto addrlen = alloc_struct32<socklen_t>();
					*addrlen = sizeof(*unix);

					auto args = alloc_args32(4);
					args[0] = sock;
					args[1] = reinterpret_cast<unsigned long>(in_data);
					args[2] = 128;
					args[3] = MSG_NOSIGNAL;
					args[4] = reinterpret_cast<unsigned long>(unix);
					args[5] = reinterpret_cast<unsigned long>(addrlen);

					syscall32(SyscallNr32::SOCKETCALL, SYS_RECVFROM, args);
				});
			})
		},
		"recvfrom()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
		do_send_unix([](int send_sock, int) {
			unsigned long args[4];
			args[0] = send_sock;
			args[1] = reinterpret_cast<unsigned long>(SEND_DATA.data());
			args[2] = SEND_DATA.size();
			args[3] = MSG_NOSIGNAL;
			syscall(SYS_socketcall, SYS_SEND, args);
		});
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Send, {
			check_send_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_Send, {
			check_send_exit(sc, good);
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls{5}, []() {
				do_send_unix([](int send_sock, int) {
					auto send_data = alloc32<char*>(SEND_DATA.size());
					memcpy(send_data, SEND_DATA.data(), SEND_DATA.size());
					auto args = alloc_args32(4);
					args[0] = send_sock;
					args[1] = reinterpret_cast<unsigned long>(send_data);
					args[2] = SEND_DATA.size();
					args[3] = MSG_NOSIGNAL;
					syscall32(SyscallNr32::SOCKETCALL, SYS_SEND, args);
				});
			})
		},
		"send()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
		do_send_unix([](int send_sock, int) {
			sockaddr_un unix;
			unix.sun_family = AF_UNIX;
			memcpy(unix.sun_path, UNIX_RECEIVER.data(), UNIX_RECEIVER.size());
			socklen_t addrlen = 2 + UNIX_RECEIVER.size();
			unsigned long args[6];
			args[0] = send_sock;
			args[1] = reinterpret_cast<unsigned long>(SEND_DATA.data());
			args[2] = SEND_DATA.size();
			args[3] = MSG_NOSIGNAL;
			args[4] = reinterpret_cast<unsigned long>(&unix);
			args[5] = addrlen;
			syscall(SYS_socketcall, SYS_SENDTO, args);
		});
#endif
		}, ENTRY_VERIFY_CB(SocketCall_SendTo, {
			check_sendto_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_SendTo, {
			check_send_exit(sc, good);
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls{6}, []() {
				do_send_unix([](int send_sock, int) {
					auto addr = alloc_struct32<sockaddr_un>();
					addr->sun_family = AF_UNIX;
					memcpy(addr->sun_path, UNIX_RECEIVER.data(), UNIX_RECEIVER.size());
					auto send_data = alloc32<char*>(SEND_DATA.size());
					memcpy(send_data, SEND_DATA.data(), SEND_DATA.size());
					auto args = alloc_args32(6);
					args[0] = send_sock;
					args[1] = reinterpret_cast<unsigned long>(send_data);
					args[2] = SEND_DATA.size();
					args[3] = MSG_NOSIGNAL;
					args[4] = reinterpret_cast<unsigned long>(addr);
					args[5] = 2 + UNIX_RECEIVER.size();
					syscall32(SyscallNr32::SOCKETCALL, SYS_SENDTO, args);
				});
			})
		},
		"sendto()",
		{clues::ABI::I386}
	},
};

} // end anon ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
