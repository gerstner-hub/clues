// test
#include "../utils/syscalls.hxx"
#include "../utils/socketcall.inl"

// cosmos
#include <cosmos/compiler.hxx>
#include <cosmos/net/unix/aux.hxx>

// clues
#include <clues/items/net.hxx>
#include <clues/private/kernel/msghdr.hxx>

// Linux
#include <sys/socket.h>
#include <linux/net.h>

using namespace std::literals;

namespace {

constexpr std::string_view UNIX_PATH{"\0clues-test"sv};
const std::string_view UNIX_SENDER{"\0send", 5};
const std::string_view UNIX_RECEIVER{"\0recv", 5};
constexpr std::string_view SEND_DATA{"testdata"};
using SocketCB = std::function<void(int)>;
using SocketPairCB = std::function<void(int, int)>;

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

/* performs 3 system calls until the `cb` is executed */
void do_send_unix(SocketPairCB cb) {
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

void verify_unix_msg_header(const cosmos::ReceiveMessageHeader &header, bool &good, bool is_recv) {
	size_t count = 0;
	for (const auto &cmsg: header) {
		VERIFY(cmsg.level() == cosmos::OptLevel::SOCKET);
		VERIFY(*cmsg.asUnixMessage() == cosmos::UnixMessage::RIGHTS);
		cosmos::UnixRightsMessage rights;
		rights.deserialize(cmsg);
		VERIFY(rights.numFDs() == 2);
		cosmos::UnixRightsMessage::FileNumVector fds;
		rights.takeFDs(fds);

		if (is_recv) {
			VERIFY(fds[0] == THIRD_FD);
			VERIFY(fds[1] == cosmos::FileNum{cosmos::to_integral(THIRD_FD) + 1});
		} else {
			VERIFY(fds[0] == cosmos::FileNum::STDIN);
			VERIFY(fds[1] == cosmos::FileNum::STDOUT);
		}
		count++;
	}
	VERIFY(count == 1);
}

void check_sendmsg_entry(const clues::SendMsgSystemCall &sc, bool &good) {
	VERIFY(sc.sockfd.fd() == FIRST_FD);
	VERIFY(sc.flags.flags() == clues::item::SendRecvFlags::MessageFlag::CONFIRM);
	const auto &msg = sc.msg;
	VERIFY(msg.header() != std::nullopt);
	VERIFY(msg.ioVector().size() == 1);
	VERIFY(msg.ioVector()[0].len == 1);
	VERIFY(msg.ioVector()[0].filled == 1);
	VERIFY(msg.controlData().size() > 0);
	verify_unix_msg_header(*msg.header(), good, false);
}

void check_sendmsg_exit(const clues::SendMsgSystemCall &sc, bool &good) {
	VERIFY(sc.hasResultValue());
	VERIFY(sc.written.value() == 1);
}

void check_recvmsg_entry(const clues::RecvMsgSystemCall &sc, bool &good) {
	VERIFY(sc.sockfd.fd() == SECOND_FD);
	VERIFY(sc.flags.flags() == clues::item::SendRecvFlags::MessageFlag::CLOEXEC);
	const auto &msg = sc.msg;
	VERIFY(msg.ioVector().size() == 1);
	VERIFY(msg.ioVector()[0].len == 1);
	VERIFY(msg.ioVector()[0].filled == 0);
	VERIFY(msg.controlData().empty());
	VERIFY(msg.header() == std::nullopt);
}

void check_recvmsg_exit(const clues::RecvMsgSystemCall &sc, bool &good) {
	VERIFY(sc.hasResultValue());
	VERIFY(sc.read.value() == 1);
	const auto &msg = sc.msg;
	VERIFY(msg.header() != std::nullopt);
	VERIFY(msg.ioVector().size() == 1);
	VERIFY(msg.ioVector()[0].len == 1);
	VERIFY(msg.ioVector()[0].filled == 1);
	VERIFY(msg.ioVector()[0].data[0] == std::byte{77});
	verify_unix_msg_header(*msg.header(), good, true);
}

template <bool USE_SOCKETCALL>
void send_fds(int sock) {
	struct msghdr msg;
	cosmos::zero_object(msg);
	struct iovec vec;
	char data = 77;
	vec.iov_base = &data;
	vec.iov_len = sizeof(char);
	int fds[2] = {STDIN_FILENO, STDOUT_FILENO};

	union {
		char buf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u;

	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

	int sent;

	/* this returns only the amount of playoad data in msg_iov */
	if constexpr (USE_SOCKETCALL) {
#ifdef COSMOS_I386
		sent = socketcall(SYS_SENDMSG, sock, &msg, MSG_CONFIRM);
#endif
	} else {
		sent = syscall(SYS_sendmsg, sock, &msg, MSG_CONFIRM);
	}

	if (sent < 0) {
		std::cerr << "failed to sendmsg(): " << strerror(errno) << "\n";
	} else if (static_cast<size_t>(sent) != sizeof(data)) {
		std::cerr << "failed to send full message: " << sent << " vs. " << sizeof(data) << "\n";
		exit(1);
	}
}

template <bool USE_SOCKETCALL>
void recv_fds(int sock) {
	struct msghdr msg;
	cosmos::zero_object(msg);
	struct iovec vec;
	char data;
	vec.iov_base = &data;
	vec.iov_len = sizeof(char);
	char ancillary[1024];

	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = ancillary;
	msg.msg_controllen = sizeof(ancillary);

	int received;

	if constexpr (USE_SOCKETCALL) {
#ifdef COSMOS_I386
		received = socketcall(SYS_RECVMSG, sock, &msg, MSG_CMSG_CLOEXEC);
#endif
	} else {
		received = syscall(SYS_recvmsg, sock, &msg, MSG_CMSG_CLOEXEC);
	}

	if (received != sizeof(char)) {
		std::cerr << "received unexpected byte count: " << received << "\n";
		exit(1);
	}

	for (auto cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		const auto fd_len = cmsg->cmsg_len - CMSG_LEN(0);

		std::vector<int> fds(fd_len / sizeof(int));
		memcpy(fds.data(), CMSG_DATA(cmsg), fd_len);

		for (auto fd: fds) {
			close(fd);
		}
	}
}

#ifdef TEST_I386_EMU

/* variant for 32-bit cross ABI tracing. Differences in data structures and
 * memory management are too big to keep common code around :-/ */
template <bool USE_SOCKETCALL>
void send_fds32(int sock) {
	auto msg = alloc_struct_abi<clues::msghdr32>();
	cosmos::zero_object(*msg);
	auto vec = alloc_struct_abi<clues::iovec32>();
	auto data = alloc_abi<char*>(1);
	*data = 77;
	vec->iov_base = to_compat_ptr(data);
	vec->iov_len = sizeof(char);
	int fds[2] = {STDIN_FILENO, STDOUT_FILENO};

	union ControlBuf {
		char buf[CMSG_SPACE(sizeof(fds))];
		clues::cmsghdr32 align;
	};

	auto control = alloc_struct_abi<ControlBuf>();

	/*
	 * we cannot use the CMSG_ macros for cross-abi system calls due to
	 * differences in padding. Use the hard coded pre-computed value of 20
	 * here for simplicity.
	 */

	msg->msg_iov = to_compat_ptr(vec);
	msg->msg_iovlen = 1;
	msg->msg_control = to_compat_ptr(control);
	msg->msg_controllen = 20;

	clues::cmsghdr32 *cmsg = &control->align;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = 20;
	memcpy((char*)cmsg + sizeof(*cmsg), fds, sizeof(fds));

	int sent;

	/* this returns only the amount of playoad data in msg_iov */
	if constexpr (USE_SOCKETCALL) {
		sent = socketcall32(SYS_SENDMSG, sock, msg, MSG_CONFIRM);
	} else {
		sent = syscall32(SyscallNr32::SENDMSG, sock, msg, MSG_CONFIRM);
	}

	constexpr auto PAYLOAD_LEN = sizeof(*data);

	if (sent < 0) {
		std::cerr << "failed to sendmsg: " << strerror(errno) << "\n";
		exit(1);
	} else if (static_cast<size_t>(sent) != PAYLOAD_LEN) {
		std::cerr << "failed to send full message: " << sent << " vs. " << PAYLOAD_LEN << "\n";
		exit(1);
	}
}

template <bool USE_SOCKETCALL>
void recv_fds32(int sock) {
	auto msg = alloc_struct_abi<clues::msghdr32>();
	cosmos::zero_object(*msg);
	auto vec = alloc_struct_abi<clues::iovec32>();
	auto data = alloc_abi<char*>(1);
	*data = 77;
	vec->iov_base = to_compat_ptr(data);
	vec->iov_len = sizeof(char);
	constexpr auto CONTROLBUF_LEN = 1024;
	auto control = alloc_abi<char*>(CONTROLBUF_LEN);

	msg->msg_iov = to_compat_ptr(vec);
	msg->msg_iovlen = 1;
	msg->msg_control = to_compat_ptr(control);
	msg->msg_controllen = CONTROLBUF_LEN;

	int received;

	if constexpr (USE_SOCKETCALL) {
		received = socketcall32(SYS_RECVMSG, sock, msg, MSG_CMSG_CLOEXEC);
	} else {
		received = syscall32(SyscallNr32::RECVMSG, sock, msg, MSG_CMSG_CLOEXEC);
	}

	if (received != sizeof(char)) {
		std::cerr << "received unexpected byte count: " << received << "\n";
		exit(1);
	}
}

#endif // TEST_I386_EMU

/* performs 4 system calls, sends 8 byte of data, binds to '\0send'  */
void do_receive_unix(SocketCB cb) {
	do_send_unix([cb](int send_sock, int recv_sock) {
		syscall(SYS_sendto, send_sock, SEND_DATA.data(), SEND_DATA.size(),
				MSG_NOSIGNAL, nullptr, 0);

		cb(recv_sock);
	});
}

void accept_conn(SocketCB cb) {
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
			socketcall(SYS_SOCKET, AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Socket, {
			check_socket_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_Socket, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				socketcall32(SYS_SOCKET, AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP);
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
			socketcall(SYS_SOCKETPAIR, AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, sv);
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
				socketcall32(SYS_SOCKETPAIR, AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, sv);
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
			socketcall(SYS_BIND, sock, &unix, addrlen);
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Bind, {
			check_bind_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_Bind, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
				auto unix = alloc_struct32<struct sockaddr_un>();
				const auto addrlen = setup_unixaddr(*unix);
				socketcall32(SYS_BIND, sock, unix, addrlen);
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
			socketcall(SYS_CONNECT, sock, &ip4, sizeof(ip4));
#endif
		}, ENTRY_VERIFY_CB(SocketCall_Connect, {
			check_connect_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_Connect, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int sock = socket(AF_INET, SOCK_DGRAM, 0);
				auto ip4 = alloc_struct32<sockaddr_in>();
				ip4->sin_family = AF_INET;
				ip4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				ip4->sin_port = htons(1234);
				socketcall32(SYS_CONNECT, sock, ip4, sizeof(*ip4));
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
			socketcall(SYS_LISTEN, sock, 15);
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
				socketcall32(SYS_LISTEN, sock, 15);
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
				socketcall(SYS_ACCEPT, sock, &addr, &len);
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
					socketcall32(SYS_ACCEPT, sock, addr, len);
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
				socketcall(SYS_ACCEPT4, sock, &addr, &len, SOCK_CLOEXEC);
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
					socketcall32(SYS_ACCEPT4, sock, addr, len, SOCK_CLOEXEC);
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
				socketcall(SYS_SHUTDOWN, conn, SHUT_WR);
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
			
					socketcall32(SYS_SHUTDOWN, conn, SHUT_WR);
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
				socketcall(SYS_GETSOCKNAME, sock, &unix, &len);
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
					socketcall32(SYS_GETSOCKNAME, sock, unix, len);
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
				socketcall(SYS_GETPEERNAME, sock, &ip, &len);
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
					socketcall32(SYS_GETPEERNAME, sock, ip, len);
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
			socketcall(SYS_RECV, sock, in_data, sizeof(in_data), MSG_NOSIGNAL);
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

					socketcall32(SYS_RECV, sock, in_data, 128, MSG_NOSIGNAL);
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

			socketcall(SYS_RECVFROM, sock, in_data, sizeof(in_data), MSG_NOSIGNAL,
					&unix, &addrlen);
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

					socketcall32(SYS_RECVFROM, sock, in_data, 128,
							MSG_NOSIGNAL, unix, addrlen);
				});
			})
		},
		"recvfrom()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
		do_send_unix([](int send_sock, int) {
			socketcall(SYS_SEND, send_sock, SEND_DATA.data(), SEND_DATA.size(), MSG_NOSIGNAL);
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
					socketcall32(SYS_SEND, send_sock, send_data,
							SEND_DATA.size(), MSG_NOSIGNAL);
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
			socketcall(SYS_SENDTO, send_sock, SEND_DATA.data(), SEND_DATA.size(),
					MSG_NOSIGNAL, &unix, addrlen);
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
					socketcall32(SYS_SENDTO, send_sock, send_data, SEND_DATA.size(),
							MSG_NOSIGNAL, addr, UNIX_RECEIVER.size() + 2);
				});
			})
		},
		"sendto()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::RECVMSG, []() {
			auto send_recv_cb = [](int send_sock, int recv_sock) {
				send_fds<false>(send_sock);
				recv_fds<false>(recv_sock);
			};

			do_send_unix(send_recv_cb);
		}, ENTRY_VERIFY_CB(RecvMsgSystemCall, {
			check_recvmsg_entry(sc, good);
		}), EXIT_VERIFY_CB(RecvMsgSystemCall, {
			check_recvmsg_exit(sc, good);
		}), IgnoreCalls::AUTO, {
			I386_CROSS_ABI(IgnoreCalls::AUTO, []() {
				auto send_recv_cb = [](int send_sock, int recv_sock) {
					send_fds32<false>(send_sock);
					recv_fds32<false>(recv_sock);
				};

				do_send_unix(send_recv_cb);
			})
		}
	},
	TestSpec{SystemCallNr::SENDMSG, []() {
			auto send_recv_cb = [](int send_sock, int) {
				send_fds<false>(send_sock);
			};

			do_send_unix(send_recv_cb);
		}, ENTRY_VERIFY_CB(SendMsgSystemCall, {
			check_sendmsg_entry(sc, good);
		}), EXIT_VERIFY_CB(SendMsgSystemCall, {
			check_sendmsg_exit(sc, good);
		}), IgnoreCalls::AUTO, {
			I386_CROSS_ABI(IgnoreCalls::AUTO, []() {
				auto send_recv_cb = [](int send_sock, int recv_sock) {
					send_fds32<false>(send_sock);
					recv_fds32<false>(recv_sock);
				};

				do_send_unix(send_recv_cb);
			})
		}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
		auto send_recv_cb = [](int send_sock, int recv_sock) {
			send_fds<false>(send_sock);
			recv_fds<true>(recv_sock);
		};

		do_send_unix(send_recv_cb);
#endif
		}, ENTRY_VERIFY_CB(SocketCall_RecvMsg, {
			check_recvmsg_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_RecvMsg, {
			check_recvmsg_exit(sc, good);
		// IgnoreCalls::AUTO won't work here, because of multiple
		// socketcalls happening.
		}), IgnoreCalls{4}, {
			I386_CROSS_ABI(IgnoreCalls::AUTO, []() {
				auto send_recv_cb = [](int send_sock, int recv_sock) {
					send_fds<false>(send_sock);
					recv_fds32<true>(recv_sock);
				};

				do_send_unix(send_recv_cb);
			})
		},
		"recvmsg()",
		{clues::ABI::I386}
	},
	TestSpec{SystemCallNr::SOCKETCALL, []() {
#ifdef COSMOS_I386
		auto send_recv_cb = [](int send_sock, int) {
			send_fds<true>(send_sock);
		};

		do_send_unix(send_recv_cb);
#endif
		}, ENTRY_VERIFY_CB(SocketCall_SendMsg, {
			check_sendmsg_entry(sc, good);
		}), EXIT_VERIFY_CB(SocketCall_SendMsg, {
			check_sendmsg_exit(sc, good);
		// IgnoreCalls::AUTO won't work here, because of multiple
		// socketcalls happening.
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls::AUTO, []() {
				auto send_recv_cb = [](int send_sock, int) {
					send_fds32<true>(send_sock);
				};

				do_send_unix(send_recv_cb);
			})
		},
		"sendmsg()",
		{clues::ABI::I386}
	},
};

} // end anon ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
