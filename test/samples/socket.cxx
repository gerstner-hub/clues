#include <linux/if_ether.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <string>

#include <optional>
#include <iostream>
#include <vector>
#include <array>

#include <cosmos/compiler.hxx>
#include <cosmos/memory.hxx>

int socket(int af, int type, int prot) {
	return syscall(SYS_socket, af, type, prot);
}

#ifdef COSMOS_I386
template <typename T>
unsigned long to_ulong(T value) {
    if constexpr (std::is_pointer_v<T>) {
        return reinterpret_cast<unsigned long>(value);
    } else {
        return static_cast<unsigned long>(value);
    }
}

template <typename... ARGS>
requires (sizeof...(ARGS) <= 6)
std::array<unsigned long, sizeof...(ARGS)> make_array(ARGS... args) {
    std::array<unsigned long, sizeof...(ARGS)> result{};

    std::size_t i = 0;
    ((result[i++] = to_ulong(args)), ...);

    return result;
}

template <typename... ARGS>
int socketcall(int call, ARGS... args) {
	const auto arr = make_array(std::forward<ARGS>(args)...);

	return syscall(SYS_socketcall, call, arr.data());
}
#endif

template <typename ADDR>
int bind(int fd, const ADDR &addr, std::optional<socklen_t> addrlen = {}) {
	auto ret = syscall(SYS_bind, fd, &addr, addrlen ? *addrlen : sizeof(addr));

	if (ret == 0) {
		syscall(SYS_listen, fd, 15);
	}

	return ret;
}

template <typename ADDR>
int connect(int type, const ADDR &addr, std::optional<socklen_t> addrlen = {},
		int flags=0, bool auto_close=true) {
	const struct sockaddr *saddr = reinterpret_cast<const struct sockaddr*>(&addr);
	auto sock = socket(saddr->sa_family, type|flags, 0);

	int ret = syscall(SYS_connect, sock, saddr, addrlen ? *addrlen : sizeof(addr));

	if (ret != 0 || auto_close)
		close(sock);

	return auto_close ? ret : (ret == 0 ? sock : ret);
}

void send_recv(int send_sock, int recv_sock) {
	const char outbuf[] = "test message";
	syscall(SYS_sendto, send_sock, outbuf, sizeof(outbuf)-1, MSG_NOSIGNAL, nullptr, 0);

	char inbuf[1024];
	const auto bytes = syscall(SYS_recvfrom, recv_sock, inbuf, sizeof(inbuf), MSG_DONTROUTE, nullptr, 0UL);
	(void)bytes;
}

void send_recv_msg(int send_sock, int recv_sock, const sockaddr_un &send_addr, const size_t addrlen) {
	int passcred = 1;
	syscall(SYS_setsockopt, send_sock, SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred));
	syscall(SYS_setsockopt, recv_sock, SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred));
	const char outbuf[] = "test message";
	struct msghdr hdr;
	cosmos::zero_object(hdr);
	hdr.msg_name = (void*)&send_addr;
	hdr.msg_namelen = addrlen;
	struct iovec vec;
	vec.iov_base = (void*)outbuf;
	vec.iov_len = sizeof(outbuf) - 1;
	hdr.msg_iov = &vec;
	hdr.msg_iovlen = 1;
	auto bytes = syscall(SYS_sendmsg, send_sock, &hdr, MSG_NOSIGNAL);

	char inbuf[1024];
	sockaddr_un from_addr;
	char ctrlbuf[1024];
	hdr.msg_name = (void*)&from_addr;
	hdr.msg_namelen = sizeof(from_addr);
	hdr.msg_control = (void*)ctrlbuf;
	hdr.msg_controllen = sizeof(ctrlbuf);
	vec.iov_base = (void*)inbuf;
	vec.iov_len = sizeof(inbuf);

	bytes = syscall(SYS_recvmsg, recv_sock, &hdr, MSG_NOSIGNAL);
	(void)bytes;
}

#ifdef COSMOS_I386
void send_recv_socketcall(int send_sock, int recv_sock, const std::string &tgt_addr_path = {}) {
	const char outbuf[] = "test message";

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, tgt_addr_path.c_str(), tgt_addr_path.size());

	if (tgt_addr_path.empty()) {
		socketcall(SYS_SEND, send_sock, outbuf, sizeof(outbuf) - 1, MSG_NOSIGNAL);
	} else {
		socketcall(SYS_SENDTO, send_sock, outbuf, sizeof(outbuf) - 1, MSG_NOSIGNAL, &addr, tgt_addr_path.size() + 2);
	}

	char inbuf[1024];

	if (tgt_addr_path.empty()) {
		socketcall(SYS_RECV, recv_sock, inbuf, sizeof(inbuf), MSG_DONTROUTE);
	} else {
		socklen_t addrlen = sizeof(sockaddr_un);
		socketcall(SYS_RECVFROM, recv_sock, inbuf, sizeof(inbuf), MSG_DONTROUTE, &addr, &addrlen);
	}
}
#endif

void pass_fds_to(int sock_to) {
	struct msghdr msg;
	cosmos::zero_object(msg);
	struct iovec vec;
	char data = 42;
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


	/* this returns only the amount of playoad data in msg_iov */
	const auto sent = syscall(SYS_sendmsg, sock_to, &msg, 0);
	if (sent < 0 || static_cast<size_t>(sent) != sizeof(data)) {
		std::cerr << "failed to send full message: " << sent << " vs. " << sizeof(data) << "\n";
		exit(1);
	}
}

void recv_fds_from(int sock_from) {
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

	const auto received = syscall(SYS_recvmsg, sock_from, &msg, MSG_CMSG_CLOEXEC);
	if (received != sizeof(char)) {
		std::cerr << "received unexpected byte count: " << received << "\n";
		exit(1);
	}

	for (auto cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		const auto fd_len = cmsg->cmsg_len - CMSG_LEN(0);

		std::vector<int> fds(fd_len / sizeof(int));
		memcpy(fds.data(), CMSG_DATA(cmsg), fd_len);

		for (auto fd: fds) {
			std::cout << "received fd " << fd << "\n";
			close(fd);
		}
	}
}

int main() {
	sockaddr_in ip4;
	sockaddr_in6 ip6;
	sockaddr_un unix;
	sockaddr_un unix2;

	cosmos::zero_object(ip4);
	cosmos::zero_object(ip6);
	cosmos::zero_object(unix);
	cosmos::zero_object(unix2);

	ip4.sin_family = AF_INET;
	ip6.sin6_family = AF_INET6;
	unix.sun_family = AF_UNIX;

	ip4.sin_port = htons(1234);
	ip4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	ip6.sin6_port = htons(1234);
	ip6.sin6_flowinfo = 4321;
	std::memcpy(ip6.sin6_addr.s6_addr, &in6addr_loopback, sizeof(in6addr_loopback));
	ip6.sin6_scope_id = 0;

	std::string un_path;
	un_path += '\0';
	un_path += "testsocket";

	std::string un_path2;
	un_path2 += '\0';
	un_path2 += "sendsocket";

	std::memcpy(unix.sun_path, un_path.data(), un_path.size());

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (bind(fd, unix, un_path.size() + 2) == 0) {
		{
			socklen_t len = sizeof(unix2);
			syscall(SYS_getsockname, fd, (sockaddr*)&unix2, &len);
		}
#ifdef SYS_accept
		if (connect(SOCK_STREAM, unix, un_path.size() + 2, SOCK_NONBLOCK) == 0) {
			sockaddr_un peer;
			socklen_t len = sizeof(peer);
			int acc_sock = syscall(SYS_accept, fd, (sockaddr*)&peer, &len);

			close(acc_sock);
		}
#endif
		if (auto conn = connect(SOCK_STREAM, unix, un_path.size() + 2, SOCK_NONBLOCK, /*auto_close=*/false); conn >= 0) {
			sockaddr_un peer;
			socklen_t len = sizeof(peer);
			int acc_sock = syscall(SYS_accept4, fd, (sockaddr*)&peer, &len, SOCK_CLOEXEC);
			len = sizeof(unix2);
			syscall(SYS_getpeername, acc_sock, (sockaddr*)&unix2, &len);
			send_recv(conn, acc_sock);
#ifdef COSMOS_I386
			send_recv_socketcall(conn, acc_sock);
#endif
			syscall(SYS_shutdown, acc_sock, SHUT_RDWR);
			close(acc_sock);
			close(conn);
		}

		if (auto conn = connect(SOCK_STREAM, unix, un_path.size() + 2, 0, /*auto_close=*/false); conn >= 0) {
			/* let's do a round of file descriptor passing to
			 * utilize recvmsg() / sendmsg() */
			int conn2 = accept(fd, NULL, 0);
			if (conn2 < 0)
				return 1;

			pass_fds_to(conn2);
			recv_fds_from(conn);

			close(conn);
			close(conn2);
		}

#ifdef COSMOS_I386
		if (connect(SOCK_STREAM, unix, un_path.size() + 2, SOCK_NONBLOCK) == 0) {
			sockaddr_un peer;
			socklen_t len = sizeof(peer);
			int acc_sock = socketcall(SYS_ACCEPT, fd, &peer, &len);
			close(acc_sock);
		}
		if (connect(SOCK_STREAM, unix, un_path.size() + 2, SOCK_NONBLOCK) == 0) {
			sockaddr_un peer;
			socklen_t len = sizeof(peer);
			int acc_sock = socketcall(SYS_ACCEPT4, fd, &peer, &len, SOCK_NONBLOCK);
			close(acc_sock);
		}
#endif
	}
	close(fd);
	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (bind(fd, ip6) == 0) {
		if (connect(SOCK_DGRAM, ip6) < 0) {

		}
	}
	close(fd);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (bind(fd, ip4) == 0) {
		if (connect(SOCK_STREAM, ip4) < 0 ) {

		}
	}
	close(fd);

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	close(fd);
	fd = socket(AF_PACKET, SOCK_RAW, ETH_P_DIAG);
	close(fd);

	int pair[2];
	syscall(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, pair);
	close(pair[0]);
	close(pair[1]);

	syscall(SYS_socketpair, AF_UNIX, SOCK_DGRAM, 0, pair);
	std::memcpy(unix.sun_path, un_path.data(), un_path.size());
	if (bind(pair[0], unix, un_path.size() + 2) < 0) {

	}
	std::memcpy(unix2.sun_path, un_path2.data(), un_path2.size());
	if (bind(pair[1], unix2, un_path2.size() + 2) < 0) {

	}
	send_recv_msg(pair[0], pair[1], unix2, un_path2.size() + 2);
	close(pair[0]);
	close(pair[1]);

#ifdef COSMOS_I386
	socketcall(SYS_SOCKET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	socketcall(SYS_SOCKETPAIR, AF_UNIX, SOCK_DGRAM, 0, pair);

	if (bind(pair[1], unix, un_path.size() + 2) < 0) {
		return 1;
	}

	memcpy(unix.sun_path, un_path2.data(), un_path2.size());

	if (bind(pair[0], unix, un_path2.size() + 2) < 0) {
		return 1;
	}

	send_recv_socketcall(pair[0], pair[1], un_path);

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (socketcall(SYS_BIND, fd, &ip6, sizeof(ip6)) == 0) {
		socketcall(SYS_LISTEN, fd, 15);

		auto conn = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		socketcall(SYS_CONNECT, conn, &ip6, sizeof(ip6));

		socklen_t len = sizeof(ip6);
		socketcall(SYS_GETPEERNAME, conn, &ip6, &len);
		socketcall(SYS_SHUTDOWN, conn, SHUT_WR);
		socketcall(SYS_GETSOCKNAME, fd, &ip6, &len);

	}
	close(fd);
#endif
}
