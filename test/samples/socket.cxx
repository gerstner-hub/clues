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
#include <cosmos/compiler.hxx>
#include <cosmos/memory.hxx>

#ifdef COSMOS_I386
#	include <array>
#endif

#include "../utils/socketcall.inl"

/*
 * On I386 socketcall() is used by default by glibc, thus use explicit
 * syscall() wrappers for the regular system calls and explicit socketcall()
 * wrappers if we want to do socketcall().
 */

constexpr auto UNIXADDR_BASE_SIZE = offsetof(struct sockaddr_un, sun_path);

int socket(int af, int type, int prot) {
	return syscall(SYS_socket, af, type, prot);
}

template <typename ADDR>
void bind_and_listen(int fd, const ADDR &addr, std::optional<socklen_t> addrlen = {}) {
	auto ret = syscall(SYS_bind, fd, &addr, addrlen ? *addrlen : sizeof(addr));

	if (ret == 0) {
		syscall(SYS_listen, fd, 15);
	} else {
		throw "failed to bind";
	}
}

template <typename ADDR>
int socket_connect(int type, const ADDR &addr, std::optional<socklen_t> addrlen = {},
		int flags=0, bool auto_close=true) {
	const struct sockaddr *saddr = reinterpret_cast<const struct sockaddr*>(&addr);
	auto sock = socket(saddr->sa_family, type|flags, 0);

	int ret = syscall(SYS_connect, sock, saddr, addrlen ? *addrlen : sizeof(addr));

	if (ret != 0 || auto_close)
		close(sock);
	if (ret != 0) {
		throw "failed to connect";
	}

	return auto_close ? -1 : sock;
}

void send_recv(int send_sock, int recv_sock) {
	const char outbuf[] = "test message";
	syscall(SYS_sendto, send_sock, outbuf, sizeof(outbuf)-1, MSG_NOSIGNAL, nullptr, 0);

	char inbuf[1024];
	const auto bytes = syscall(SYS_recvfrom, recv_sock, inbuf, sizeof(inbuf), MSG_DONTROUTE, nullptr, 0UL);
	(void)bytes;
}

void send_recv_msg(int send_sock, int recv_sock, const sockaddr_un &send_addr, const size_t addrlen,
		bool use_socketcall = false) {
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
	if (use_socketcall) {
#ifdef COSMOS_I386
		socketcall(SYS_SENDMSG, send_sock, &hdr, MSG_NOSIGNAL);
#else
		throw "no socketcall on non-i386";
#endif
	} else {
		(void)syscall(SYS_sendmsg, send_sock, &hdr, MSG_NOSIGNAL);
	}

	char inbuf[1024];
	sockaddr_un from_addr;
	char ctrlbuf[1024];
	hdr.msg_name = (void*)&from_addr;
	hdr.msg_namelen = sizeof(from_addr);
	hdr.msg_control = (void*)ctrlbuf;
	hdr.msg_controllen = sizeof(ctrlbuf);
	vec.iov_base = (void*)inbuf;
	vec.iov_len = sizeof(inbuf);

	if (use_socketcall) {
#ifdef COSMOS_I386
		(void)socketcall(SYS_RECVMSG, recv_sock, &hdr, MSG_NOSIGNAL);
#endif
	} else {
		(void)syscall(SYS_recvmsg, recv_sock, &hdr, MSG_NOSIGNAL);
	}
}

#ifdef COSMOS_I386
void send_recv_socketcall(int send_sock, int recv_sock, const std::string &tgt_addr_path = {}) {
	const char outbuf[] = "test message";

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, tgt_addr_path.c_str(), tgt_addr_path.size()+1);

	int res;

	if (tgt_addr_path.empty()) {
		res = socketcall(SYS_SEND, send_sock, outbuf, sizeof(outbuf) - 1, MSG_NOSIGNAL);
	} else {
		res = socketcall(SYS_SENDTO, send_sock, outbuf, sizeof(outbuf) - 1, MSG_NOSIGNAL, &addr, tgt_addr_path.size() + 1 + UNIXADDR_BASE_SIZE);
	}

	if (res < 0) {
		throw "send(to) failed";
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

socklen_t set_unix_addr(sockaddr_un &unix, const std::string &path) {
	std::memcpy(unix.sun_path, path.data(), path.size());

	return path.size() + UNIXADDR_BASE_SIZE + 1;
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
	unix2.sun_family = AF_UNIX;

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

	socklen_t addrlen, addrlen2;
	addrlen = set_unix_addr(unix, un_path);

	int sock1 = -1, sock2 = -1, sock3 = -1;
	int pair[2];

	/*
	 *  AF_UNIX
	 */

	sock1 = socket(AF_UNIX, SOCK_STREAM, 0);
	bind_and_listen(sock1, unix, addrlen);

	addrlen2 = sizeof(unix2);
	syscall(SYS_getsockname, sock1, (sockaddr*)&unix2, &addrlen2);

#ifdef SYS_accept /* not all ABIs have the old accept() anymore */
	socket_connect(SOCK_STREAM, unix, addrlen, SOCK_NONBLOCK);
	addrlen2 = sizeof(unix2);
	sock2 = syscall(SYS_accept, sock1, (sockaddr*)&unix2, &addrlen2);
	close(sock2);
#endif
	sock2 = socket_connect(SOCK_STREAM, unix, addrlen, SOCK_NONBLOCK, /*auto_close=*/false);
	addrlen2 = sizeof(unix2);
	sock3 = syscall(SYS_accept4, sock1, (sockaddr*)&unix2, &addrlen2, SOCK_CLOEXEC);
	addrlen2 = sizeof(unix2);
	syscall(SYS_getpeername, sock3, (sockaddr*)&unix2, &addrlen2);
	send_recv(sock2, sock3);
#ifdef COSMOS_I386
	send_recv_socketcall(sock2, sock3);
#endif
	syscall(SYS_shutdown, sock3, SHUT_RDWR);
	close(sock3);
	close(sock2);

	sock2 = socket_connect(SOCK_STREAM, unix, addrlen, 0, /*auto_close=*/false);
	/* let's do a round of file descriptor passing to
	 * utilize recvmsg() / sendmsg() */
	sock3 = accept(sock1, NULL, 0);
	if (sock3 < 0) {
		throw "failed to accept";
	}

	pass_fds_to(sock3);
	recv_fds_from(sock2);

	close(sock2);
	close(sock3);

#ifdef COSMOS_I386
	socket_connect(SOCK_STREAM, unix, addrlen, SOCK_NONBLOCK);
	addrlen2 = sizeof(unix2);
	sock3 = socketcall(SYS_ACCEPT, sock1, &unix2, &addrlen2);
	close(sock3);

	socket_connect(SOCK_STREAM, unix, addrlen, SOCK_NONBLOCK);
	addrlen2 = sizeof(unix2);
	sock3 = socketcall(SYS_ACCEPT4, sock1, &unix2, &addrlen2, SOCK_NONBLOCK);
	close(sock3);
#endif

	close(sock1);

	/*
	 * end AF_UNIX
	 */

	sock1 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	bind_and_listen(sock1, ip6);
	socket_connect(SOCK_DGRAM, ip6);
	close(sock1);

	sock1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bind_and_listen(sock1, ip4);
	socket_connect(SOCK_STREAM, ip4);
	close(sock1);

	sock1 = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	close(sock1);

	sock1 = socket(AF_PACKET, SOCK_RAW, ETH_P_DIAG);
	close(sock1);

	syscall(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, pair);
	close(pair[0]);
	close(pair[1]);

	syscall(SYS_socketpair, AF_UNIX, SOCK_DGRAM, 0, pair);
	bind_and_listen(pair[0], unix, addrlen);
	addrlen2 = set_unix_addr(unix2, un_path2);
	bind_and_listen(pair[1], unix2, addrlen2);
	send_recv_msg(pair[0], pair[1], unix2, addrlen2);
#ifdef COSMOS_I386
	send_recv_msg(pair[0], pair[1], unix2, addrlen2, /*use_socketcall=*/true);
#endif
	close(pair[0]);
	close(pair[1]);

#ifdef COSMOS_I386
	socketcall(SYS_SOCKET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	socketcall(SYS_SOCKETPAIR, AF_UNIX, SOCK_DGRAM, 0, pair);
	bind_and_listen(pair[1], unix, addrlen);
	addrlen2 = set_unix_addr(unix2, un_path2);
	bind_and_listen(pair[0], unix2, addrlen2);
	send_recv_socketcall(pair[0], pair[1], un_path);
	close(pair[0]);
	close(pair[1]);

	sock1 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (socketcall(SYS_BIND, sock1, &ip6, sizeof(ip6)) < 0) {
		throw "failed to socketcall-bind";
	}

	socketcall(SYS_LISTEN, sock1, 15);

	sock2 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	socketcall(SYS_CONNECT, sock2, &ip6, sizeof(ip6));

	addrlen = sizeof(ip6);
	socketcall(SYS_GETPEERNAME, sock2, &ip6, &addrlen);
	socketcall(SYS_SHUTDOWN, sock2, SHUT_WR);
	socketcall(SYS_GETSOCKNAME, sock1, &ip6, &addrlen);

	close(sock1);
	close(sock2);
#endif
}
