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

#include <cosmos/compiler.hxx>
#include <cosmos/memory.hxx>

int socket(int af, int type, int prot) {
	return syscall(SYS_socket, af, type, prot);
}

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
	const auto bytes = syscall(SYS_recvfrom, recv_sock, inbuf, sizeof(inbuf), MSG_DONTROUTE, nullptr, 0);
	(void)bytes;
}

#ifdef COSMOS_I386
void send_recv_socketcall(int send_sock, int recv_sock, const std::string &tgt_addr_path = {}) {
	unsigned long args[6];

	const char outbuf[] = "test message";
	args[0] = send_sock;
	args[1] = reinterpret_cast<unsigned long>(outbuf);
	args[2] = sizeof(outbuf) - 1;
	args[3] = MSG_NOSIGNAL;

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, tgt_addr_path.c_str(), tgt_addr_path.size());

	if (tgt_addr_path.empty()) {
		syscall(SYS_socketcall, SYS_SEND, args);
	} else {
		args[4] = reinterpret_cast<unsigned long>(&addr);
		args[5] = tgt_addr_path.size() + 2;
		syscall(SYS_socketcall, SYS_SENDTO, args);
	}

	char inbuf[1024];
	args[0] = recv_sock;
	args[1] = reinterpret_cast<unsigned long>(inbuf);
	args[2] = sizeof(inbuf);
	args[3] = MSG_DONTROUTE;

	if (tgt_addr_path.empty()) {
		syscall(SYS_socketcall, SYS_RECV, args);
	} else {
		socklen_t addrlen = sizeof(sockaddr_un);
		args[5] = reinterpret_cast<unsigned long>(&addrlen);
		syscall(SYS_socketcall, SYS_RECVFROM, args);
	}
}
#endif

int main() {
#ifdef COSMOS_I386
	unsigned long args[6] = {0};
#endif

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
#ifdef COSMOS_I386
		if (connect(SOCK_STREAM, unix, un_path.size() + 2, SOCK_NONBLOCK) == 0) {
			sockaddr_un peer;
			socklen_t len = sizeof(peer);
			args[0] = fd;
			args[1] = (unsigned long)&peer;
			args[2] = (unsigned long)&len;
			int acc_sock = syscall(SYS_socketcall, SYS_ACCEPT, args);
			close(acc_sock);
		}
		if (connect(SOCK_STREAM, unix, un_path.size() + 2, SOCK_NONBLOCK) == 0) {
			sockaddr_un peer;
			socklen_t len = sizeof(peer);
			args[0] = fd;
			args[1] = (unsigned long)&peer;
			args[2] = (unsigned long)&len;
			args[3] = SOCK_NONBLOCK;
			int acc_sock = syscall(SYS_socketcall, SYS_ACCEPT4, args);
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

#ifdef COSMOS_I386
	args[0] = AF_INET6;
	args[1] = SOCK_DGRAM;
	args[2] = IPPROTO_UDP;
	syscall(SYS_socketcall, SYS_SOCKET, args);

	args[0] = AF_UNIX;
	args[1] = SOCK_DGRAM;
	args[2] = 0;
	args[3] = reinterpret_cast<unsigned long>(pair);
	syscall(SYS_socketcall, SYS_SOCKETPAIR, args);

	if (bind(pair[1], unix, un_path.size() + 2) < 0) {
		return 1;
	}

	std::string un_path2;
	un_path2 += '\0';
	un_path2 += "sendsocket";
	memcpy(unix.sun_path, un_path2.data(), un_path2.size());

	if (bind(pair[0], unix, un_path2.size() + 2) < 0) {
		return 1;
	}

	send_recv_socketcall(pair[0], pair[1], un_path);

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	args[0] = fd;
	args[1] = reinterpret_cast<unsigned long>(&ip6);
	args[2] = sizeof(ip6);
	if (syscall(SYS_socketcall, SYS_BIND, args) == 0) {
		args[1] = 15;
		syscall(SYS_socketcall, SYS_LISTEN, args);

		auto conn = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		args[0] = conn;
		args[1] = reinterpret_cast<unsigned long>(&ip6);
		syscall(SYS_socketcall, SYS_CONNECT, args);

		socklen_t len = sizeof(ip6);
		args[2] = reinterpret_cast<unsigned long>(&len);
		syscall(SYS_socketcall, SYS_GETPEERNAME, args);

		args[1] = SHUT_WR;
		syscall(SYS_socketcall, SYS_SHUTDOWN, args);

		args[0] = fd;
		args[1] = reinterpret_cast<unsigned long>(&ip6);
		args[2] = reinterpret_cast<unsigned long>(&len);
		syscall(SYS_socketcall, SYS_GETSOCKNAME, args);

	}
	close(fd);
#endif
}
