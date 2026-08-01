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

#include <cosmos/compiler.hxx>
#include <cosmos/memory.hxx>

int socket(int af, int type, int prot) {
	return syscall(SYS_socket, af, type, prot);
}

template <typename ADDR>
int bind(int fd, const ADDR &addr, socklen_t addrlen) {
	return syscall(SYS_bind, fd, &addr, addrlen);
}

int main() {

	sockaddr_in ip4;
	sockaddr_in6 ip6;
	sockaddr_un unix;

	cosmos::zero_object(ip4);
	cosmos::zero_object(ip6);
	cosmos::zero_object(unix);

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
	if (bind(fd, unix, un_path.size() + 2) < 0) {

	}
	close(fd);
	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (bind(fd, ip6, sizeof(ip6)) < 0) {

	}
	close(fd);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (bind(fd, ip4, sizeof(ip4)) < 0) {

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
	unsigned long args[6] = {0};

	args[0] = AF_INET6;
	args[1] = SOCK_DGRAM;
	args[2] = IPPROTO_UDP;
	syscall(SYS_socketcall, SYS_SOCKET, args);

	args[0] = AF_UNIX;
	args[1] = SOCK_STREAM;
	args[2] = 0;
	args[3] = reinterpret_cast<unsigned long>(pair);
	syscall(SYS_socketcall, SYS_SOCKETPAIR, args);

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	args[0] = fd;
	args[1] = reinterpret_cast<unsigned long>(&ip6);
	args[2] = sizeof(ip6);
	syscall(SYS_socketcall, SYS_BIND, args);
	close(fd);
#endif
}
