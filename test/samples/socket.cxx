#include <linux/if_ether.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cosmos/compiler.hxx>

int socket(int af, int type, int prot) {
	return syscall(SYS_socket, af, type, prot);
}

int main() {
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	close(fd);
	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	close(fd);
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	close(fd);
	fd = socket(AF_PACKET, SOCK_RAW, ETH_P_DIAG);
	close(fd);

#ifdef COSMOS_I386
	int args[6] = {0};

	args[0] = AF_INET6;
	args[1] = SOCK_DGRAM;
	args[2] = IPPROTO_UDP;
	syscall(SYS_socketcall, SYS_SOCKET, args);
#endif
}
