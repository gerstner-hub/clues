#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <string>
#include <linux/filter.h>

void sol_socket() {
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	int i = 0;
	socklen_t len = sizeof(i);
	getsockopt(s, SOL_SOCKET, SO_DONTROUTE, &i, &len);
	i = 1;
	setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &i, sizeof(i));
	/* test incomplete option read */
	i = 4711;
	len = 0;
	getsockopt(s, SOL_SOCKET, SO_DONTROUTE, &i, &len);

	len = sizeof(i);

	getsockopt(s, SOL_SOCKET, SO_BROADCAST, &i, &len);

	i = 1;

	setsockopt(s, SOL_SOCKET, SO_BROADCAST, &i, sizeof(i));

	/* test bad option name */
	getsockopt(s, SOL_SOCKET, 348734873, &i, &len);
	/* test bad option level */
	getsockopt(s, 349834, 0, &i, &len);

	i = 20;
	setsockopt(s, SOL_SOCKET, SO_PRIORITY, &i, sizeof(i));
	len = sizeof(i);
	getsockopt(s, SOL_SOCKET, SO_PRIORITY, &i, &len);

	std::string stropt;
	stropt = "lo";
	setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, stropt.c_str(), stropt.size());

	stropt.resize(IFNAMSIZ);
	len = stropt.size();
	getsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, stropt.data(), &len);

	struct sock_fprog fprog;
	fprog.len = 1;
	struct sock_filter filter;
	filter = BPF_STMT(BPF_RET | BPF_K, 0);
	fprog.filter = &filter;

	/*
	 * note that attaching a filter is not allowed on TCP (SOCK_DGRAM)
	 * sockets without CAP_NET_ADMIN.
	 */
	setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
	fprog.len = 1;
	len = 1; // number of socket filter entries available for output
	getsockopt(s, SOL_SOCKET, SO_GET_FILTER, &filter, &len);

	close(s);
}

int main() {
	sol_socket();
}
