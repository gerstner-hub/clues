#include <utility>

#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <string>
#include <linux/filter.h>

namespace {

int set_int_opt(int sock, const int level, const int name, const int val) {
	return ::setsockopt(sock, level, name, &val, sizeof(val));
}

int set_sock_int_opt(int sock, const int name, const int val) {
	return set_int_opt(sock, SOL_SOCKET, name, val);
}

template <typename T>
int set_opt(int sock, const int level, const int name, const T &val) {
	return ::setsockopt(sock, level, name, &val, sizeof(val));
}

template <typename T>
int set_sock_opt(int sock, const int name, const T &val) {
	return set_opt(sock, SOL_SOCKET, name, val);
}

template <typename T>
std::pair<int, int> get_opt(int sock, const int level, const int name, T &val) {
	socklen_t len = sizeof(val);
	auto ret = ::getsockopt(sock, level, name, &val, &len);
	return std::make_pair(ret, len);
}

template <typename T>
std::pair<int, int> get_sock_opt(int sock, const int name, T &val) {
	return get_opt(sock, SOL_SOCKET, name, val);
}

std::pair<int, int> get_int_opt(int sock, const int level, const int name) {
	int val;
	socklen_t len = sizeof(val);
	auto ret = ::getsockopt(sock, level, name, &val, &len);

	return std::make_pair(ret, val);
}

std::pair<int, int> get_sock_int_opt(int sock, const int name) {
	return get_int_opt(sock, SOL_SOCKET, name);
}

void sol_socket() {
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	get_sock_int_opt(s, SO_DONTROUTE);
	set_sock_int_opt(s, SO_DONTROUTE, 1);

	/* test incomplete option read */
	int i = 4711;
	socklen_t len = 0;
	getsockopt(s, SOL_SOCKET, SO_DONTROUTE, &i, &len);

	get_sock_int_opt(s, SO_BROADCAST);

	set_sock_int_opt(s, SO_BROADCAST, 1);

	/* test bad option name */
	get_sock_int_opt(s, 348734873);
	/* test bad option level */
	get_sock_int_opt(s, 349834);

	set_sock_int_opt(s,  SO_PRIORITY, 20);
	get_sock_int_opt(s, SO_PRIORITY);

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

	get_sock_int_opt(s, SO_DOMAIN);
	set_sock_int_opt(s,  SO_DOMAIN, AF_INET6);

	get_sock_int_opt(s, SO_ERROR);
	set_sock_int_opt(s, SO_ERROR, EAGAIN);

	struct linger lng;
	lng.l_onoff = 1;
	lng.l_linger = 12;

	set_sock_opt(s, SO_LINGER, lng);
	get_sock_opt(s, SO_LINGER, lng);

	close(s);
}

} // end ns

int main() {
	sol_socket();
}
