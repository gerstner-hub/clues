#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

void sol_socket() {
	int s = socket(AF_INET, SOCK_STREAM, 0);
	int i = 0;
	socklen_t len = sizeof(i);
	getsockopt(s, SOL_SOCKET, SO_DONTROUTE, &i, &len);
	i = 1;
#if 0
	setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &i, sizeof(i));
#endif
	/* test error */
	i = 4711;
	len = 0;
	getsockopt(s, SOL_SOCKET, SO_DONTROUTE, &i, &len);

	getsockopt(s, SOL_SOCKET, SO_BROADCAST, &i, &len);

	close(s);
}

int main() {
	sol_socket();
}
