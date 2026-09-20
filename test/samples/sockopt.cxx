#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

void sol_socket() {
	int s = socket(AF_INET, SOCK_STREAM, 0);
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
	getsockopt(s, SOL_SOCKET, 2348734873, &i, &len);
	/* test bad option level */
	getsockopt(s, 349834, 0, &i, &len);

	close(s);
}

int main() {
	sol_socket();
}
