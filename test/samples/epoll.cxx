#include <sys/epoll.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
	int fd;
#ifdef SYS_epoll_create
	fd = epoll_create(128);
	close(fd);
#endif
	fd = epoll_create1(EPOLL_CLOEXEC);

	epoll_event ev;
	ev.events = EPOLLIN|EPOLLHUP;
	ev.data.fd = 4711;
	epoll_ctl(fd, EPOLL_CTL_ADD, 0, &ev);

	close(fd);
}
