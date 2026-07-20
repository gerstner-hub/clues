#include <sys/epoll.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>

#include <cosmos/memory.hxx>
#include <cosmos/compiler.hxx>

int main() {
	int fd;
#ifdef SYS_epoll_create
	fd = epoll_create(128);
	close(fd);
#endif
	fd = epoll_create1(EPOLL_CLOEXEC);
	int pipes[2];
	if (pipe(pipes) < 0) {
		return 1;
	}
	if (write(pipes[1], "test", 4) < 0) {
		return 1;
	}

	epoll_event ev;
	cosmos::zero_object(ev);
	ev.events = EPOLLIN|EPOLLHUP;
	ev.data.fd = 4711;
	epoll_ctl(fd, EPOLL_CTL_ADD, pipes[0], &ev);
	ev.events = EPOLLOUT|EPOLLHUP;
	ev.data.fd = 815;
	epoll_ctl(fd, EPOLL_CTL_ADD, pipes[1], &ev);

	struct epoll_event evreport[3];
#ifndef COSMOS_AARCH64
	epoll_wait(fd, evreport, 3, 10);
#endif
	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGTERM);
	epoll_pwait(fd, evreport, 3, 10, &ss);
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 10 * 1000;
	epoll_pwait2(fd, evreport, 3, &ts, &ss);

	close(fd);
}
