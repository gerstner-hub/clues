#include <poll.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>

#include <cosmos/memory.hxx>

int main() {
	int pipes[2];
	if (pipe(pipes) < 0) {
		return 1;
	}
	if (write(pipes[1], "test", 4) < 0) {
		return 1;
	}

	/* poll with invalid ptr */
	poll((struct pollfd*)0x1234, 1, 100);

	struct pollfd fds[2];
	cosmos::zero_object(fds);
	fds[0].fd = pipes[0];
	fds[0].events = POLLIN|POLLRDHUP;
	fds[1].fd = pipes[1];
	fds[1].events = POLLOUT|POLLHUP;

	poll(fds, 2, 100);

	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGUSR1);
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 10000;

	ppoll(fds, 2, &ts, &ss);
#ifdef SYS_ppoll_time64
	syscall(SYS_ppoll_time64, fds, 2, &ts, &ss, 8);
#endif
}
