#include <sys/eventfd.h>
#include <sys/pidfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int fetch_child_fd(int pidfd) {
	/* try to dup our child's stdin */
	int child_in = syscall(SYS_pidfd_getfd, pidfd, 0, 0);

	if (child_in < 0)
		return 1;
	else
		close(child_in);

	return 0;
}

int main() {

	if (const auto child = fork(); child == 0) {
		pause();
		return 0;
	} else {
		int fd = syscall(SYS_pidfd_open, child, PIDFD_NONBLOCK);
		if (fd < 0)
			return 1;

		fetch_child_fd(fd);

#ifdef PIDFD_SIGNAL_THREAD_GROUP
		unsigned int flags = PIDFD_SIGNAL_THREAD_GROUP;
#else
		unsigned int flags = 0;
#endif

		syscall(SYS_pidfd_send_signal, fd, SIGKILL, nullptr, flags);

		close(fd);

		int stat;
		wait(&stat);
	}
}
