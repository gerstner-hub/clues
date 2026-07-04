#include <sys/eventfd.h>
#include <sys/pidfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int fetch_child_fd(pid_t child) {
	int fd = syscall(SYS_pidfd_open, child, PIDFD_NONBLOCK);
	if (fd < 0)
		return 1;

	/* try to dup our child's stdin */
	int child_in = syscall(SYS_pidfd_getfd, fd, 0, 0);

	close(fd);

	if (child_in < 0)
		return 1;
	else
		close(child_in);

	return 0;
}

int main() {

	int ev = eventfd(0, 0);

	if (ev < 0)
		return 1;

	uint64_t cnt;

	if (const auto child = fork(); child == 0) {
		if (read(ev, &cnt, sizeof(cnt)) < 0) {
			return 1;
		}
		return 0;
	} else {
		fetch_child_fd(child);
		cnt = 1;
		if (write(ev, &cnt, sizeof(cnt)) < 0) {
			// all hope is lost
		}
		close(ev);
		int stat;
		wait(&stat);
	}
}
