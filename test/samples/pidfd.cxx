#include <sys/syscall.h>
#include <sys/pidfd.h>
#include <unistd.h>

int main() {
	int fd = syscall(SYS_pidfd_open, getppid(), PIDFD_NONBLOCK);
	if (fd < 0)
		return 1;

	close(fd);
}
