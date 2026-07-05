#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
#ifdef SYS_eventfd
	int efd = syscall(SYS_eventfd, 10);
	close(efd);
#endif

	int efd2 = eventfd(10, EFD_CLOEXEC);
	close(efd2);
}
