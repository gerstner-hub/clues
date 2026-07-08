#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>

int main() {
	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGUSR1);
	int fd = signalfd(-1, &ss, SFD_CLOEXEC);
	sigaddset(&ss, SIGUSR2);
	signalfd(fd, &ss, 0);
	close(fd);

#ifdef SYS_signalfd
	int fd2 = syscall(SYS_signalfd, -1, &ss, 8);
	sigdelset(&ss, SIGUSR1);
	syscall(SYS_signalfd, fd2, &ss, 8);
	close(fd2);
#endif
}
