#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

void flockCntl() {
	char path[] = "/tmp/fcntl_syscall_test.XXXXXX";
	int fd = mkstemp(path);

	struct flock fl;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_CUR;
	fl.l_start = 10;
	fl.l_len = 100;
	fl.l_pid = 4711;

	fcntl(fd, F_SETLK, &fl);

	fl.l_type = F_UNLCK;

	fcntl(fd, F_SETLK, &fl);

	fl.l_type = F_RDLCK;

	fcntl(fd, F_SETLKW, &fl);

	fcntl(fd, F_GETLK, &fl);

	fl.l_type = F_WRLCK;

	fcntl(fd, F_SETLK, &fl);

	close(fd);
	unlink(path);
}

int main() {

	(void)fcntl(0, F_DUPFD, 5);
	(void)fcntl(1, F_DUPFD_CLOEXEC, 10);
	(void)fcntl(0, F_GETFD);
	(void)fcntl(0, F_SETFD, FD_CLOEXEC);
	(void)fcntl(0, F_GETFD);
	(void)fcntl(2, F_GETFL);
	(void)fcntl(2, F_SETFL, O_APPEND);
	(void)fcntl(2, F_GETFL);

	flockCntl();

}
