#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <signal.h>

static void flockCntl() {
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

static void flockCntlOFD() {
	char path[] = "/tmp/fcntl_syscall_test.XXXXXX";
	int fd = mkstemp(path);

	struct flock fl;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_CUR;
	fl.l_start = 10;
	fl.l_len = 100;
	fl.l_pid = 0;

	fcntl(fd, F_OFD_SETLK, &fl);

	fl.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLK, &fl);

	fl.l_type = F_RDLCK;

	fcntl(fd, F_OFD_SETLKW, &fl);

	fcntl(fd, F_OFD_GETLK, &fl);

	fl.l_type = F_WRLCK;

	fcntl(fd, F_OFD_SETLK, &fl);

	close(fd);
	unlink(path);
}

static void ownerEx() {
	struct f_owner_ex ex;

	fcntl(0, F_GETOWN_EX, &ex);

	ex.type = F_OWNER_PID;
	ex.pid = getpid();
	fcntl(0, F_SETOWN_EX, &ex);
	fcntl(0, F_GETOWN_EX, &ex);
	ex.type = F_OWNER_TID;
	ex.pid = gettid();
	fcntl(0, F_SETOWN_EX, &ex);
	fcntl(0, F_GETOWN_EX, &ex);
	ex.type = F_OWNER_PGRP;
	ex.pid = getpgid(getpid());
	fcntl(0, F_SETOWN_EX, &ex);
	fcntl(0, F_GETOWN_EX, &ex);
}

static void leases() {
	char path[] = "/tmp/fcntl_syscall_test.XXXXXX";
	int fd = mkstemp(path);
	fcntl(fd, F_GETLEASE);
	fcntl(fd, F_SETLEASE, F_WRLCK);
	fcntl(fd, F_GETLEASE);
	fcntl(fd, F_SETLEASE, F_UNLCK);
	close(fd);

	int fd2 = open(path, O_RDONLY);
	fcntl(fd2, F_SETLEASE, F_RDLCK);
	fcntl(fd2, F_GETLEASE);
	fcntl(fd2, F_SETLEASE, F_UNLCK);

	close(fd2);
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
	flockCntlOFD();

	fcntl(0, F_SETOWN, getpid());
	syscall(SYS_fcntl, 0, F_GETOWN);
	fcntl(0, F_SETOWN, -getpgid(getpid()));
	syscall(SYS_fcntl, 0, F_GETOWN);

	ownerEx();

	fcntl(0, F_SETSIG, 0);
	fcntl(0, F_GETSIG);
	fcntl(0, F_SETSIG, SIGUSR1);
	fcntl(0, F_GETSIG);

	leases();
}
