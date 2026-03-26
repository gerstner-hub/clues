#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

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

	fl.l_type = F_UNLCK;
	fcntl(fd, F_SETLK, &fl);

#ifdef __i386__

	/*
	 * extra tests with struct flock using 32-bit off_t, we need to invoke
	 * the raw system calls here and use literal values for get the 32-bit
	 * variant (we're compiled with _FILE_OFFSET_BITS=64).
	 */

#define F_GETLK32 5
#define F_SETLK32 6
#define F_SETLKW32 7

	struct flock32 {
		short l_type;
		short l_whence;
		uint32_t l_start;
		uint32_t l_len;
		pid_t l_pid;
	};

	struct flock32 fl32;
	fl32.l_type = F_RDLCK;
	fl32.l_whence = SEEK_SET;
	fl32.l_start = 20;
	fl32.l_len = 200;
	fl32.l_pid = 815;

	syscall(SYS_fcntl, fd, F_SETLK32, &fl32);
	syscall(SYS_fcntl, fd, F_GETLK32, &fl32);
	fl32.l_type = F_UNLCK;
	syscall(SYS_fcntl, fd, F_SETLKW32, &fl32);

	fl32.l_type = F_RDLCK;
	syscall(SYS_fcntl64, fd, F_SETLK32, &fl32);
	syscall(SYS_fcntl64, fd, F_GETLK32, &fl32);
	fl32.l_type = F_UNLCK;
	syscall(SYS_fcntl64, fd, F_SETLKW32, &fl32);

	// should fail with 32-bit fcntl()
	syscall(SYS_fcntl, fd, F_GETLK, &fl);
#endif

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

static void dnotify() {
	int fd = open("/", O_RDONLY|O_DIRECTORY);
	fcntl(fd, F_NOTIFY, DN_ACCESS|DN_DELETE|DN_MULTISHOT);
	fcntl(fd, F_NOTIFY, 0);
	close(fd);
}

static void pipes() {
	int pipe_ends[2];
	if (::pipe(pipe_ends) != 0) {
		_exit(1);
	}

	fcntl(pipe_ends[0], F_GETPIPE_SZ);
	fcntl(pipe_ends[1], F_SETPIPE_SZ, 5192);
	fcntl(pipe_ends[1], F_GETPIPE_SZ);

	close(pipe_ends[0]);
	close(pipe_ends[1]);
}

static void seals() {
	int fd = ::memfd_create("mymemfd", MFD_CLOEXEC|MFD_ALLOW_SEALING);
	fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK);
	fcntl(fd, F_GET_SEALS);
	fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL);
	close(fd);
}

static void rwhints() {
	int pipe_ends[2];
	if (::pipe(pipe_ends) != 0) {
		_exit(1);
	}

	int fd = pipe_ends[0];

	uint64_t hint = -1;

	fcntl(fd, F_GET_RW_HINT, &hint);
	hint = RWH_WRITE_LIFE_SHORT;
	fcntl(fd, F_SET_RW_HINT, &hint);
	/*
	 * the following two seem unimplemented in the kernel for unknown
	 * reasons
	 */
	fcntl(fd, F_GET_FILE_RW_HINT, &hint);
	hint = RWH_WRITE_LIFE_MEDIUM;
	fcntl(fd, F_SET_FILE_RW_HINT, &hint);

	close(pipe_ends[0]);
	close(pipe_ends[1]);
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

	dnotify();

	pipes();

	seals();

	rwhints();
}
