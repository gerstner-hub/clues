#include <sys/select.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h>

#include "utils/syscall32.hxx"
#include <clues/private/kernel/select.hxx>
#include <clues/private/kernel/sigset.hxx>
#include <clues/private/kernel/time.hxx>

#include <utils/types.hxx>

int main() {
	int fd[2];
	if (pipe(fd) < 0) {
		return 1;
	}

	int readfd = fd[0];
	int writefd = fd[1];

	fd_set readset, writeset;

	FD_ZERO(&readset);
	FD_ZERO(&writeset);

	FD_SET(readfd, &readset);
	FD_SET(writefd, &writeset);

	canon_timeval tv;
	tv.tv_sec = 50;
	tv.tv_usec = 100;

#ifdef SYS__newselect
	syscall(SYS__newselect, writefd + 1, &readset, &writeset, NULL, &tv);

	FD_SET(readfd, &readset);
	FD_SET(writefd, &writeset);

	/*
	 * and try the old select just as well
	 */
	clues::select_arg_struct args;
	args.nfds = writefd + 1;
	args.readset_p = reinterpret_cast<uint32_t>(&readset);
	args.writeset_p = reinterpret_cast<uint32_t>(&writeset);
	args.exceptset_p = 0;
	args.timeval_p = reinterpret_cast<uint32_t>(&tv);
	tv.tv_sec = 50;
	tv.tv_usec = 100;

	syscall(SYS_select, &args);
#elif defined(SYS_select)
	auto tv_fault = (struct timeval*)0x1234;
	syscall(SYS_select, writefd + 1, &readset, &writeset, NULL, tv_fault);
	auto set_fault = (fd_set*)0x1234;
	syscall(SYS_select, writefd + 1, set_fault, &writeset, NULL, tv_fault);
	syscall(SYS_select, writefd + 1, &readset, &writeset, NULL, &tv);
#endif

	struct timespec ts;
	ts.tv_nsec = 100;
	ts.tv_sec = 50;
	FD_SET(readfd, &readset);
	FD_SET(writefd, &writeset);
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	pselect(writefd + 1, &readset, &writeset, NULL, &ts, &set);

#ifdef SYS_pselect6_time64
	/* try the 64-bit timespec pselect as well */
	clues::timespec64 ts64;
	ts64.tv_sec = 50;
	ts64.tv_nsec = 100;
	FD_SET(readfd, &readset);
	FD_SET(writefd, &writeset);
	clues::sigset_argpack pack;
	pack.sigset_p = &set;
	pack.size = 8;
	syscall(SYS_pselect6_time64, writefd + 1, &readset, &writeset, NULL,
			&ts64, &pack);
#endif
}
