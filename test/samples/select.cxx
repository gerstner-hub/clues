#include <sys/select.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "utils/syscall32.hxx"
#include <clues/private/kernel/select.hxx>

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

	struct timeval tv;
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
#else
	syscall(SYS_select, writefd + 1, &readset, &writeset, NULL, &tv);
#endif
}
