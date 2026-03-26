#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <climits>

#include <clues/private/kernel/other.hxx>
#include <iostream>

int main() {
	/*
	 * invoke the legacy getrlimit and setrlimit which use 32-bit unsigned
	 * ints. Glibc no longer makes these accessible, so directly invoke
	 * the system calls.
	 */
	if (sizeof(unsigned long) == 4) {
		/*
		 * on 32-bit archs the compat system calls are in effect
		 */
		clues::rlimit32  lim32;
		syscall(SYS_getrlimit, RLIMIT_AS, &lim32);
		lim32.rlim_cur = 50000;
		lim32.rlim_max = 500000;
		syscall(SYS_setrlimit, RLIMIT_AS, &lim32);
		lim32.rlim_cur = UINT32_MAX;
		lim32.rlim_max = UINT32_MAX;
		syscall(SYS_setrlimit, RLIMIT_AS, &lim32);
	} else {
		clues::rlimit64 lim64;
		syscall(SYS_getrlimit, RLIMIT_AS, &lim64);
		lim64.rlim_cur = 50000;
		lim64.rlim_max = 500000;
		syscall(SYS_setrlimit, RLIMIT_AS, &lim64);
		lim64.rlim_cur = RLIM_INFINITY;
		lim64.rlim_max = RLIM_INFINITY;
		syscall(SYS_setrlimit, RLIMIT_AS, &lim64);
	}

	{
		struct rlimit lim;
		getrlimit(RLIMIT_AS, &lim);
		setrlimit(RLIMIT_AS, &lim);

		lim.rlim_cur = 60000;
		lim.rlim_max = 400000;

		prlimit(0, RLIMIT_AS, &lim, &lim);
	}
}
