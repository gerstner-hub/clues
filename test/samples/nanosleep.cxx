#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <iostream>

#include <cosmos/compiler.hxx>
#include <clues/private/kernel/time.hxx>
#include <utils/types.hxx>

void clock_sleep(struct timespec ts) {
	clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, &ts);
#ifdef SYS_clock_nanosleep_time64
	syscall(SYS_clock_nanosleep_time64, CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, &ts);
#endif
}

void nano_sleep(struct timespec ts) {
	canon_timespec cts;
	cts.tv_sec = ts.tv_sec;
	cts.tv_nsec = ts.tv_nsec;
	syscall(SYS_nanosleep, &cts, &cts);
}

int main(const int argc, const char **argv) {
	struct timespec ts;
	ts.tv_sec = 5;
	ts.tv_nsec = 500;

	if (argc == 3) {
		ts.tv_sec = std::stoul(argv[1]);
		ts.tv_nsec = std::stoul(argv[2]);
	}

	clock_sleep(ts);
	nano_sleep(ts);
}
