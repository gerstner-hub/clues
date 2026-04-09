#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <iostream>

int main(const int argc, const char **argv) {
	struct timespec ts;
	ts.tv_sec = 5;
	ts.tv_nsec = 500;

	if (argc == 3) {
		ts.tv_sec = std::stoul(argv[1]);
		ts.tv_nsec = std::stoul(argv[2]);
	}

	clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, &ts);
	syscall(SYS_nanosleep, &ts, &ts);
}
