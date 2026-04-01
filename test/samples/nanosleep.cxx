#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
	struct timespec ts;
	ts.tv_sec = 5;
	ts.tv_nsec = 500;
	clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, &ts);
	syscall(SYS_nanosleep, &ts, &ts);
}
