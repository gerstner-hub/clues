#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <unistd.h>

int main() {
	if (const auto child = fork(); child != 0) {
		int status;
		struct rusage ru;
		syscall(SYS_wait4, child, &status, WCONTINUED, &ru);
	} else {
		_exit(10);
	}
}
