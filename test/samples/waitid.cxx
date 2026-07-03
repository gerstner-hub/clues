#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

int main() {

	if (const auto child = fork(); child != 0) {
		siginfo_t sinfo;
		waitid(P_PID, child, &sinfo, WEXITED);
	} else {
		_exit(10);
	}

	if (const auto child = fork(); child != 0) {
		siginfo_t sinfo;
		waitid(P_ALL, 815, &sinfo, WEXITED);
	} else {
		::raise(SIGKILL);
	}

}
