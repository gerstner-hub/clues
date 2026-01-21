#include <sched.h>
#include <sys/wait.h>

int child(void *) {
	return 5;
}

int main() {
	char child_stack[8192];
	int var = -5000;
	if (clone(&child, child_stack, CLONE_FS|SIGCHLD, &var) < 0) {
		return 1;
	}

	wait(NULL);
}
