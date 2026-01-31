#include <sched.h>
#include <sys/wait.h>

int child(void *) {
	return 5;
}

int main() {
	char child_stack[8192];
	int arg = -5000;
	pid_t parent_tid = 0;
	if (clone(&child, child_stack, CLONE_FS|CLONE_PARENT_SETTID|SIGCHLD, &arg, &parent_tid) < 0) {
		return 1;
	}

	wait(NULL);

	int pidfd = -1;

	if (clone(&child, child_stack, CLONE_FS|CLONE_PIDFD|SIGCHLD, &arg, &pidfd) < 0) {
		return 1;
	}

	waitpid(-1, NULL, WSTOPPED|__WNOTHREAD);

	pid_t child_tid = 0;

	// the child_tid value is only written to the child process's memory,
	// even if we share the same address space it is not guaranteed that
	// the write is complete by the time the clone call returns in the
	// parent.
	if (clone(&child, child_stack, CLONE_FS|CLONE_CHILD_SETTID|SIGCHLD, &arg, /*parent_tid=*/nullptr, /*tls=*/nullptr, &child_tid) < 0) {
		return 1;
	}

	int status = 1;

	wait(&status);

	int stuff = 1234;

	if (clone(&child, child_stack, CLONE_FS|CLONE_SETTLS|SIGCHLD, &arg, /*parent_tid=*/nullptr, /*tls=*/stuff) < 0) {
		return 1;
	}

	wait(NULL);
}
