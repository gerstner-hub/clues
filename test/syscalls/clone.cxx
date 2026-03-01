#include <sched.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include <cosmos/proc/clone.hxx>
#include <cosmos/proc/process.hxx>

int child(void *) {
	return 5;
}

void testClone3() {
	cosmos::CloneArgs args;
	cosmos::PidFD pidfd;
	using enum cosmos::CloneFlag;
	args.setFlags(cosmos::CloneFlags{CLEAR_SIGHAND, PIDFD, CHILD_SETTID, PARENT_SETTID});
	args.setPidFD(&pidfd);
	cosmos::ThreadID tid;
	args.setChildTID(&tid);
	args.setParentTID(&tid);

	if (const auto child = cosmos::proc::clone(args); child) {
		wait(NULL);
	} else {
		cosmos::proc::exit(cosmos::ExitStatus{5});
	}

	// another test, likely unsucessfuly, using custom TIDs for the child
	cosmos::ThreadID tids[3] = {cosmos::ThreadID{5}, cosmos::ThreadID{50}, cosmos::ThreadID{500}};

	args.setTIDs(&tids[0], sizeof(tids) / sizeof(cosmos::ThreadID));

	try {
		if (const auto child = cosmos::proc::clone(args); child) {
			wait(NULL);
		} else {
			cosmos::proc::exit(cosmos::ExitStatus{5});
		}
	} catch (const std::exception &) {
		// to be expected, we're lacking privileges
	}
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
	struct rusage rus;

	wait4(-1, &status, 0, &rus);

	int stuff = 1234;

	if (clone(&child, child_stack, CLONE_FS|CLONE_SETTLS|SIGCHLD, &arg, /*parent_tid=*/nullptr, /*tls=*/stuff) < 0) {
		return 1;
	}

	wait(NULL);

	if (clone(&child, child_stack, CLONE_FILES|SIGCHLD, &arg, /*parent_tid=*/nullptr, /*tls=*/nullptr) < 0) {
		return 1;
	}

	wait(NULL);

	testClone3();
}
