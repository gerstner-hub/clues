#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include <clues/arch.hxx>

#ifdef CLUES_HAVE_PIPE1
/* explicit pipe() system call invocation, since glibc always invokes pipe2 */
int pipe1(int ends[2]) {
	return syscall(SYS_pipe, ends);
}
#endif

int main() {
	int ends[2];

#ifdef CLUES_HAVE_PIPE1
	if (pipe1(ends) != 0) {
		return 1;
	}

	close(ends[0]);
	close(ends[1]);

	// test bad userspace address
	if (pipe1(NULL) == 0){
		// should fail
		return 1;
	}
#endif

	if (pipe2(ends, O_CLOEXEC|O_DIRECT) != 0) {
		return 1;
	}

	close(ends[0]);
	close(ends[1]);
}
