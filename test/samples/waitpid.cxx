#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "utils/syscall32.hxx"

int main() {
#ifdef SYS_waitpid
	if (const auto child = fork(); child != 0) {
		int status;
		syscall(SYS_waitpid, child, &status, WCONTINUED);
	} else {
		_exit(10);
	}
#elif defined(COSMOS_X86_64)
	if (const auto child = fork(); child != 0) {
		auto status = alloc32<int*>(sizeof(int));
		syscall32(clues::SystemCallNrI386::WAITPID, child, status, WCONTINUED);
	} else {
		_exit(10);
	}
#endif
}

