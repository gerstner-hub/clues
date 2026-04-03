#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>

#include <clues/arch.hxx>
#include <iostream>

int main() {
#ifdef CLUES_HAVE_FORK
	syscall(SYS_fork);
#else
	std::cerr << "no fork() on this ABI!\n";
	_exit(1);
#endif
}
