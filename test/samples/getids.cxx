#include <unistd.h>
#include <sys/syscall.h>
#include <cosmos/compiler.hxx>

int main() {
	syscall(SYS_getuid);
	syscall(SYS_getgid);
	syscall(SYS_geteuid);
	syscall(SYS_getegid);
#ifdef COSMOS_I386
	syscall(SYS_getuid32);
	syscall(SYS_getgid32);
	syscall(SYS_geteuid32);
	syscall(SYS_getegid32);
#endif
	const auto own_pid = syscall(SYS_getpid);
	syscall(SYS_getpgid, own_pid);
	syscall(SYS_getppid);
	syscall(SYS_gettid);
}
