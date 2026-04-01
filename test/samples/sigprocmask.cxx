#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdint>

#include <cosmos/compiler.hxx>
#include <cosmos/memory.hxx>

int main() {
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigfillset(&old);
	sigprocmask(SIG_BLOCK, &set, &old);

#ifdef COSMOS_I386
	uint32_t set32 = 0, old32;
	set32 |= 1 << (SIGUSR1 - 1);
	syscall(SYS_sigprocmask, SIG_BLOCK, &set32, &old32);
#endif
}

