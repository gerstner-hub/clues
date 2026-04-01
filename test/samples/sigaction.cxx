#include <iostream>

#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cosmos/compiler.hxx>
#include <cosmos/memory.hxx>

#include <clues/private/kernel/sigaction.hxx>

void sighandler(int) {

}

int main() {
	struct sigaction act, oldact;

	cosmos::zero_object(act);
	cosmos::zero_object(oldact);

	act.sa_handler = sighandler;
	sigaddset(&act.sa_mask, SIGUSR1);
	act.sa_flags = SA_RESTART|SA_RESETHAND;

	::sigaction(SIGCHLD, &act, &oldact);

	std::cout << "sigaction: " << sizeof(struct sigaction) << " bytes\n";
	std::cout << "sigset_t: " << sizeof(sigset_t) << " bytes\n";
#ifdef COSMOS_I386
	struct clues::kernel_old_sigaction act_old;
	cosmos::zero_object(act_old);
	act_old.handler = (uintptr_t)sighandler;
	act_old.flags = SA_RESTART|SA_RESETHAND;
	act_old.restorer = 0;
	act_old.mask |= 1 << (SIGCHLD - 1);
	syscall(SYS_sigaction, SIGUSR1, &act_old, &act_old);
#endif
}
