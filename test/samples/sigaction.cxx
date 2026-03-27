#include <signal.h>

#include <cosmos/memory.hxx>

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
}
