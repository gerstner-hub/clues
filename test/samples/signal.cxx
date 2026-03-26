#include <signal.h>

int main() {
	sigset_t ss, old_ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGUSR1);

	::sigprocmask(SIG_BLOCK, &ss, &old_ss);

	sigdelset(&ss, SIGUSR1);
	sigaddset(&ss, SIGUSR2);

	::sigprocmask(SIG_BLOCK, &ss, &old_ss);
}
