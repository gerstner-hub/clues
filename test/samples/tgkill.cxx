#include <signal.h>

int main() {
	tgkill(getpid(), gettid(), 0);
}
