#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
	if (fork() == 0) {
		sleep(1);
		exit(0);
	} else {
		wait(NULL);
	}

	return 0;
}
