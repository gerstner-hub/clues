#include <fcntl.h>

int main() {

	(void)fcntl(0, F_DUPFD, 5);
	(void)fcntl(1, F_DUPFD_CLOEXEC, 10);
}
