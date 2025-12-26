#include <fcntl.h>

int main() {

	(void)fcntl(0, F_DUPFD, 5);
}
