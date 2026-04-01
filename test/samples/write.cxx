#include <unistd.h>
#include <fcntl.h>

int main() {
	int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
	const char buffer[] = "abcdefgh";
	if (write(fd, buffer, sizeof(buffer)) < 0) {

	}
}
