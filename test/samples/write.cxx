#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>

int main() {
	int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
	const char buffer[] = "abcdefgh";
	if (write(fd, buffer, sizeof(buffer)) < 0) {

	}

	if (pwrite(fd, buffer, sizeof(buffer), 100) < 0) {

	}

	const char buf2[] = "123456";

	struct iovec iov[2];
	iov[0].iov_base = (void*)buffer;
	iov[0].iov_len = sizeof(buffer) - 1;
	iov[1].iov_base = (void*)buf2;
	iov[1].iov_len = sizeof(buf2) - 1;

	if (writev(fd, iov, sizeof(iov) / sizeof(struct iovec)) < 0) {

	}
}
