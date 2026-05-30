#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>

int main() {
	int fd = open("/etc/fstab", O_RDONLY);
	char buffer[1024];
	if (read(fd, buffer, sizeof(buffer)) < 0) {

	}

	if (pread(fd, buffer, sizeof(buffer), 20) < 0) {

	}

	char buffer2[1024];

	struct iovec vec[2];
	vec[0].iov_base = (void*)buffer;
	vec[0].iov_len = 24;
	vec[1].iov_base = (void*)buffer2;
	vec[1].iov_len = 16;

	lseek(fd, SEEK_SET, 0);

	if (readv(fd, vec, 2) < 0 ) {

	}
}
