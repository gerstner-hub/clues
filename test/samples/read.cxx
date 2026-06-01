#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>

#include <string_view>

int main() {
	int fd = open("/etc/fstab", O_RDONLY);
	if (fd < 0) {
		return 1;
	}
	char buffer[1024];
	if (read(fd, buffer, sizeof(buffer)) < 0) {

	}

	if (pread(fd, buffer, sizeof(buffer), 20) < 0) {

	}

	/*
	 * test non-blocking I/O where a buffer is only partially filled on
	 * read() and where another read() generates EAGAIN
	 */

	int pipes[2];

	if (pipe2(pipes, O_NONBLOCK) != 0) {
		return 1;
	}

	constexpr std::string_view TEST_DATA{"a test string"};

	if (write(pipes[1], TEST_DATA.data(), TEST_DATA.size()) < 0)
		return 1;

	if (read(pipes[0], buffer, sizeof(buffer)) < 0) {
	}

	/* this should result in EAGAIN */
	if (read(pipes[0], buffer, sizeof(buffer)) < 0) {
	}

	/* readv() */

	char buffer2[1024];

	struct iovec vec[2];
	vec[0].iov_base = (void*)buffer;
	vec[0].iov_len = 24;
	vec[1].iov_base = (void*)buffer2;
	vec[1].iov_len = 16;

	lseek(fd, SEEK_SET, 0);

	if (readv(fd, vec, 2) < 0 ) {
		return 1;
	}

	/* now try a partial read from the pipe */
	if (write(pipes[1], TEST_DATA.data(), TEST_DATA.size()) < 0) {
		return 1;
	}

	if (readv(pipes[0], vec, 2) < 0) {

	}
}
