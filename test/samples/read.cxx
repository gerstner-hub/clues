#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <stdlib.h>

#include <string_view>
#include <string>

int main() {
	// create some test data in a temporary file */
	int fd = open("/tmp", O_RDWR|O_TMPFILE|O_CLOEXEC, 0600);
	if (fd < 0) {
		return 1;
	}

	constexpr std::string_view TEST_DATA{"test file content goes here; pretty long line\nand another line\nand yet another line\n"};

	if (write(fd, TEST_DATA.data(), TEST_DATA.size()) != (ssize_t)TEST_DATA.size()) {
		return 1;
	}

	lseek(fd, SEEK_SET, 0);

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

	if (readv(fd, vec, 2) < 0) {
		return 1;
	}

	constexpr std::string_view PIPE_DATA{"test pipe content\n"};

	/* now try a partial read from the pipe */
	if (write(pipes[1], PIPE_DATA.data(), PIPE_DATA.size()) < 0) {
		return 1;
	}

	if (readv(pipes[0], vec, 2) < 0) {

	}

	lseek(fd, SEEK_SET, 0);

	if (preadv(fd, vec, 2, 7) < 0) {

	}

	lseek(fd, SEEK_SET, 0);

	if (preadv2(fd, vec, 2, 3, RWF_HIPRI) < 0) {

	}
}
