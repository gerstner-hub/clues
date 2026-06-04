#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>

#include <string_view>

int main() {
	int fd = open("/tmp", O_RDWR|O_TMPFILE|O_CLOEXEC, 0600);

	if (fd < 0)
		return 1;

	std::string_view sv{"some arbitrary file content"};

	if (const auto res = write(fd, sv.data(), sv.size()); res < 0 || (size_t)res < sv.size()) {
		return 1;
	}

	::lseek(fd, -10, SEEK_END);
	::lseek(fd, 10, SEEK_SET);
	::lseek(fd, 5, SEEK_CUR);

#ifdef __i386__
	/* for 64-bit seek on I386 this call takes the following arguments:
	 *
	 * - file descriptor
	 * - high bits for offset
	 * - low bits for offset
	 * - pointer to new offset resulting from successful call
	 * - seek direction
	 */
	int64_t new_offset;
	::syscall(SYS__llseek, fd, 1, 2, &new_offset, SEEK_SET);

	/* 32-bit seek */
	::syscall(SYS_lseek, fd, -10, SEEK_END);
#endif
}
