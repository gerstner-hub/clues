#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(const int argc, const char **argv) {
	const char *path = argc > 1 ? argv[1] : "/";

	int fd = open(path, O_RDONLY|O_DIRECTORY);

	char buffer[16384];

	syscall(SYS_getdents, fd, buffer, sizeof(buffer));
	lseek(fd, SEEK_SET, 0);
	syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
}
