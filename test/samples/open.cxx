#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
	syscall(SYS_open, "/some/thing", O_RDONLY|O_CREAT, 0755);
	syscall(SYS_open, "/some/thing", O_RDONLY, 0755);
	syscall(SYS_open, "/some/thing", O_WRONLY|O_TMPFILE, 0644);

	int fd = open("/etc", O_RDONLY|O_DIRECTORY);
	syscall(SYS_openat, fd, "fstab", O_RDONLY|O_CLOEXEC);

	int fd2 = open("/tmp", O_RDONLY|O_DIRECTORY);
	syscall(SYS_openat, fd2, ".", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
}
