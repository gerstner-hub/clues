#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
	syscall(SYS_open, "/some/thing", O_RDONLY|O_CREAT, 0755);
	syscall(SYS_open, "/some/thing", O_RDONLY, 0755);
	syscall(SYS_open, "/some/thing", O_WRONLY|O_TMPFILE, 0644);
}
