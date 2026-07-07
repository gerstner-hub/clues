#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cosmos/compiler.hxx>

int main() {
	struct statfs buf;
	statfs("/proc", &buf);

	int fd = open("/proc", O_RDONLY|O_DIRECTORY);
	if (fd < 0)
		return 1;

#ifdef COSMOS_I386
	syscall(SYS_statfs, "/proc", &buf);
	syscall(SYS_fstatfs, fd, &buf);
#endif

	fstatfs(fd, &buf);
}
