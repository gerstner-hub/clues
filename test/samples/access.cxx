#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include <clues/arch.hxx>

int main() {
#ifdef CLUES_HAVE_ACCESS
	syscall(SYS_access, "/etc/fstab", R_OK);
#endif

	int fd = open("/etc", O_DIRECTORY|O_RDONLY);
	if (fd < 0) {
		return 1;
	}

	// directly invoke the older faccessat system call
	syscall(SYS_faccessat, fd, "fstab", W_OK);

	int res = faccessat(fd, "fstab", X_OK, AT_EACCESS);
	(void)res;
}
