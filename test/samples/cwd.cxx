#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

int main() {
	if (chdir("/tmp") < 0) {
		return 1;
	}

	char cwd[PATH_MAX];

	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		return 1;
	}

	auto bad_cwd = (char*)0x1;

	if (getcwd(bad_cwd, 100) == NULL) {

	}

	if (chdir(bad_cwd) < 0) {

	}

	int fd = open("/tmp", O_RDONLY|O_DIRECTORY);
	if (fd < 0) {
		return 1;
	}

	if (fchdir(fd) < 0) {
		return 1;
	}

	if (fchdir(100) < 0) {

	}
}
