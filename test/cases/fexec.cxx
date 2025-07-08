#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <string.h>
#include <errno.h>

int main() {
	int fd = open("/bin/true", O_RDONLY|O_CLOEXEC);
	const char *argv[] = {"true", nullptr};
	fexecve(fd, const_cast<char*const*>(argv), environ);
	std::cerr << "true: " << strerror(errno) << std::endl;
	return 1;
}

