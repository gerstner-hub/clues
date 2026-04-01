#include <unistd.h>
#include <fcntl.h>

int main() {
	int fd = open("/etc/fstab", O_RDONLY);
	char buffer[1024];
	if (read(fd, buffer, sizeof(buffer)) < 0) {

	}
}
