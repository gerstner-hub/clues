#include <unistd.h>
#include <fcntl.h>

int main() {
	int fd = open("/", O_RDONLY|O_DIRECTORY);
	close(fd);
}
