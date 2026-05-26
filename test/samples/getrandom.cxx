#include <sys/random.h>
#include <sys/syscall.h>
#include <cstdint>
#include <unistd.h>

int main() {
	/* the glibc wrapper for getrandom seems to change the buffer size
	 * under some circumstances */
	uint8_t buf[16];
	syscall(SYS_getrandom, buf, sizeof(buf), 0);
}
