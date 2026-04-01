#include <sys/syscall.h>
#include <unistd.h>

int main() {
	syscall(SYS_brk, 0x4711);
}
