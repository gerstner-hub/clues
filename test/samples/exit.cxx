#include <unistd.h>
#include <sys/syscall.h>

int main() {
	syscall(SYS_exit_group, 11);
}
