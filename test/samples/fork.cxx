#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
	syscall(SYS_fork);
}
