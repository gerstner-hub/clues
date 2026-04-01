#include <sys/syscall.h>
#include <unistd.h>

int main() {
	int tptr;
	syscall(SYS_set_tid_address, &tptr);
}
