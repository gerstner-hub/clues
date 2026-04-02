#include <sys/syscall.h>
#include <unistd.h>
#include <linux/futex.h>

int main() {
	struct robust_list_head *head;
	size_t size;
	syscall(SYS_get_robust_list, gettid(), &head, &size);

	syscall(SYS_set_robust_list, head, size);
}
