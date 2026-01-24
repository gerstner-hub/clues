#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>

namespace {

long futex(uint32_t *uaddr, int op, uint32_t val, const struct timespec *to = nullptr, uint32_t *uaddr2 = nullptr, uint32_t val3 = 0) {
	return syscall(SYS_futex, uaddr, op, val, to, uaddr2, val3);
}

long futex(uint32_t *uaddr, int op, uint32_t val, uint32_t val2, uint32_t *uaddr2 = nullptr, uint32_t val3 = 0) {
	return syscall(SYS_futex, uaddr, op, val, val2, uaddr2, val3);
}

}

int main() {
	uint32_t myfux = 4711;
	uint32_t myfux2 = 815;
	struct timespec ts;
	ts.tv_sec = 1;
	ts.tv_nsec = 100;

	futex(&myfux, FUTEX_WAIT|FUTEX_CLOCK_REALTIME, 1);
	futex(&myfux, FUTEX_WAIT|FUTEX_PRIVATE_FLAG, 1, &ts);
	futex(&myfux, FUTEX_WAKE, 5);
	futex(&myfux, FUTEX_FD, SIGIO);
	futex(&myfux, FUTEX_CMP_REQUEUE, 10, 5, &myfux2, 100);
	futex(&myfux, FUTEX_CMP_REQUEUE, 10, 5, &myfux2, 4711);
	futex(&myfux, FUTEX_REQUEUE, 10, 5, &myfux2);
	futex(&myfux, FUTEX_WAKE_OP, 13, 15, &myfux2, FUTEX_OP(FUTEX_OP_ADD, 1234, FUTEX_OP_CMP_LT, 321));
	futex(&myfux, FUTEX_WAIT_BITSET, 7, (timespec*)NULL, NULL, 0x48);
	futex(&myfux, FUTEX_WAKE_BITSET, 8, (timespec*)NULL, NULL, 0x24);
	futex(&myfux, FUTEX_LOCK_PI, 0, &ts);
	futex(&myfux, FUTEX_LOCK_PI2, 0, &ts);
	futex(&myfux, FUTEX_TRYLOCK_PI, 0);
	futex(&myfux, FUTEX_UNLOCK_PI, 0);
	futex(&myfux, FUTEX_CMP_REQUEUE_PI, 10, 5, &myfux2, 200);
	futex(&myfux, FUTEX_WAIT_REQUEUE_PI, 10, &ts, &myfux2);

	struct robust_list_head *rlist;
	size_t rlist_size;

	syscall(SYS_get_robust_list, 0, &rlist, &rlist_size);
	syscall(SYS_set_robust_list, rlist, rlist_size);
}
