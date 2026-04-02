#include <sys/mman.h>
#include <cosmos/compiler.hxx>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
	auto addr = mmap((void*)0x4711, 0x1000, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	munmap(addr, 0x1000);
	addr = mmap((void*)0x815, 0x2000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	munmap(addr, 0x2000);
	addr = mmap(0, 0xf000, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB|MAP_HUGE_2MB, -1, 0);
	mprotect(addr, 0xf000, PROT_WRITE);
	munmap(addr, 0xf000);

#ifdef COSMOS_I386
	syscall(SYS_mmap2, (void*)0x4711, 0x1000, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#endif
}
