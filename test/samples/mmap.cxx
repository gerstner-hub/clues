#include <sys/mman.h>
#include <cosmos/compiler.hxx>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MAP_HUGE_2MB
/* older Debian doesn't define this in the userspace headers */
#	include <linux/mman.h>
#endif

#include <clues/private/kernel/mmap.hxx>

int main() {
	auto addr = mmap((void*)0x4711, 0x1000, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	munmap(addr, 0x1000);
	addr = mmap((void*)0x815, 0x2000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	munmap(addr, 0x2000);
	addr = mmap(0, 0xf000, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB|MAP_HUGE_2MB, -1, 0);
	mprotect(addr, 0xf000, PROT_WRITE);
	munmap(addr, 0xf000);

#ifdef COSMOS_I386
	clues::mmap_arg_struct args;
	args.addr = 0x4711;
	args.len = 0x1000;
	args.prot = PROT_READ|PROT_EXEC;
	args.flags = MAP_PRIVATE|MAP_ANONYMOUS;
	args.fd = -1;
	args.offset = 0;
	syscall(SYS_mmap, &args);
#endif
}
