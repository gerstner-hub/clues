#include <sys/mman.h>

int main() {
	auto addr = mmap((void*)0x4711, 0x1000, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	munmap(addr, 0x1000);
	addr = mmap((void*)0x815, 0x2000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	munmap(addr, 0x2000);
}
