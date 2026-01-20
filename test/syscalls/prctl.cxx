#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cosmos/compiler.hxx>

#ifdef COSMOS_X86
template <typename ADDR>
static int arch_prctl(int op, ADDR addr) {
	return syscall(SYS_arch_prctl, op, addr);
}
#endif

int main() {
#ifdef COSMOS_X86
	arch_prctl(ARCH_SET_CPUID, 1);
	arch_prctl(ARCH_SET_CPUID, 0);
	arch_prctl(ARCH_SET_CPUID, 100);
	arch_prctl(ARCH_GET_CPUID, 0x4711);
#	ifdef COSMOS_X86_64
	unsigned long orig_fs, orig_gs;
	arch_prctl(ARCH_GET_FS, &orig_fs);
	arch_prctl(ARCH_GET_GS, &orig_gs);
	arch_prctl(ARCH_SET_FS, 0x1000);
	arch_prctl(ARCH_SET_GS, 0x5000);
	arch_prctl(ARCH_SET_FS, orig_fs);
	arch_prctl(ARCH_SET_GS, orig_gs);
#	endif
#endif

}
