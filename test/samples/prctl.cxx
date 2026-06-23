#include <clues/arch.hxx>

#ifdef CLUES_HAVE_ARCH_PRCTL
#include <asm/prctl.h>
#else
#include <iostream>
#endif

#include <sys/syscall.h>
#include <unistd.h>
#include <linux/prctl.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <signal.h>


#ifdef CLUES_HAVE_ARCH_PRCTL
template <typename ADDR>
static int arch_prctl(int op, ADDR addr) {
	return syscall(SYS_arch_prctl, op, addr);
}
#endif

int main() {
#ifdef CLUES_HAVE_ARCH_PRCTL
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

	int int_out;

	prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN);
	prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_NET_ADMIN, 0, 0);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_RAW, 0, 0);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0 ,0);
	prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
	prctl(PR_GET_CHILD_SUBREAPER, &int_out, 0, 0 ,0);
	prctl(PR_SET_DUMPABLE, 1);
	prctl(PR_GET_DUMPABLE);
	prctl(PR_GET_IO_FLUSHER);
	prctl(PR_SET_IO_FLUSHER, 1, 0, 0, 0);
	prctl(PR_GET_KEEPCAPS);
	prctl(PR_SET_KEEPCAPS, 1);
	prctl(PR_MCE_KILL, PR_MCE_KILL_CLEAR, 0, 0, 0);
	prctl(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_EARLY, 0, 0);
	prctl(PR_MCE_KILL_GET, 0, 0, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_START_CODE, 0x1234, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_END_CODE, 0x4321, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_START_DATA, 0x2345, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_END_DATA, 0x5432, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_START_STACK, 0x3456, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_START_BRK, 0x4567, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_BRK, 0x6789, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_ARG_START, 0x7890, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_ARG_END, 0x9870, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_ENV_START, 0x8900, 0, 0);
	prctl(PR_SET_MM, PR_SET_MM_ENV_END, 0x9990, 0, 0);
	/* this also takes a size argument */
	prctl(PR_SET_MM, PR_SET_MM_AUXV, 0x1357, 0x100, 0);
	/* this takes a file descriptor */
	prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, 14, 0, 0);
	/* takes a struct containing all the memory mapping information */
	prctl_mm_map map;
	map.start_code = 0x1234;
	map.end_code = 0x4321;
	map.start_data = 0x2345;
	map.end_data = 0x5432;
	map.start_brk = 0x3456;
	map.brk = 0x6543;
	map.start_stack = 0x4567;
	map.arg_start = 0x5678;
	map.arg_end = 0x8765;
	map.env_start = 0x6789;
	map.env_end = 0x9876;
	map.auxv = (__u64*)0x7890;
	map.auxv_size = 0x123;
	map.exe_fd = 14;
	prctl(PR_SET_MM, PR_SET_MM_MAP, &map, sizeof(map), 0);
	unsigned int map_size = 0;
	prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, &map_size, 0, 0);

	auto anon_mem = mmap(NULL,
			4096,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	/* this returns EINVAL is CONFIG_VMA_ANON_NAME is not set in the
	 * kernel */
	prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, anon_mem, 4096, "testname");
#ifndef __SANITIZE_ADDRESS__
	/* don't do this on ASAN, this triggers an internal ASAN SIGSEGV */
	prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, anon_mem, 4096, NULL);
#endif

	prctl(PR_SET_NAME, "new name");
	char name[16];
	prctl(PR_GET_NAME, name);

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);

	prctl(PR_SET_PDEATHSIG, SIGSEGV, 0, 0, 0);
	long sig = 0;
	prctl(PR_GET_PDEATHSIG, &sig, 0, 0, 0);

	prctl(PR_SET_PTRACER, 1, 0, 0, 0);
	prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

	prctl(PR_GET_SECCOMP);

	struct sock_fprog prog{};
	/*
	 * an invalid bpf program jumping beyond the existing code, we only
	 * want to provoke an EINVAL return here.
	 */
	struct sock_filter filter[2] = {
		BPF_JUMP(BPF_JMP | BPF_JA, 10, 0, 0),
		BPF_JUMP(BPF_JMP | BPF_JA, 20, 0, 0)
	};
	prog.len = sizeof(filter) / sizeof(struct sock_filter);
	prog.filter = filter;
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

	prctl(PR_SET_SECUREBITS, SECBIT_NOROOT|SECBIT_NO_CAP_AMBIENT_RAISE);
	prctl(PR_GET_SECUREBITS);

	prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);
	prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, 0, 0);

	int8_t sys_dispatch = SYSCALL_DISPATCH_FILTER_ALLOW;

	prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, main, 4096, &sys_dispatch);
	prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0);

	prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0);
	prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);

	prctl(PR_TASK_PERF_EVENTS_ENABLE);
	prctl(PR_TASK_PERF_EVENTS_DISABLE);

	prctl(PR_SET_THP_DISABLE, 1, PR_THP_DISABLE_EXCEPT_ADVISED, 0, 0);
	prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
	prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
	prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0);

	/*
	 * only execute this call after everything else, because afterwards we
	 * no longer can execute arbitrary system calls, not even
	 * exit_group().
	 */
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
	syscall(SYS_exit, 0);
}
