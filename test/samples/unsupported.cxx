#include <sys/syscall.h>
#include <unistd.h>

#include <cosmos/compiler.hxx>

int main() {
	syscall(SYS_afs_syscall);
	syscall(SYS_putpmsg);
	syscall(SYS_getpmsg);
	syscall(SYS_vserver);
#ifdef COSMOS_I386
	syscall(SYS_break);
	syscall(SYS_ftime);
	syscall(SYS_gtty);
	syscall(SYS_lock);
	syscall(SYS_mpx);
	syscall(SYS_prof);
	syscall(SYS_profil);
	syscall(SYS_ulimit);
	syscall(SYS_stty);
#elif defined(COSMOS_X86_64)
	syscall(SYS_security);
	syscall(SYS_tuxcall);
#endif
#ifndef __NR_syscalls
#	define __NR_syscalls 500
#endif
	/* test what happens when an invalid system call is invoked */
	syscall(__NR_syscalls + 50);
}
