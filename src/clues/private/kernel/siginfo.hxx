#pragma once

// clues
#include <clues/private/kernel/types.hxx>

// Linux
#include <signal.h>

namespace clues {

extern "C" {

union compat_sigval_t {
	compat_int_t    sival_int;
	compat_uptr_t   sival_ptr;
};

/// compat_siginfo_t needed for 64-bit <-> 32-bit cross ABI tracing.
struct kernel_siginfo32 {
	int si_signo;
#ifndef __ARCH_HAS_SWAPPED_SIGINFO /* only on MIPS */
	int si_errno;
	int si_code;
#else
	int si_code;
	int si_errno;
#endif

	union {
		int _pad[128/sizeof(int) - 3];

		/* kill() */
		struct {
			compat_pid_t _pid;	/* sender's pid */
			__compat_uid32_t _uid;	/* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			compat_timer_t _tid;	/* timer id */
			int _overrun;		/* overrun count */
			compat_sigval_t _sigval;	/* same as below */
		} _timer;

		/* POSIX.1b signals */
		struct {
			compat_pid_t _pid;	/* sender's pid */
			__compat_uid32_t _uid;	/* sender's uid */
			compat_sigval_t _sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			compat_pid_t _pid;	/* which child */
			__compat_uid32_t _uid;	/* sender's uid */
			int _status;		/* exit code */
			compat_clock_t _utime;
			compat_clock_t _stime;
		} _sigchld;

#if 0 /* SIGCHLD (x32 version) */
		struct {
			compat_pid_t _pid;	/* which child */
			__compat_uid32_t _uid;	/* sender's uid */
			int _status;		/* exit code */
			compat_s64 _utime;
			compat_s64 _stime;
		} _sigchld_x32;
#endif

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
		struct {
			compat_uptr_t _addr;	/* faulting insn/memory ref. */
#define __COMPAT_ADDR_BND_PKEY_PAD  (__alignof__(compat_uptr_t) < sizeof(short) ? \
				     sizeof(short) : __alignof__(compat_uptr_t))
			union {
				/* used on alpha and sparc */
				int _trapno;	/* TRAP # which caused the signal */
				/*
				 * used when si_code=BUS_MCEERR_AR or
				 * used when si_code=BUS_MCEERR_AO
				 */
				short int _addr_lsb;	/* Valid LSB of the reported address. */
				/* used when si_code=SEGV_BNDERR */
				struct {
					char _dummy_bnd[__COMPAT_ADDR_BND_PKEY_PAD];
					compat_uptr_t _lower;
					compat_uptr_t _upper;
				} _addr_bnd;
				/* used when si_code=SEGV_PKUERR */
				struct {
					char _dummy_pkey[__COMPAT_ADDR_BND_PKEY_PAD];
					uint32_t _pkey;
				} _addr_pkey;
				/* used when si_code=TRAP_PERF */
				struct {
					compat_ulong_t _data;
					uint32_t _type;
					uint32_t _flags;
				} _perf;
			};
		} _sigfault;

		/* SIGPOLL */
		struct {
			compat_long_t _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
			int _fd;
		} _sigpoll;

		struct {
			compat_uptr_t _call_addr; /* calling user insn */
			int _syscall;	/* triggering system call number */
			unsigned int _arch;	/* AUDIT_ARCH_* of syscall */
		} _sigsys;
	} _sifields;
};

}

} // end ns
