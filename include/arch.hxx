// Linux
#include <sys/syscall.h>

// cosmos
#include <cosmos/compiler.hxx>

/*
 * this header contains preprocessor defines to help with conditional
 * compilation of system calls only present certain architectures.
 */

#ifdef COSMOS_X86
#	define CLUES_HAVE_ARCH_PRCTL
#	define CLUES_HAVE_LEGACY_GETDENTS
/* aarch64 only has openat() anymore */
#	define CLUES_HAVE_OPEN
#endif

/*
 * presence of fork() depends not only on the ABI/arch but also on the kernel
 * configuration CONFIG_COMPAT and the present userspace headers.
 */
#ifdef SYS_fork
#	define CLUES_HAVE_FORK
#endif

/* aarch64 only has statx() and newfstatat() instead of stat() and lstat() */
#ifdef SYS_stat
#	define CLUES_HAVE_STAT
#endif

#ifdef SYS_lstat
#	define CLUES_HAVE_LSTAT
#endif

/* aarch64 only has faccessat() & friends */
#ifdef SYS_access
#	define CLUES_HAVE_ACCESS
#endif

/* aarch64 only comes with pipe2() */
#ifdef SYS_pipe
#	define CLUES_HAVE_PIPE1
#endif

/* aarch64 only comes with setitimer */
#ifdef SYS_alarm
#	define CLUES_HAVE_ALARM
#endif
