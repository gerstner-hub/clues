// Linux
#include <sys/syscall.h>

// C++
#include <cstdint>
#include <sys/types.h>

// cosmos
#include <cosmos/compiler.hxx>

namespace clues {

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
 * On 32-bit platforms like I386 the off_t used in legacy system call
 * interfaces is an int32_t, but we won't see this in user space when
 * compiling with _FILE_OFFSET_BITS=64. Thus we need our own define here.
 *
 * This is important to get proper sign extension when negative offsets are
 * used, for example.
 */
#ifdef COSMOS_I386
using kernel_off_t = int32_t;
#else
using kernel_off_t = off_t;
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

/* aarch64 only comes with readlinkat */
#ifdef SYS_readlink
#	define CLUES_HAVE_READLINK
#endif

} // end ns
