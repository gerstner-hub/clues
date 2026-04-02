#include <cosmos/compiler.hxx>

/*
 * this header contains preprocessor defines to help with exclusive compiling
 * of system call only present certain architectures.
 */

#ifdef COSMOS_X86
#	define CLUES_HAVE_ARCH_PRCTL
#endif
