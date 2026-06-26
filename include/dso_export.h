#pragma once

/*
 * Helper macro to control visibility of public APIs of the cosmos shared
 * library.
 * The object files are compiled with -fvisibility=hidden, thus each public
 * interface needs to be explicitly made visible again.
 */
#if defined(CLUES_EXPORT)
#	define CLUES_API __attribute__ ((visibility ("default")))
#else
#	define CLUES_API
#endif

/*
 * These macros can be used to change visibility of a group of symbols until
 * the OFF macro appears again.
 *
 * This only works on GCC / clang but these are our main target compilers so
 * far.
 */

#define CLUES_DEFAULT_VISIBILITY_ON \
	    _Pragma("GCC visibility push(default)")

#define CLUES_DEFAULT_VISIBILITY_OFF \
	    _Pragma("GCC visibility pop")
