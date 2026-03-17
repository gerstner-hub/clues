#pragma once

#include <stdint.h>

namespace clues {

extern "C" {

/*
 * the man page says there's no header for this.
 */

/// 32-bit getdents() directory entries.used on native 32-bit/64-bit ABIs.
struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[];
	/*
	 * following fields, cannot be sensibly accessed by the compiler,
	 * needs to be calculated during runtime, therefore only as comments
	char pad; // zero padding byte
	char d_type; // file type since Linux 2.6.4
	*/
};

/// 32-bit getdents() directory entries used in 32-bit emulation ABI.
struct linux_dirent32 {
	uint32_t d_ino;
	uint32_t d_off;
	uint16_t d_reclen;
	char d_name[];
};

} // end extern "C"

} // end ns
