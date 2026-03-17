#pragma once

namespace clues {

extern "C" {

/*
 * the man page says there's no header for this.
 */

/// 32-bit getdents() directory entries.
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

} // end extern "C"

} // end ns
