#pragma once

// C++
#include <cstdint>
#include <type_traits>

// cosmos
#include <cosmos/compiler.hxx>

namespace clues {

extern "C" {

struct fsid_t {
	int val[2];
};


/*
 * in the kernel with 64-bit long this is even a signed int64_t, but for our
 * purposes we should be able to stick to unsigned types for both cases.
 */
using statfs_word = std::conditional_t<sizeof(long) == 4, uint32_t, uint64_t>;

/*
 * - the single data structure used on 64-bit systems
 * - otherwise on 32-bit systems this is the structure used with the system
 *   calls without 64-bit suffix, which don't support large integers in
 *   various critical fields.
 */

struct statfs {
        statfs_word f_type;
        statfs_word f_bsize;
        statfs_word f_blocks;
        statfs_word f_bfree;
        statfs_word f_bavail;
        statfs_word f_files;
        statfs_word f_ffree;
        fsid_t f_fsid;
        statfs_word f_namelen;
        statfs_word f_frsize;
        statfs_word f_flags;
        statfs_word f_spare[4];
};

#ifdef COSMOS_X86_64

/*
 * the `struct statfs` used in 32-bit emulation ABI on 64-bit hosts
 */

struct statfs32 {
        uint32_t f_type;
        uint32_t f_bsize;
        uint32_t f_blocks;
        uint32_t f_bfree;
        uint32_t f_bavail;
        uint32_t f_files;
        uint32_t f_ffree;
        fsid_t f_fsid;
        uint32_t f_namelen;
        uint32_t f_frsize;
        uint32_t f_flags;
        uint32_t f_spare[4];
} __attribute__((packed,aligned(4)));

/*
 * for cross ABI we need a dedicated definition here with special padding for
 * the 32-bit emulation statsf64() and fstatfs64().
 */

struct statfs64 {
        uint32_t f_type;
        uint32_t f_bsize;
        uint64_t f_blocks;
        uint64_t f_bfree;
        uint64_t f_bavail;
        uint64_t f_files;
        uint64_t f_ffree;
        fsid_t f_fsid;
        uint32_t f_namelen;
        uint32_t f_frsize;
        uint32_t f_flags;
        uint32_t f_spare[4];
} __attribute__((packed,aligned(4)));

#elif defined(COSMOS_I386)

/*
 * for 32-bit systems this is the data structure used with the system calls
 * with a `64` stuffix, supporting large integers where necessary.
 */

struct statfs64 {
        statfs_word f_type;
        statfs_word f_bsize;
        uint64_t f_blocks;
        uint64_t f_bfree;
        uint64_t f_bavail;
        uint64_t f_files;
        uint64_t f_ffree;
        fsid_t f_fsid;
        statfs_word f_namelen;
        statfs_word f_frsize;
        statfs_word f_flags;
        statfs_word f_spare[4];
};

using statfs32 = statfs;
#endif


} // end extern

} // end ns
