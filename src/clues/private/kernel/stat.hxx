#pragma once

// C++
#include <cstdint>

namespace clues {

extern "C" {

/// Original Linux stat data structure for SystemCallNr::OLDSTAT, OLDLSTAT and OLDFSTAT.
struct old_kernel_stat {
        uint16_t dev;
        uint16_t ino;
        uint16_t mode;
        uint16_t nlink;
        uint16_t uid;
        uint16_t gid;
        uint16_t rdev;
        uint32_t size;
        uint32_t atime;
        uint32_t mtime;
        uint32_t ctime;
};

/// 32-bit sized stat data structure with some padding for SystemCallNR::STAT, LSTAT and FSTAT on 32-bit archs like i386.
struct stat32 {
        uint32_t dev;
        uint32_t ino;
        uint16_t mode;
        uint16_t nlink;
        uint16_t uid;
        uint16_t gid;
        uint32_t rdev;
        uint32_t size;
        uint32_t blksize;
        uint32_t blocks;
        uint32_t atime;
        uint32_t atime_nsec;
        uint32_t mtime;
        uint32_t mtime_nsec;
        uint32_t ctime;
        uint32_t ctime_nsec;
        uint32_t __unused4;
        uint32_t __unused5;
};

/// 64-bit sized stat data structure used with the stat64 family of system calls on 32-bit ABIs like i386.
/**
 * According to the kernel sources this is based on some Glibc data structure
 * which is the reason for the weird padding.
 **/
struct stat32_64 {
        uint64_t dev;
        unsigned char __pad0[4];
        uint32_t _ino;
        uint32_t mode;
        uint32_t nlink;
        uint32_t uid;
        uint32_t gid;
        uint64_t rdev;
        unsigned char __pad3[4];
        int64_t size;
        uint32_t blksize;
        /* Number 512-byte blocks allocated. */
        uint64_t blocks;
        uint32_t atime;
        uint32_t atime_nsec;
        uint32_t mtime;
        uint32_t mtime_nsec;
        uint32_t ctime;
        uint32_t ctime_nsec;
        uint64_t ino;
} __attribute__((packed));

/// The single stat structure used on 64-bit ABIs like x86_64.
struct stat64 {
        uint64_t dev;
        uint64_t ino;
        uint64_t nlink;

        uint32_t mode;
        uint32_t uid;
        uint32_t gid;
        uint32_t __pad0;
        uint64_t rdev;
        int64_t size;
        int64_t blksize;
        int64_t blocks; /* Number 512-byte blocks alloc */

        uint64_t atime;
        uint64_t atime_nsec;
        uint64_t mtime;
        uint64_t mtime_nsec;
        uint64_t ctime;
        uint64_t ctime_nsec;
        int64_t __unused[3];
};

} // end extern

} // end ns
