#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace kernel {

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

/*
 * stat structure used on 32-bit ABIs like I386
 */
struct stat32 {
        unsigned long  dev;
        unsigned long  ino;
        unsigned short mode;
        unsigned short nlink;
        unsigned short uid;
        unsigned short gid;
        unsigned long  rdev;
        unsigned long  size;
        unsigned long  blksize;
        unsigned long  blocks;
        unsigned long  atime;
        unsigned long  atime_nsec;
        unsigned long  mtime;
        unsigned long  mtime_nsec;
        unsigned long  ctime;
        unsigned long  ctime_nsec;
        unsigned long  __unused4;
        unsigned long  __unused5;
};

/*
 * used with stat64 family of system calls on 32-bit ABIs like i386
 */
struct stat32_64 {
        unsigned long long      dev;
        unsigned char   __pad0[4];

        unsigned long   _ino;

        unsigned int    mode;
        unsigned int    nlink;

        unsigned long   uid;
        unsigned long   gid;

        unsigned long long      rdev;
        unsigned char   __pad3[4];

        long long       size;
        unsigned long   blksize;

        /* Number 512-byte blocks allocated. */
        unsigned long long      blocks;

        unsigned long   atime;
        unsigned long   atime_nsec;

        unsigned long   mtime;
        unsigned int    mtime_nsec;

        unsigned long   ctime;
        unsigned long   ctime_nsec;

        unsigned long long      ino;
};

/*
 * the single stat structure used on 64-bit ABIs like x86_64
 */
struct stat64 {
        __kernel_ulong_t        dev;
        __kernel_ulong_t        ino;
        __kernel_ulong_t        nlink;

        unsigned int            mode;
        unsigned int            uid;
        unsigned int            gid;
        unsigned int            __pad0;
        __kernel_ulong_t        rdev;
        __kernel_long_t         size;
        __kernel_long_t         blksize;
        __kernel_long_t         blocks;      /* Number 512-byte blocks alloc */

        __kernel_ulong_t        atime;
        __kernel_ulong_t        atime_nsec;
        __kernel_ulong_t        mtime;
        __kernel_ulong_t        mtime_nsec;
        __kernel_ulong_t        ctime;
        __kernel_ulong_t        ctime_nsec;
        __kernel_long_t         __unused[3];
};

}

int main() {
	struct stat st;
	constexpr const char *PATH{"/etc/os-release"};
	const auto fd = ::open(PATH, O_RDONLY);
	const auto dirfd = ::open("/etc", O_RDONLY|O_DIRECTORY);

	if (fd == -1 || dirfd == -1)
		return 1;

	// default stat as provided by glibc
	::stat(PATH, &st);
	::lstat(PATH, &st);
	::fstat(fd, &st);
	::fstatat(fd, "", &st, AT_EMPTY_PATH);
	::fstatat(dirfd, "os-release", &st, AT_NO_AUTOMOUNT);

#ifdef __i386__
	/*
	 * three different kinds of stat structures exist on i386
	 */
	struct kernel::old_kernel_stat old_st;
	const auto dev_fd = ::open("/dev/null", O_RDONLY);
	// on regular file systems we mostly get EOVERFLOW here, because the
	// large inode numbers etc. don't fit into the old struct st. Try a
	// device file, this seems to work.
	::syscall(SYS_oldstat, "/dev/null", &old_st);
	::syscall(SYS_oldlstat, "/dev/null", &old_st);
	::syscall(SYS_oldfstat, dev_fd, &old_st);

	struct kernel::stat32 st32;

	::syscall(SYS_stat, "/dev/null", &st32);
	::syscall(SYS_lstat, "/dev/null", &st32);
	::syscall(SYS_fstat, dev_fd, &st32);

	struct kernel::stat32_64 st32_64;

	::syscall(SYS_stat64, PATH, &st32_64);
	::syscall(SYS_lstat64, PATH, &st32_64);
	::syscall(SYS_fstat64, fd, &st32_64);

	::syscall(SYS_fstatat64, fd, "", &st, AT_EMPTY_PATH);
	::syscall(SYS_fstatat64, dirfd, "os-release", &st, AT_NO_AUTOMOUNT);

	::close(dev_fd);
#else
	struct kernel::stat64 st64;
	::syscall(SYS_stat, PATH, &st64);
	::syscall(SYS_lstat, PATH, &st64);
	::syscall(SYS_fstat, fd, &st64);

	::syscall(SYS_newfstatat, fd, "", &st, AT_EMPTY_PATH);
	::syscall(SYS_newfstatat, dirfd, "os-release", &st, AT_NO_AUTOMOUNT);
#endif
	::close(fd);
	::close(dirfd);
}
