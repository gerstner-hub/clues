#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "utils/syscall32.hxx"

int main() {
	int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0644);
	/*
	 * this will call the single fadvise64() using 64-bit parameters for
	 * both offset and size on 64-bit architectures.
	 *
	 * on I386 this will call fadvise64_64() using two combined offset
	 * values.
	 */
	posix_fadvise(fd, (1LL << 32) + 32, (1LL << 32) + 4, POSIX_FADV_SEQUENTIAL);
#ifdef COSMOS_X86_64
	/*
	 * explicitly call the two 32-bit personalities of fadvise64
	 */
	// off low, off high, len low, len high
	syscall32(SyscallNr32::FADVISE64_64, fd, 128, 1, 64, 1, POSIX_FADV_RANDOM);
	// off low, off high, 32-bit len
	syscall32(SyscallNr32::FADVISE64, fd, 128, 1, 512, POSIX_FADV_RANDOM);
#elif defined(COSMOS_I386)
	syscall(SYS_fadvise64_64, fd, 128, 1, 64, 1, POSIX_FADV_RANDOM);
	syscall(SYS_fadvise64, fd, 128, 1, 512, POSIX_FADV_RANDOM);
#endif
	close(fd);
}
