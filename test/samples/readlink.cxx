#include <limits.h>
#include <sys/syscall.h>
#include <unistd.h>

// cosmos
#include <cosmos/compiler.hxx>
#include <cosmos/fs/TempDir.hxx>
#include <cosmos/fs/filesystem.hxx>

int main() {

	cosmos::TempDir dir{"/tmp/readlink-test"};

	const auto link_path = dir.path() + "/link";

	cosmos::fs::make_symlink("/our/test/symlink/content", link_path);

#ifdef COSMOS_X86
	char target[PATH_MAX];
	syscall(SYS_readlink, link_path.c_str(), target, PATH_MAX);
#endif

	int dirfd = open(dir.path().c_str(), O_RDONLY|O_DIRECTORY);

	if (dirfd < 0)
		return 1;

	if (readlinkat(dirfd, "link", target, PATH_MAX) < 0) {

	}

	close(dirfd);
}
