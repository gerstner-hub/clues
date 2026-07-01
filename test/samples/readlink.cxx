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
}
