#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

#include <string>

int main(const int argc, const char **argv) {
	char exe[PATH_MAX];
	auto bytes = ::readlink("/proc/self/exe", exe, sizeof(exe));
	if (bytes < 0)
		return 1;
	exe[bytes] = '\0';

	if (argc == 1) {
		const char *const args[] = {exe, "execveat", nullptr};
		::execve(exe, const_cast<char*const*>(args), environ);
	} else if (std::string{argv[1]} == "execveat") {
		const char *const args[] = {exe, "final", nullptr};
		int fd = open(exe, O_RDONLY);
		if (fd < 0)
			return 1;
		::execveat(fd, "", const_cast<char*const*>(args), environ, AT_EMPTY_PATH);
	}

	return 0;
}
