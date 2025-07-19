#include <cstdlib>
#include <cosmos/proc/process.hxx>

int main(int argc, const char **argv) {
	if (argc < 2) {
		return 0;
	}

	try {
		auto exit_status = std::strtoul(argv[1], nullptr, 10);
		return static_cast<int>(exit_status);
	} catch (const std::exception &) {
		return 1;
	}
}
