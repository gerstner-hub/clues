#include <cosmos/proc/process.hxx>
#include <cosmos/time/time.hxx>
#include <cosmos/main.hxx>

/*
 * this is a simple forking program for testing tracing
 */

class Forker :
	public cosmos::MainContainerArgs {
public:
	cosmos::ExitStatus main(const std::string_view argv0, const cosmos::StringViewVector &args) override;
};

cosmos::ExitStatus Forker::main(const std::string_view, const cosmos::StringViewVector &args) {
	if (auto child_pid = cosmos::proc::fork(); child_pid) {
		(void)cosmos::proc::wait(*child_pid);
	} else {
		if (!args.empty()) {
			const auto sleep_ms = std::stoul(args[0].data());
			cosmos::time::sleep(std::chrono::milliseconds{sleep_ms});
		}
		cosmos::proc::exit(cosmos::ExitStatus::SUCCESS);
	}

	return cosmos::ExitStatus::SUCCESS;
}

int main(const int argc, const char **argv) {
	return cosmos::main<Forker>(argc, argv);
}
