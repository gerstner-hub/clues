#include <cstdlib>
#include <iostream>
#include <cosmos/proc/process.hxx>
#include <cosmos/main.hxx>

/*
 * this program simply returns the exit status given on the command line
 */

class Exiter :
	public cosmos::MainContainerArgs {
public:
	cosmos::ExitStatus main(const std::string_view argv0, const cosmos::StringViewVector &args) override;
};

cosmos::ExitStatus Exiter::main(const std::string_view, const cosmos::StringViewVector &args) {
	if (args.empty()) {
		return cosmos::ExitStatus::SUCCESS;
	}

	try {
		auto exit_status = std::stoi(args[0].data());
		return cosmos::ExitStatus{exit_status};
	} catch (const std::exception &ex) {
		std::cerr << ex.what() << ": bad exit code value" << std::endl;
		return cosmos::ExitStatus::FAILURE;
	}
}

int main(int argc, const char **argv) {
	return cosmos::main<Exiter>(argc, argv);
}
