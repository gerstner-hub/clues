#include <iostream>

#include <cosmos/proc/process.hxx>
#include <cosmos/fs/File.hxx>
#include <cosmos/main.hxx>

/*
 * this program executes the target program via the execveat() system call.
 */

class FileExec :
	public cosmos::MainContainerArgs {
public:
	cosmos::ExitStatus main(const std::string_view argv0, const cosmos::StringViewVector &args) override;
};

cosmos::ExitStatus FileExec::main(const std::string_view exe,
		const cosmos::StringViewVector &args) {

	auto prog = std::string{exe}.substr(0, exe.rfind("/"));
	prog += "/exiter";

	if (!args.empty()) {
		prog = args[0].data();
	}

	try {
		auto file = cosmos::File{prog, cosmos::OpenMode::READ_ONLY};

		cosmos::proc::fexec(file.fd(),cosmos::CStringVector{prog.c_str(), nullptr});
	} catch (const std::exception &ex) {
		std::cerr << ex.what() << "\n";
		return cosmos::ExitStatus::FAILURE;
	}
	std::cerr << "unexpectedly survived fexec()?!" << std::endl;
	return cosmos::ExitStatus::FAILURE;
}

int main(int argc, const char **argv) {
	return cosmos::main<FileExec>(argc, argv);
}

