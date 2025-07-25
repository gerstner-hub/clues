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

cosmos::ExitStatus FileExec::main(const std::string_view,
		const cosmos::StringViewVector &args) {

	const char *path = "/bin/true";
	if (!args.empty()) {
		path = args[0].data();
	}

	try {
		auto file = cosmos::File{path, cosmos::OpenMode::READ_ONLY};

		cosmos::proc::fexec(file.fd(),cosmos::CStringVector{path, nullptr});
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

