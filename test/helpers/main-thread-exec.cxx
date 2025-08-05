#include <iostream>
#include <string>

#include <cosmos/main.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/thread/PosixThread.hxx>
#include <cosmos/time/time.hxx>
#include <cosmos/fs/filesystem.hxx>

/*
 * this helper performs an execve() while another thread is still alive
 */

class MainThreadExec :
	public cosmos::MainContainerArgs {
public:
	cosmos::ExitStatus main(const std::string_view argv0, const cosmos::StringViewVector &args) override;
};

cosmos::pthread::ExitValue thread_entry(cosmos::pthread::ThreadArg) {
	std::cout << "other thread pid is " << cosmos::thread::get_tid() << std::endl;
	cosmos::time::sleep(std::chrono::milliseconds(1000 * 1000));
	return cosmos::pthread::ExitValue{0};
}

cosmos::ExitStatus MainThreadExec::main(const std::string_view exe,
		const cosmos::StringViewVector &args) {
	std::cout << "main thread pid is " << cosmos::proc::get_own_pid() << std::endl;
	cosmos::PosixThread thread{&thread_entry, cosmos::pthread::ThreadArg{0}};

	if (!args.empty()) {
		std::cerr << "press enter to execve()\n";
		bool ready;
		std::cin >> ready;
	} else {
		// give the other thread some time to output its message
		cosmos::time::sleep(std::chrono::milliseconds(200));
	}

	std::string exiter = std::string{exe.substr(0, exe.rfind("/"))};
	exiter += "/exiter";

	cosmos::proc::exec(exiter, cosmos::CStringVector{exiter.c_str(), nullptr});
	std::cerr << "a life post-exec?!\n";
	return cosmos::ExitStatus::FAILURE;
}

int main(int argc, const char **argv) {
	return cosmos::main<MainThreadExec>(argc, argv);
}
