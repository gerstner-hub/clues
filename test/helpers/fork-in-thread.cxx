#include <iostream>

#include <cosmos/thread/PosixThread.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/main.hxx>

/*
 * this program performs a fork() & execve() in a thread
 */

const char *sleep_time = "0";

cosmos::pthread::ExitValue thread_entry(cosmos::pthread::ThreadArg) {
	std::cout << "other thread PID is " << gettid() << std::endl;

	if (auto child_pid = cosmos::proc::fork(); child_pid) {
		(void)cosmos::proc::wait(*child_pid);
		std::cout << "child finished\n";
	} else {
		auto sleep_exe = cosmos::fs::which("sleep");
		if (!sleep_exe) {
			std::cerr << "failed to find sleep program?!\n";
			cosmos::proc::exit(cosmos::ExitStatus::FAILURE);
		}

		cosmos::proc::exec(*sleep_exe, cosmos::CStringVector{sleep_exe->c_str(), sleep_time, nullptr});
		std::cerr << " a life post-exec?!\n";
		cosmos::proc::exit(cosmos::ExitStatus::FAILURE);
	}

	return cosmos::pthread::ExitValue{0};
}

class ForkInThread :
	public cosmos::MainContainerArgs {
public:
	cosmos::ExitStatus main(const std::string_view argv0, const cosmos::StringViewVector &args) override;
};

cosmos::ExitStatus ForkInThread::main(const std::string_view,
		const cosmos::StringViewVector &args) {
	std::cout << "main thread PID is " << cosmos::proc::get_own_pid() << std::endl;

	if (!args.empty()) {
		sleep_time = args[0].data();
	}

	cosmos::PosixThread thread{&thread_entry, cosmos::pthread::ThreadArg{0}};

	thread.join();

	return cosmos::ExitStatus::SUCCESS;
}

int main(const int argc, const char **argv) {
	return cosmos::main<ForkInThread>(argc, argv);
}

