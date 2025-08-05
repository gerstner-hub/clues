#include <iostream>
#include <string>

#include <cosmos/thread/PosixThread.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/main.hxx>

/*
 * this program performs an execve in a thread, which causes the PID
 * re-assignment while tracing.
 */

bool ask_before_exec = false;
std::string exiter;

cosmos::pthread::ExitValue thread_entry(cosmos::pthread::ThreadArg) {
	std::cout << "other thread PID is " << cosmos::thread::get_tid() << std::endl;

	if (ask_before_exec) {
		std::cerr << "press enter to execve()\n";
		bool ready;
		std::cin >> ready;
	}

	cosmos::proc::exec(exiter, cosmos::CStringVector{exiter.c_str(), nullptr});
	std::cerr << " a life post-exec?!\n";
	return cosmos::pthread::ExitValue{0};
}

class ExecInThread :
	public cosmos::MainContainerArgs {
public:
	cosmos::ExitStatus main(const std::string_view argv0, const cosmos::StringViewVector &args) override;
};

cosmos::ExitStatus ExecInThread::main(const std::string_view exe,
		const cosmos::StringViewVector &args) {
	std::cout << "main thread PID is " << cosmos::proc::get_own_pid() << std::endl;

	exiter = exe.substr(0, exe.rfind("/"));
	exiter += "/exiter";

	if (!args.empty()) {
		ask_before_exec = true;
	}

	cosmos::PosixThread thread{&thread_entry, cosmos::pthread::ThreadArg{0}};
	thread.join();

	std::cerr << "thread didn't exec?!\n";
	return cosmos::ExitStatus::FAILURE;
}


int main(int argc, const char **argv) {
	return cosmos::main<ExecInThread>(argc, argv);
}
