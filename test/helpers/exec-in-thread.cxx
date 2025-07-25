#include <iostream>

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

cosmos::pthread::ExitValue thread_entry(cosmos::pthread::ThreadArg) {
	std::cout << "other thread PID is " << cosmos::thread::get_tid() << std::endl;

	auto true_exe = cosmos::fs::which("true");

	if (!true_exe) {
		std::cerr << "failed to find true program?!\n";
		cosmos::proc::exit(cosmos::ExitStatus::FAILURE);
	}

	if (ask_before_exec) {
		std::cerr << "press enter to execve()\n";
		bool ready;
		std::cin >> ready;
	}

	cosmos::proc::exec(*true_exe, cosmos::CStringVector{true_exe->c_str(), nullptr});
	std::cerr << " a life post-exec?!\n";
	return cosmos::pthread::ExitValue{0};
}

class ExecInThread :
	public cosmos::MainContainerArgs {
public:
	cosmos::ExitStatus main(const std::string_view argv0, const cosmos::StringViewVector &args) override;
};

cosmos::ExitStatus ExecInThread::main(const std::string_view,
		const cosmos::StringViewVector &args) {
	std::cout << "main thread PID is " << cosmos::proc::get_own_pid() << std::endl;

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
