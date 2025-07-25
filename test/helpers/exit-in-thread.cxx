#include <iostream>

#include <cosmos/cosmos.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/thread/PosixThread.hxx>
#include <cosmos/formatting.hxx>
#include <cosmos/main.hxx>

bool ask_before_exit = false;

/*
 * this helper creates a thread which exits the process
 */

cosmos::pthread::ExitValue thread_entry(cosmos::pthread::ThreadArg) {
	std::cout << "other thread PID is " << cosmos::thread::get_tid() << std::endl;
	if (ask_before_exit) {
		std::cout << "press ENTER to exit thread\n";
		bool ready;
		std::cin >> ready;
	}
	cosmos::proc::exit(cosmos::ExitStatus{5});
	return cosmos::pthread::ExitValue{0};
}

class ExitInThread :
	public cosmos::MainContainerArgs {
public:
	cosmos::ExitStatus main(const std::string_view argv0, const cosmos::StringViewVector &args) override;
};

cosmos::ExitStatus ExitInThread::main(const std::string_view,
		const cosmos::StringViewVector &args) {
	std::cout << "main thread PID is " << cosmos::proc::get_own_pid() << std::endl;

	if (!args.empty())
		ask_before_exit = true;

	cosmos::PosixThread thread{&thread_entry, cosmos::pthread::ThreadArg{0}};
	thread.join();
	std::cout << "joined thread?!\n";
	return cosmos::ExitStatus::FAILURE;
}

int main(int argc, const char **argv) {
	return cosmos::main<ExitInThread>(argc, argv);
}
