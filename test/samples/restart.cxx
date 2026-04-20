#include <cosmos/proc/SigAction.hxx>
#include <cosmos/proc/signal.hxx>

#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <iostream>
#include <string>

namespace {

int pipes[2];
char buf[10];
cosmos::SigAction action;

void fatal(const std::string_view why) {
	std::cerr << "FATAL: " << why << "\n";
	_exit(1);
}

void set_action(const bool restart) {
	if (restart) {
		action.setFlags(cosmos::SigAction::Flags{cosmos::SigAction::Flag::RESTART});
	} else {
		action.setFlags(cosmos::SigAction::Flags{});
	}

	cosmos::signal::set_action(cosmos::signal::ALARM, action);
}

void create_timer(const cosmos::Signal sig, const size_t seconds) {
	struct sigevent event;
	std::memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_SIGNAL;
	event.sigev_signo = cosmos::to_integral(sig.raw());
	timer_t id;
	if (timer_create(CLOCK_MONOTONIC, &event, &id) != 0) {
		fatal("timer_create failed");
	}

	struct itimerspec spec;
	std::memset(&spec, 0, sizeof(spec));
	spec.it_value.tv_sec = seconds;

	if (timer_settime(id, 0, &spec, nullptr) != 0) {
		fatal("timer_settime failed");
	}
}

void sighandler(const cosmos::Signal) {
	std::cerr << "sighandler running\n";
}

void restart_syscall() {
	create_timer(cosmos::signal::STOP, 3);
	create_timer(cosmos::signal::CONT, 6);

	struct timespec ts;
	ts.tv_sec = 10;
	ts.tv_nsec = 0;

	/*
	 * time related system calls will be handled via restart_syscall
	 */
	if (nanosleep(&ts, nullptr) != 0) {
		std::cerr << strerror(errno) << std::endl;
		fatal("nanosleep failed");
	}
}

void wakeup_read(const cosmos::Signal) {
	const char ch = 0;
	if (::write(pipes[1], &ch, 1) < 0) {
		std::cerr << "write(): " << strerror(errno) << "\n";
		fatal("write failed");
	}
}

void transparent_restart() {
	set_action(true);

	cosmos::SigAction wake_action;
	wake_action.setHandler(wakeup_read);
	wake_action.setFlags(cosmos::SigAction::Flag::RESTART);
	cosmos::signal::set_action(cosmos::signal::USR1, wake_action);

	create_timer(cosmos::signal::USR1, 5);
	::alarm(1);
	if (::read(pipes[0], buf, sizeof(buf)) < 0) {
		fatal("read() failed");
	}

	std::cout << "read returned successfully\n";
}

void visible_eintr() {
	set_action(false);

	::alarm(1);
	if (::read(pipes[0], buf, sizeof(buf)) == 0 || errno != EINTR) {
		fatal("read() succeeded or failed in unexpected ways");
	}

	std::cout << "read return EINTR\n";
}

}

int main(const int argc, const char **argv) {
	/*
	 * this example triggers:
	 *
	 * - a transparent restart involving restart_syscall()
	 * - a transparent restart without restart_syscall()
	 * - a regular visible EINTR return from a system call
	 */

	action.setHandler(sighandler);

	cosmos::SigSet ss;
	ss.set(cosmos::signal::ALARM);
	cosmos::signal::unblock(ss);

	if (::pipe(pipes) != 0) {
		fatal("pipe() failed");
	}

	if (argc == 1) {
		std::cout << "restart_syscall\n";
		restart_syscall();
		std::cout << "transparent_restart\n";
		transparent_restart();
		std::cout << "visible_eintr\n";
		visible_eintr();
	} else {
		const std::string_view type = argv[1];
		if (type == "restart_syscall")
			restart_syscall();
		else if (type == "transparent_restart")
			transparent_restart();
		else if (type == "visible_eintr")
			visible_eintr();
		else {
			fatal("bad test type encountered");
		}
	}
}
