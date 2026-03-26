// Linux
#include <unistd.h>

// C
#include <errno.h>
#include <sys/syscall.h>

// C++
#include <cstring>
#include <functional>
#include <iostream>

// Clues
#include <clues/SystemCall.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/Tracee.hxx>

// cosmos
#include <cosmos/proc/signal.hxx>
#include <cosmos/proc/SigAction.hxx>

// Test
#include "TestBase.hxx"
#include "TraceeCreator.hxx"

/*
 * The purpose of this test is to observe an interrupted system call and see
 * it being resumed.
 *
 * Currently RESUMED is only observed if restart_syscall() is invoked by the
 * kernel, which only happens for some time-related system calls like
 * nanosleep().
 */

class RestartSyscallTracer : public clues::EventConsumer {
protected:
	void syscallEntry(clues::Tracee &t,
			const clues::SystemCall &call,
			const StatusFlags flags) override {
#if 0
		const auto name = clues::SYSTEM_CALL_NAMES[cosmos::to_integral(call.callNr())];
		std::cerr << "-> " << name << " flags = " << flags.raw() << "\n";
#endif
		if (!m_sent_sig) {
			if (call.callNr() == clues::SystemCallNr::NANOSLEEP) {
				cosmos::signal::send(t.pid(), cosmos::signal::STOP);
				m_sent_sig = true;
			}
		} else if (m_seen_interrupted && !m_seen_resumed) {
			if (call.callNr() == clues::SystemCallNr::NANOSLEEP) {
				m_seen_resumed = flags[StatusFlag::RESUMED];
			}
		}

		if (m_seen_resumed) {
			cosmos::signal::send(t.pid(), cosmos::signal::KILL);
		}
	}

	void syscallExit(clues::Tracee &t, const clues::SystemCall &call, const StatusFlags flags) override {
#if 0
		const auto name = clues::SYSTEM_CALL_NAMES[cosmos::to_integral(call.callNr())];
		std::cerr << "<- " << name << " flags = " << flags.raw() << "\n";
#endif
		if (m_sent_sig && !m_seen_interrupted) {
			if (call.callNr() == clues::SystemCallNr::NANOSLEEP) {
				m_seen_interrupted = flags[StatusFlag::INTERRUPTED];
			}

			if (m_seen_interrupted) {
				cosmos::signal::send(t.pid(), cosmos::signal::CONT);
			}
		}
	}

	bool m_sent_sig = false;
	bool m_seen_interrupted = false;
	bool m_seen_resumed = false;
public:
	bool seenInterrupted() const {
		return m_seen_interrupted;
	}

	bool seenResumed() const {
		return m_seen_resumed;
	}
};

using AttachedCB = std::function<void()>;

/*
 * This tests another variant of resuming, where restart_syscall() is not
 * invoked, e.g. when a read() system call is interrupted by signal.
 *
 * In this case libclues needs to use other forms of tracking the resume.
 */

class ResumeSyscallTracer : public clues::EventConsumer {
protected:
	void syscallEntry(clues::Tracee &t,
			const clues::SystemCall &call,
			const StatusFlags flags) override {
#if 0
		const auto name = clues::SYSTEM_CALL_NAMES[cosmos::to_integral(call.callNr())];
		std::cerr << "-> " << name << " flags = " << flags.raw() << "\n";
#endif
		if (!m_sent_sig) {
			if (call.callNr() == clues::SystemCallNr::READ) {
				if (m_num_reads_seen++ > 0) {
					cosmos::signal::send(t.pid(), cosmos::signal::USR1);
					m_sent_sig = true;
				}
			}
		} else if (m_seen_interrupted && !m_seen_resumed) {
			if (call.callNr() == clues::SystemCallNr::READ) {
				m_seen_resumed = flags[StatusFlag::RESUMED];
			}
		}

		if (m_seen_resumed) {
			cosmos::signal::send(t.pid(), cosmos::signal::KILL);
		}
	}

	void syscallExit(clues::Tracee &, const clues::SystemCall &call, const StatusFlags flags) override {
#if 0
		const auto name = clues::SYSTEM_CALL_NAMES[cosmos::to_integral(call.callNr())];
		std::cerr << "<- " << name << " flags = " << flags.raw() << "\n";
#endif
		if (m_sent_sig && !m_seen_interrupted) {
			if (call.callNr() == clues::SystemCallNr::READ) {
				m_seen_interrupted = flags[StatusFlag::INTERRUPTED];
			}
		}
	}

	void attached(clues::Tracee &) override {
		m_attached_cb();
	}

	size_t m_num_reads_seen = 0;
	bool m_sent_sig = false;
	bool m_seen_interrupted = false;
	bool m_seen_resumed = false;
	AttachedCB m_attached_cb;


public:
	bool seenInterrupted() const {
		return m_seen_interrupted;
	}

	bool seenResumed() const {
		return m_seen_resumed;
	}

	void setAttachedCB(AttachedCB cb) {
		m_attached_cb = cb;
	}
};

void sighandler(const cosmos::Signal) {
	/* perform some system call for additional test coverage, it will make
	 * it harder for libclues to find the resumed system call */
	::getpid();
}

class RestartSyscallTest : public cosmos::TestBase {
	void runTests() override {
		runRestartTest();
		runResumeTest();
	}

	void runRestartTest() {
		START_TEST("system call interrupt/restart");
		RestartSyscallTracer tracer;

		TraceeCreator creator{[]() {
				struct timespec ts;
				ts.tv_sec = 1000;
				ts.tv_nsec = 0;
				if (syscall(SYS_nanosleep, &ts, nullptr) != 0) {
					std::cerr << "nanosleep failed!\n";
				}
			}, tracer};
		creator.run();

		RUN_STEP("seen-interrupted", tracer.seenInterrupted());
		RUN_STEP("seen-resumed", tracer.seenResumed());
	}

	void runResumeTest() {
		START_TEST("system call interrupt/resume");
		ResumeSyscallTracer tracer;

		TraceeCreator creator{[]() {
				cosmos::SigAction action;
				action.setHandler(&sighandler);
				action.setFlags(cosmos::SigAction::Flag::RESTART);
				cosmos::signal::set_action(cosmos::signal::USR1, action);
				cosmos::SigSet set;
				set.set(cosmos::signal::USR1);
				cosmos::signal::unblock(set);

				int pipes[2];
				if (pipe(pipes) != 0) {
					std::cerr << "pipe() failed\n";
					return;
				}

				char buf[128];

				/*
				 * the system call to be interrupted
				 */

				if (::read(pipes[0], buf, sizeof(buf)) < 0) {
					std::cerr << "read() failed\n";
				}
			}, tracer};
		tracer.setAttachedCB([&creator]() { creator.signalChild(); });
		creator.run(clues::FollowChildren{false}, /*explicit_signal=*/true);

		RUN_STEP("seen-interrupted", tracer.seenInterrupted());
		RUN_STEP("seen-resumed", tracer.seenResumed());
	}
};

int main(const int argc, const char **argv) {
	RestartSyscallTest test;
	return test.run(argc, argv);
}
