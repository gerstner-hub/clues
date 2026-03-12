// Linux
#include <asm/prctl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <time.h>

// C++
#include <iostream>

// cosmos
#include <cosmos/compiler.hxx>

// clues
#include <clues/syscalls/fs.hxx>
#include <clues/syscalls/memory.hxx>
#include <clues/syscalls/process.hxx>
#include <clues/syscalls/signals.hxx>
#include <clues/syscalls/time.hxx>
#include <clues/Tracee.hxx>

// Test
#include "TestBase.hxx"
#include "TraceeCreator.hxx"

/*
 * This is a collective unit test for every single system call.
 *
 * This is a test purely on library API level. We're setting up a child
 * process which executes a lambda function which executes one or more target
 * system call variants, for which system call enter and exit callbacks are
 * expected, again running lambda functions to verify the observed data.
 */

using clues::SystemCall;
using TraceVerifyCB = std::function<void (const SystemCall &, bool &good)>;
using SyscallInvoker = std::function<void (void)>;
using clues::SystemCallNr;
/*
 * the first file descriptor number which will be used in tracee context.
 * used for comparison of file descriptor values observed.
 */
constexpr cosmos::FileNum FIRST_FD{4};
constexpr uintptr_t STACK_ADDR = sizeof(void*) == 8 ? 0x700000000000 : 0x70000000;

#define VERIFY(...) if (!(__VA_ARGS__)) { \
	std::cerr << "check |" << #__VA_ARGS__ << "| failed\n"; \
	good = false; \
	return; \
}

#define VERIFY_FALSE(expr) VERIFY(!(expr))

#define ENTRY_VERIFY_CB(SYSTEM_CALL_TYPE, ...) [](const SystemCall &_sc, bool &good) { \
	good = true; \
	const auto &sc = downcast<clues::SYSTEM_CALL_TYPE>(_sc); \
	__VA_ARGS__ \
}

#define ENTRY_VERIFY_CB_CAPTURE(CAPTURE, SYSTEM_CALL_TYPE, ...) [CAPTURE](const SystemCall &_sc, bool &good) { \
	good = true; \
	const auto &sc = downcast<clues::SYSTEM_CALL_TYPE>(_sc); \
	__VA_ARGS__ \
}

#define EXIT_VERIFY_CB(SYSTEM_CALL_TYPE, ...) [](const SystemCall &_sc, bool &good) { \
	good = true; \
	const auto &sc = downcast<clues::SYSTEM_CALL_TYPE>(_sc); \
	__VA_ARGS__ \
}

class SyscallTracer : public clues::EventConsumer {
public:
	explicit SyscallTracer(const SystemCallNr nr,
			TraceVerifyCB enter_verify,
			TraceVerifyCB exit_verify,
			const size_t ignore_calls = 0) :
				m_call_nr{nr},
				m_enter_verify{enter_verify},
				m_exit_verify{exit_verify},
				m_ignore_calls{ignore_calls} {
	}

	void syscallEntry(clues::Tracee &,
			const SystemCall &call,
			const StatusFlags) override {
		if (m_ran_cbs) {
			return;
		} else if (!m_seen_initial_read) {
			return;
		} else if (m_current_call != m_ignore_calls) {
			// we haven't reached the system call under test yet
			return;
		}

		if (call.callNr() != m_call_nr) {
			std::cerr << __FUNCTION__ << ": unexpected system call nr " << cosmos::to_integral(call.callNr()) << "\n";
			return;
		}

		m_enter_verify(call, m_entry_good);
	}

	void syscallExit(clues::Tracee &,
			const SystemCall &call,
			const StatusFlags) override {
		if (m_ran_cbs) {
			return;
		} else if (!m_seen_initial_read) {
		       if (call.callNr() == clues::SystemCallNr::READ) {
				/* Tracee Creator performs a read() system
				 * call for synchronization which we need to
				 * skip */
				m_seen_initial_read = true;
			}
			return;
		} else if (m_current_call++ != m_ignore_calls) {
			// we haven't reached the system call under test yet
			return;
		}

		if (call.callNr() != m_call_nr) {
			std::cerr << __FUNCTION__ << ": unexpected system call nr " << cosmos::to_integral(call.callNr()) << "\n";
			return;
		}

		m_exit_verify(call, m_exit_good);
		m_ran_cbs = true;
	}

	void setCreator(TraceeCreator<SyscallInvoker> &creator) {
		/*
		 * we need this to synchronize exactly to the eventfd read()
		 * in the child in attached().
		 */
		m_creator = &creator;
	}

	void attached(clues::Tracee &) override {
		m_creator->signalChild();
	}

	void exited(clues::Tracee&, const cosmos::WaitStatus, const StatusFlags) override {
		if (!m_ran_cbs) {
			std::cerr << "never seen expected system call!\n";
		}
	}

	bool entryGood() const {
		return m_entry_good;
	}

	bool exitGood() const {
		return m_exit_good;
	}

protected:

	const SystemCallNr m_call_nr;
	TraceVerifyCB m_enter_verify;
	TraceVerifyCB m_exit_verify;
	bool m_entry_good = false;
	bool m_exit_good = false;
	bool m_seen_initial_read = false;
	bool m_ran_cbs = false;
	/*
	 * some system call tests need more than once system call (e.g.
	 * opening a file descriptor to operate on first.
	 *
	 * this counter determines how many system calls should be ignored
	 * before calling the verification callbacks.
	 */
	size_t m_ignore_calls = 0;
	size_t m_current_call = 0;
	TraceeCreator<SyscallInvoker> *m_creator = nullptr;
};

template <typename SC>
const SC& downcast(const SystemCall &sc) {
	return dynamic_cast<const SC&>(sc);
}

class SyscallTest :
	public cosmos::TestBase {

	void runTests() override;

	void runTrace(
			const SystemCallNr nr,	
			SyscallInvoker invoker,
			TraceVerifyCB enter_verify,
			TraceVerifyCB exit_verify,
			const size_t ignore_calls = 0) {
		const auto name = clues::SYSTEM_CALL_NAMES[cosmos::to_integral(nr)];
		START_TEST(cosmos::sprintf("testing system call %s", &name[0]));
		SyscallTracer tracer{nr, enter_verify, exit_verify, ignore_calls};

		TraceeCreator creator{std::move(invoker), tracer};
		tracer.setCreator(creator);
		try {
			creator.run(clues::FollowChildren{false},
					/*explicit_signal=*/true);
		} catch (const std::exception &ex) {
			std::cerr << "test failed: " << ex.what() << std::endl;
		}
		RUN_STEP("system call entry good", tracer.entryGood());
		RUN_STEP("system call exit good", tracer.exitGood());
	}
};

void SyscallTest::runTests() {
	runTrace(SystemCallNr::ACCESS,
		[]() {
			access("/etc/", R_OK|X_OK);
		},
		ENTRY_VERIFY_CB(AccessSystemCall, {
			VERIFY(sc.path.data() == "/etc/");
			using cosmos::fs::AccessCheck;
			using cosmos::fs::AccessChecks;
			const AccessChecks checks{AccessCheck::READ_OK, AccessCheck::EXEC_OK};
			VERIFY((*sc.mode.checks()) == checks);
		}), EXIT_VERIFY_CB(AccessSystemCall, {
			VERIFY(!sc.hasErrorCode());
		}));

	/* shared entry check for faccessat1/2 */
	auto check_faccessat_entry = [](const auto &access_sc, bool &good) {
		VERIFY(access_sc.dirfd.fd() == FIRST_FD);
		VERIFY(access_sc.path.data() == "etc");

		using cosmos::fs::AccessCheck;
		using cosmos::fs::AccessChecks;
		const AccessChecks checks{AccessCheck::READ_OK, AccessCheck::EXEC_OK};
		VERIFY((*access_sc.mode.checks()) == checks);
	};

	runTrace(SystemCallNr::FACCESSAT,
		[]() {
			auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_faccessat, dirfd, "etc", R_OK|X_OK);
		},
		ENTRY_VERIFY_CB_CAPTURE(check_faccessat_entry, FAccessAtSystemCall, {
			check_faccessat_entry(sc, good);
		}), EXIT_VERIFY_CB(FAccessAtSystemCall, {
			VERIFY(!sc.hasErrorCode());
		}),
		1);

	runTrace(SystemCallNr::FACCESSAT2,
		[]() {
			auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_faccessat2, dirfd, "etc", R_OK|X_OK, AT_EACCESS);
		},
		ENTRY_VERIFY_CB_CAPTURE(check_faccessat_entry, FAccessAt2SystemCall, {
			auto &access_sc = downcast<clues::FAccessAt2SystemCall>(sc);
			check_faccessat_entry(access_sc, good);
			if (!good)
				return;
			using AtFlags = clues::item::AtFlagsValue::AtFlags;
			using enum clues::item::AtFlagsValue::AtFlag;
			VERIFY(access_sc.flags.flags() == AtFlags{EACCESS})
		}), EXIT_VERIFY_CB(FAccessAt2SystemCall, {
			VERIFY(!sc.hasErrorCode());
		}),
		1);

	runTrace(SystemCallNr::ALARM,
		[]() {
			/* make two calls so that we get a non-zero return
			 * value */
			alarm(1234);
			alarm(4321);
		},
		ENTRY_VERIFY_CB(AlarmSystemCall, {
			VERIFY(sc.seconds.value() == 4321);
		}), EXIT_VERIFY_CB(AlarmSystemCall, {
			VERIFY(sc.old_seconds.value() == 1234);
		}),
		1);

#ifdef COSMOS_X86
	runTrace(SystemCallNr::ARCH_PRCTL,
		[]() {
			// disable SET_CPUID instruction
			syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
		},
		ENTRY_VERIFY_CB(ArchPrctlSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ArchOpParameter::Operation::SET_CPUID);
			VERIFY_FALSE(sc.set_addr || sc.get_addr || sc.on_off_ret);
			VERIFY(sc.on_off->value() == 0);
		}), EXIT_VERIFY_CB(ArchPrctlSystemCall, {
			/* either success or ENODEV is to be expected for this
			 * test */
			VERIFY(!sc.hasErrorCode() || *sc.error()->errorCode() == cosmos::Errno::NO_DEVICE);
		}));
#endif

	runTrace(SystemCallNr::BREAK,
		[]() {
			syscall(SYS_brk, 0x4711);
		},
		ENTRY_VERIFY_CB(BreakSystemCall, {
			VERIFY(sc.req_addr.ptr() == (void*)0x4711);
		}), EXIT_VERIFY_CB(BreakSystemCall, {
			VERIFY(!sc.hasErrorCode());
			VERIFY(sc.ret_addr.ptr() != nullptr);
		}));

	runTrace(SystemCallNr::CLOCK_NANOSLEEP,
		[]() {
			struct timespec ts;
			ts.tv_sec = 5;
			ts.tv_nsec = 500;
			/* avoid using the glibc wrapper, which does extra
			 * stuff on 32-bit */
			syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, &ts);
		},
		ENTRY_VERIFY_CB(ClockNanoSleepSystemCall, {
			VERIFY(sc.clockid.type() == cosmos::ClockType::MONOTONIC);
			using enum clues::item::ClockNanoSleepFlags::Flag;
			using Flags = clues::item::ClockNanoSleepFlags::Flags;
			VERIFY(sc.flags.flags() == Flags{ABSTIME});
			const auto &sleep_time = *sc.time.spec();
			VERIFY(sleep_time.tv_sec == 5 && sleep_time.tv_nsec == 500);
		}), EXIT_VERIFY_CB(ClockNanoSleepSystemCall, {
			VERIFY(!sc.hasErrorCode());
			/* remain is unused when TIMER_ABSTIME is passed or
			 * no EINTR occurred. */
			VERIFY(!sc.remaining.spec());
		}));

	runTrace(SystemCallNr::CLONE,
		[]() {
			pid_t child_tid = 9000;

#ifdef COSMOS_X86
			long flags = CLONE_PARENT_SETTID|SIGCHLD;
			if (sizeof(long) == 8) {
				/*
				 * this flag requires 64-bit registers, if we
				 * pass it, then `syscall()` will split it up
				 * to two registers, breaking our test.
				 */
				flags |= CLONE_CLEAR_SIGHAND;
			}
			auto res = syscall(SYS_clone, flags, nullptr, &child_tid);
#else
#error "adapt unit test to your ABI"
#endif
			if (res == 0) {
				_exit(123);
			} else {
				wait(NULL);
			}
		},
		ENTRY_VERIFY_CB(CloneSystemCall, {
			using enum cosmos::CloneFlag;
			if (sizeof(long) == 8) {
				VERIFY(sc.flags.flags() == cosmos::CloneFlags{CLEAR_SIGHAND, PARENT_SETTID});
			} else {
				/* on 32-bit ABIs the CLEAR_SIGHAND bit cannot
				 * be passed in the 32-bit register */
				VERIFY(sc.flags.flags() == cosmos::CloneFlags{PARENT_SETTID});
			}
			VERIFY(*(sc.flags.exitSignal()) == cosmos::SignalNr::CHILD);
			VERIFY(sc.stack.ptr() == nullptr);
			const auto parent_tid = *sc.parent_tid;
			VERIFY(((uintptr_t)parent_tid.pointer() & STACK_ADDR) == STACK_ADDR);
		}), EXIT_VERIFY_CB(CloneSystemCall, {
			VERIFY(!sc.hasErrorCode());
			const auto parent_tid = *sc.parent_tid;
			VERIFY(sc.new_pid.pid() == parent_tid.value());
		}));

	runTrace(SystemCallNr::CLONE3,
		[]() {
			int pidfd;
			int child_tid;
			struct clone_args args;
			memset(&args, 0, sizeof(args));
			args.flags = CLONE_CLEAR_SIGHAND|CLONE_PIDFD|CLONE_PARENT_SETTID;
			args.exit_signal = SIGCHLD;
			args.pidfd = (uintptr_t)&pidfd;
			args.parent_tid = (uintptr_t)&child_tid;
			if (syscall(SYS_clone3, &args, sizeof(args)) == 0) {
				_exit(123);
			} else {
				wait(NULL);
			}
		},
		ENTRY_VERIFY_CB(Clone3SystemCall, {
			using enum cosmos::CloneFlag;
			VERIFY(sc.size.value() == sizeof(clone_args));
			const auto &args = *sc.cl_args.args();
			VERIFY(args.flags() == cosmos::CloneFlags{CLEAR_SIGHAND, PIDFD, PARENT_SETTID});
			VERIFY(args.exitSignal().raw() == cosmos::SignalNr::CHILD);
			VERIFY(args.stack() == nullptr);
			VERIFY(args.stackSize() == 0);
		}), EXIT_VERIFY_CB(Clone3SystemCall, {
			VERIFY(!sc.hasErrorCode());
			VERIFY(sc.cl_args.pidfd() == FIRST_FD);
			VERIFY(sc.pid.pid() == static_cast<cosmos::ProcessID>(sc.cl_args.tid()));
		}));

	runTrace(SystemCallNr::CLOSE,
		[]() {
			close(2);
		},
		ENTRY_VERIFY_CB(CloseSystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum{2});
		}),
		EXIT_VERIFY_CB(CloseSystemCall, {
			VERIFY(sc.hasResultValue());
		}));
}

int main(const int argc, const char **argv) {
	SyscallTest test;
	return test.run(argc, argv);
}
