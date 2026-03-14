// Linux
#include <asm/prctl.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// C++
#include <cstring>
#include <iostream>
#include <type_traits>

// cosmos
#include <cosmos/compiler.hxx>
#include <cosmos/error/RuntimeError.hxx>

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
 * process which executes a lambda function which executes a system call under
 * test, for which system call enter and exit callbacks are expected, again
 * running lambda functions, to verify the observed data.
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

#ifdef COSMOS_X86_64
#	define TEST_I386_EMU

/*
 * syscall() like wrapper for explicitly calling 32-bit emulation system calls
 * in x86-64 context.
 *
 * For testing tracing of 32-bit emulation Tracee's we'd ideally need separate
 * binaries compiled with `-m32`, but this would bloat the unit testing
 * approach massively.
 *
 * Instead we go for a bit of a hacky solution by explicitly invoking 32-bit
 * system calls from our 64-bit child processes. This has a couple of
 * complications as well:
 *
 * - parameters to system calls must not be larger than 32 bits. We verify
 *   this in the wrapper and throw an exception should this happen. We verify
 *   this in the wrapper and throw an exception should this happen.
 * - this also goes for pointers, which means that we need to specially
 *   manager 32-bit memory allocations using `alloc32()`.
 *
 * NOTE: testing the X32 ABI can be done in a similar way. In modern kernels
 * the ABI is disabled by default, however and requires an explicit boot
 * parameter to work. Since this ABI is highly exotic these days it probably
 * doesn't make sense to invest a lot of work into it at the moment.
 */
template <class T1=long, class T2=long, class T3=long, class T4=long, class T5=long, class T6=long>
static int syscall32(const clues::SystemCallNrI386 nr,
		T1 t1=0, T2 t2=0, T3 t3=0, T4 t4=0, T5 t5=0, T6 t6=0) {

	auto fits_in32 = [](long x) -> bool {
		return (long)(int32_t)x == x;
	};

	auto cast_to_long = [](auto in) -> long {
		if constexpr (std::is_arithmetic_v<decltype(in)>) {
			return static_cast<long>(in);
		}

		if constexpr (!std::is_arithmetic_v<decltype(in)>) {
			return reinterpret_cast<long>(in);
		}
	};

	long _1 = cast_to_long(t1);
	long _2 = cast_to_long(t2);
	long _3 = cast_to_long(t3);
	long _4 = cast_to_long(t4);
	long _5 = cast_to_long(t5);
	long _6 = cast_to_long(t6);

	register long eax asm("eax") = cosmos::to_integral(nr);
	register long ebx asm("ebx") = _1;
	register long ecx asm("ecx") = _2;
	register long edx asm("edx") = _3;
	register long esi asm("esi") = _4;
	register long edi asm("edi") = _5;

	if (!fits_in32(_1) || !fits_in32(_2) || !fits_in32(_3) || !fits_in32(_4) || !fits_in32(_5) || !fits_in32(_6)) {
		throw cosmos::RuntimeError{"too large syscall32 parameters"};
	}

	asm volatile(
			"push %%rbp\n\t"
			"mov %[_6], %%rbp\n\t"
			"int $0x80\n\t"
			"pop %%rbp"
			: "+r"(eax)
			: "r"(ebx), "r"(ecx), "r"(edx),
			"r"(esi), "r"(edi), [_6]"r"(_6)
			: "memory"
	);

	return eax;
}

template <typename T>
static T alloc32(size_t bytes) {
	auto ret = mmap(nullptr, bytes, PROT_READ|PROT_WRITE, MAP_32BIT|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (ret == MAP_FAILED) {
		throw cosmos::ApiError{"mmap()[32]"};
	}

	return reinterpret_cast<T>(ret);
}

static const char* alloc_str32(const char *s) {
	const auto len = std::strlen(s);
	auto ret = alloc32<char*>(len);
	std::strcpy(ret, s);
	return ret;
}
#endif // COSMOS_X86_64

class SyscallTracer :
		public clues::EventConsumer {
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

protected:

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
		} else if (m_abi != clues::ABI::UNKNOWN && call.abi() != m_abi) {
			std::cerr << __FUNCTION__ << ": ABI mismatch for system call\n";
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

	void attached(clues::Tracee &) override {
		m_creator->signalChild();
	}

	void exited(clues::Tracee&, const cosmos::WaitStatus,
			const StatusFlags) override {
		if (!m_ran_cbs) {
			std::cerr << "never seen expected system call!\n";
		}
	}

public:

	void setCreator(TraceeCreator<SyscallInvoker> &creator) {
		/*
		 * we need this to synchronize exactly to the eventfd read()
		 * in the child in attached().
		 */
		m_creator = &creator;
	}

	void setABI(const clues::ABI abi) {
		m_abi = abi;
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
	// for emulation targets this is set to the expected ABI
	clues::ABI m_abi = clues::ABI::UNKNOWN;
};

template <typename SC>
const SC& downcast(const SystemCall &sc) {
	return dynamic_cast<const SC&>(sc);
}

class SyscallTest :
	public cosmos::TestBase {
protected:
	void runTests() override;

	void runNativeTests();

	void run32BitEmuTests();

	void runTrace(
			const SystemCallNr nr,	
			SyscallInvoker invoker,
			TraceVerifyCB enter_verify,
			TraceVerifyCB exit_verify,
			const size_t ignore_calls = 0,
			const clues::ABI abi = clues::ABI::UNKNOWN) {
		const auto name = clues::SYSTEM_CALL_NAMES[cosmos::to_integral(nr)];
		START_TEST(cosmos::sprintf("testing system call %s", &name[0]));
		SyscallTracer tracer{nr, enter_verify, exit_verify, ignore_calls};

		TraceeCreator creator{std::move(invoker), tracer};
		tracer.setCreator(creator);
		tracer.setABI(abi);
		try {
			creator.run(clues::FollowChildren{false},
					/*explicit_signal=*/true);
		} catch (const std::exception &ex) {
			std::cerr << "test failed: " << ex.what() << std::endl;
		}
		RUN_STEP("system call entry good", tracer.entryGood());
		RUN_STEP("system call exit good", tracer.exitGood());
	}

#ifdef TEST_I386_EMU
	void runI386Trace(
			const SystemCallNr nr,
			SyscallInvoker invoker,
			TraceVerifyCB enter_verify,
			TraceVerifyCB exit_verify,
			const size_t ignore_calls = 0) {
		runTrace(nr, invoker, enter_verify, exit_verify,
				ignore_calls, clues::ABI::I386);
	}
#endif

protected:

	// helper binary
	std::string m_exiter;
};

namespace {
/* check routines shared between multiple system calls*/

/* shared entry check for faccessat1/2 */
template <typename SC>
void check_faccessat_entry(const SC &access_sc, bool &good) {
	VERIFY(access_sc.dirfd.fd() == FIRST_FD);
	VERIFY(access_sc.path.data() == "etc");

	using cosmos::fs::AccessCheck;
	using cosmos::fs::AccessChecks;
	const AccessChecks checks{AccessCheck::READ_OK, AccessCheck::EXEC_OK};
	VERIFY((*access_sc.mode.checks()) == checks);
};

} // end anon ns

void SyscallTest::runTests() {
	m_exiter = findHelper("exiter");

	runNativeTests();
	run32BitEmuTests();
}

void SyscallTest::runNativeTests() {

	/*
	 * the following are per system call unit tests:
	 *
	 * - the first callback is a function executed in a child tracee
	 *   context. system call events will be monitored by SyscallTracer,
	 *   which will invoked a TraceVerifyCB on entry and exit of the
	 *   system call under test.
	 * - the second callback is the TraceVerifyCB which inspects the
	 *   system call enter event. It should validate any in/in-out
	 *   parameters. The macros ENTRY_VERIFY_CB and EXIT_VERIFY_CB
	 *   automatically placed an appropriately typed SystemCall object on
	 *   the stack to work with.
	 * - the third callback is the TraceVerifyCB which inspects the system
	 *   call exit event. It should validate any in-out/out and return
	 *   parameters as well as system call success indication.
	 * - The optional last parameter is a system call skip count. Since we
	 *   want to hit exactly the system call under test and nothing else
	 *   we need to keep track of any additional system calls that might
	 *   occur before the system call under test.
	 * - The VERIFY macro marks a bad test state with an informational
	 *   error output and stops executing the current callback.
	 */

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

	runTrace(SystemCallNr::FACCESSAT,
		[]() {
			auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_faccessat, dirfd, "etc", R_OK|X_OK);
		},
		ENTRY_VERIFY_CB(FAccessAtSystemCall, {
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
		ENTRY_VERIFY_CB(FAccessAt2SystemCall, {
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

	runTrace(SystemCallNr::EXECVE,
		[this]() {
			const char* const args[] = {m_exiter.c_str(), "5", NULL};
			const char* const env[] = {"THIS=THAT", "ME=YOU", NULL};
			::execve(m_exiter.c_str(), const_cast<char *const*>(args), const_cast<char*const*>(env));
			_exit(128);
		},
		ENTRY_VERIFY_CB_CAPTURE(this, ExecveSystemCall, {
			VERIFY(sc.pathname.data() == m_exiter);
			VERIFY(sc.argv.data() == cosmos::StringVector{m_exiter, "5"});
			VERIFY(sc.envp.data() == cosmos::StringVector{"THIS=THAT", "ME=YOU"});
		}), EXIT_VERIFY_CB(ExecveSystemCall, {
			VERIFY(sc.hasResultValue());
		}));

	runTrace(SystemCallNr::EXECVEAT,
		[this]() {
			int fd = open(m_exiter.c_str(), O_RDONLY|O_PATH);
			const char* const args[] = {m_exiter.c_str(), "5", NULL};
			const char* const env[] = {"THIS=THAT", "ME=YOU", NULL};
			execveat(fd, "",
					const_cast<char * const *>(args),
					const_cast<char * const *>(env),
					AT_EMPTY_PATH);
			_exit(128);
		},
		ENTRY_VERIFY_CB_CAPTURE(this, ExecveAtSystemCall, {
			VERIFY(sc.dirfd.fd() == cosmos::FileNum(FIRST_FD));
			VERIFY(sc.pathname.data() == "");
			VERIFY(sc.argv.data() == cosmos::StringVector{m_exiter, "5"});
			VERIFY(sc.envp.data() == cosmos::StringVector{"THIS=THAT", "ME=YOU"});
			using AtFlags = clues::item::AtFlagsValue::AtFlags;
			using enum clues::item::AtFlagsValue::AtFlag;
			VERIFY(sc.flags.flags() == AtFlags{EMPTY_PATH});
		}), EXIT_VERIFY_CB(ExecveAtSystemCall, {
			VERIFY(sc.hasResultValue());
		}),
		1);
}

void SyscallTest::run32BitEmuTests() {
#ifdef TEST_I386_EMU
	using SysCallNr = clues::SystemCallNrI386;
	runI386Trace(SystemCallNr::ACCESS,
		[]() {
			syscall32(SysCallNr::ACCESS, alloc_str32("/etc/"), R_OK|X_OK);
		},
		ENTRY_VERIFY_CB(AccessSystemCall, {
			VERIFY(sc.path.data() == "/etc/");
			using cosmos::fs::AccessCheck;
			using cosmos::fs::AccessChecks;
			const AccessChecks checks{AccessCheck::READ_OK, AccessCheck::EXEC_OK};
			VERIFY((*sc.mode.checks()) == checks);
		}), EXIT_VERIFY_CB(AccessSystemCall, {
			VERIFY(!sc.hasErrorCode());
		}),
		1);

#endif
}

int main(const int argc, const char **argv) {
	SyscallTest test;
	return test.run(argc, argv);
}
