// C++
#include <cstring>
#include <iostream>
#include <type_traits>
#include <vector>

// cosmos
#include <cosmos/compiler.hxx>
#include <cosmos/error/RuntimeError.hxx>
#include <cosmos/memory.hxx>
#include <cosmos/proc/process.hxx>

// clues
#include <clues/private/kernel/mmap.hxx>
#include <clues/private/kernel/other.hxx>
#include <clues/private/kernel/time.hxx>
#include <clues/private/kernel/sigaction.hxx>
#include <clues/syscalls/all.hxx>
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>

// Linux
#ifdef CLUES_HAVE_ARCH_PRCTL
#include <asm/prctl.h>
#endif
#include <fcntl.h>
#include <linux/fs.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>


// Test
#include "TestBase.hxx"
#include "TraceeCreator.hxx"

using namespace std::string_literals;

/*
 * This is a collective unit test for every single system call.
 *
 * This is a test purely on library API level. We're setting up a child
 * process which executes a lambda function which executes a system call under
 * test, for which system call enter and exit callbacks are expected, again
 * running lambda functions, to verify the observed data.
 */

using clues::SystemCall;
using clues::Tracee;
using TraceVerifyCB = std::function<void (const Tracee &, const SystemCall &, bool &good)>;
using SyscallInvoker = std::function<void (void)>;
using clues::SystemCallNr;
using clues::ForeignPtr;

enum class IgnoreCalls : size_t {
	NONE = 0
};

/*
 * for cross-ABI tracing tests like 32-bit emulation on x86-64, this specifies
 * the extra ingredients:
 * - the cross-target ABI
 * - the ABI specific system call invoker
 * - the ignore call counter
 * the rest of the TestSpec will stay the same.
 */
struct ExtraABI {
	clues::ABI abi;
	IgnoreCalls ignore_calls = IgnoreCalls::NONE;
	SyscallInvoker invoker;
};

struct TestSpec {
	clues::SystemCallNr nr;
	SyscallInvoker invoker;
	TraceVerifyCB enter_verify;
	TraceVerifyCB exit_verify;
	IgnoreCalls ignore_calls = IgnoreCalls::NONE;
	std::vector<ExtraABI> extra_abi_tests = {};
	// a label to differentiate different test variant of the same system
	// call, can be empty
	std::string_view variant = {};
	// if empty then the test is for all ABIs, otherwise only for the
	// contained ABIs.
	std::vector<clues::ABI> abis = {};

	bool isSupportedABI() const {
		if (abis.empty()) {
			return true;
		}

		for (const auto abi: abis) {
			if (abi == clues::get_default_abi())
				return true;
		}

		return false;
	}
};

/*
 * the first file descriptor number which will be used in tracee context.
 * used for comparison of file descriptor values observed.
 */
constexpr cosmos::FileNum FIRST_FD{4};
constexpr cosmos::FileNum SECOND_FD{5};
constexpr uintptr_t STACK_ADDR = sizeof(void*) == 8 ? 0x700000000000 : 0x70000000;

#define VERIFY(...) if (!(__VA_ARGS__)) { \
	std::cerr << "check |" << #__VA_ARGS__ << "| failed\n"; \
	good = false; \
	return; \
}

#define VERIFY_FALSE(expr) VERIFY(!(expr))

#define ENTRY_VERIFY_CB(SYSTEM_CALL_TYPE, ...) [](const Tracee &tracee, const SystemCall &_sc, bool &good) { \
	(void)tracee; \
	good = true; \
	const auto &sc = downcast<clues::SYSTEM_CALL_TYPE>(_sc); \
	__VA_ARGS__ \
}

#define ENTRY_VERIFY_CB_CAPTURE(CAPTURE, SYSTEM_CALL_TYPE, ...) [CAPTURE](const Tracee &tracee, const SystemCall &_sc, bool &good) { \
	(void)tracee; \
	good = true; \
	const auto &sc = downcast<clues::SYSTEM_CALL_TYPE>(_sc); \
	__VA_ARGS__ \
}

#define EXIT_VERIFY_CB(SYSTEM_CALL_TYPE, ...) [](const Tracee &tracee, const SystemCall &_sc, bool &good) { \
	(void)tracee; \
	good = true; \
	const auto &sc = downcast<clues::SYSTEM_CALL_TYPE>(_sc); \
	__VA_ARGS__ \
}

/*
 * this is used to perform the same system call twice, which is useful when
 * output parameters are present and we want to verify that no old state
 * remains in the SystemCall object.
 */
#define TWICE(...) { \
	for (auto _: cosmos::Twice{}) { \
		__VA_ARGS__; \
	} \
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
		if constexpr (std::is_arithmetic_v<decltype(in)> || std::is_enum_v<decltype(in)>) {
			return static_cast<long>(in);
		}

		if constexpr (!std::is_arithmetic_v<decltype(in)> && !std::is_enum_v<decltype(in)>) {
			return reinterpret_cast<long>(in);
		}
	};

	long _1 = cast_to_long(t1);
	long _2 = cast_to_long(t2);
	long _3 = cast_to_long(t3);
	long _4 = cast_to_long(t4);
	long _5 = cast_to_long(t5);
	long _6 = cast_to_long(t6);

	if (!fits_in32(_1) || !fits_in32(_2) || !fits_in32(_3) || !fits_in32(_4) || !fits_in32(_5) || !fits_in32(_6)) {
		throw cosmos::RuntimeError{"too large syscall32 parameters"};
	}

	register long eax asm("eax") = cosmos::to_integral(nr);
	register long ebx asm("ebx") = _1;
	register long ecx asm("ecx") = _2;
	register long edx asm("edx") = _3;
	register long esi asm("esi") = _4;
	register long edi asm("edi") = _5;

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

template <typename T>
static T* alloc_struct32() {
	return alloc32<T*>(sizeof(T));
}

static const char* alloc_str32(const char *s) {
	const auto len = std::strlen(s) + 1;
	auto ret = alloc32<char*>(len);
	std::strcpy(ret, s);
	return ret;
}
#endif // COSMOS_X86_64

#ifdef TEST_I386_EMU
#	define I386_CROSS_ABI(IGNORE_COUNT, ...) ExtraABI{ \
		clues::ABI::I386, \
		IGNORE_COUNT, \
		__VA_ARGS__ \
	}
#else
#	define I386_CROSS_ABI(IGNORE_COUNT, ...)
#endif

class SyscallTracer :
		public clues::EventConsumer {
public:
	explicit SyscallTracer(const SystemCallNr nr,
			TraceVerifyCB enter_verify,
			TraceVerifyCB exit_verify,
			const IgnoreCalls ignore_calls = IgnoreCalls::NONE) :
				m_call_nr{nr},
				m_enter_verify{enter_verify},
				m_exit_verify{exit_verify},
				m_ignore_calls{ignore_calls} {
	}

protected:

	void syscallEntry(clues::Tracee &tracee,
			const SystemCall &call,
			const StatusFlags) override {
		if (m_ran_cbs) {
			return;
		} else if (!m_seen_initial_read) {
			return;
		} else if (m_current_call != cosmos::to_integral(m_ignore_calls)) {
			// we haven't reached the system call under test yet
			return;
		}

		if (call.callNr() != m_call_nr) {
			const auto sys_name = clues::SYSTEM_CALL_NAMES[cosmos::to_integral(call.callNr())];
			std::cerr << __FUNCTION__ << ": unexpected system call nr " << cosmos::to_integral(call.callNr()) << " (" << sys_name << ")\n";
			return;
		} else if (m_abi != clues::ABI::UNKNOWN && call.abi() != m_abi) {
			std::cerr << __FUNCTION__ << ": ABI mismatch for system call\n";
			return;
		}

		m_enter_verify(tracee, call, m_entry_good);
	}

	void syscallExit(clues::Tracee &tracee,
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
		} else if (m_current_call++ != cosmos::to_integral(m_ignore_calls)) {
			// we haven't reached the system call under test yet
			return;
		}

		if (call.callNr() != m_call_nr) {
			std::cerr << __FUNCTION__ << ": unexpected system call nr " << cosmos::to_integral(call.callNr()) << "\n";
			return;
		}

		m_exit_verify(tracee, call, m_exit_good);
		m_ran_cbs = true;
	}

	void attached(clues::Tracee &) override {
		m_creator->signalChild();
	}

	void exited(clues::Tracee&, const cosmos::WaitStatus,
			const StatusFlags) override {
		if (!m_ran_cbs) {
			if (m_entry_good && cosmos::in_list(m_call_nr, {clues::SystemCallNr::EXIT_GROUP})) {
				/* for exit system calls system-call-exit will
				 * never be observed */
				m_exit_good = true;
			} else {
				std::cerr << "never seen expected system call!\n";
			}
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
	IgnoreCalls m_ignore_calls = IgnoreCalls::NONE;
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

	void runTrace(
		const SystemCallNr nr,
		SyscallInvoker invoker,
		TraceVerifyCB enter_verify,
		TraceVerifyCB exit_verify,
		const IgnoreCalls ignore_calls = IgnoreCalls::NONE,
		const clues::ABI abi = clues::ABI::UNKNOWN,
		const std::string_view variant = "");
protected:
	std::string m_syscall_filter;
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
	VERIFY(access_sc.mode.checks() == checks);
};


/// path to the exiter helper
std::string exiter;

#ifdef TEST_I386_EMU
using SyscallNr32 = clues::SystemCallNrI386;
#endif

/*
 * the following are per system call unit tests specifications:
 *
 * - the first callback (`SyscallInvoker`) is a function executed in a child
 *   tracee context. system call events will be monitored by SyscallTracer,
 *   which will invoked a TraceVerifyCB on entry and exit of the system call
 *   under test.
 * - the second  callback (`TraceVerifyCB`) inspects the system call enter
 *   event.  It should validate any in/in-out parameters.  The macros
 *   ENTRY_VERIFY_CB and EXIT_VERIFY_CB automatically placed an appropriately
 *   typed SystemCall object on the stack to work with.
 * - the third callback (`TraceVerifyCB`) inspects the system call exit event.
 *   It should validate any in-out/out and return parameters as well as system
 *   call success indication.
 * - The optional size_t is a system call skip count. Since we want to hit
 *   exactly the system call under test and nothing else we need to keep track
 *   of any additional system calls that might occur before the system call
 *   under test.
 * - The VERIFY macro marks a bad test state with an informational
 *   error output and stops executing the current TraceVerifyCB callback.
 * - The optional ExtraABI vector contains additional emulation target test
 *   specification for the same system call.
 */
const auto TESTS = std::array{
#ifdef CLUES_HAVE_ACCESS
	TestSpec{SystemCallNr::ACCESS, []() {
			access("/etc/", R_OK|X_OK);
		}, ENTRY_VERIFY_CB(AccessSystemCall, {
			VERIFY(sc.path.data() == "/etc/");
			using cosmos::fs::AccessCheck;
			using cosmos::fs::AccessChecks;
			const AccessChecks checks{AccessCheck::READ_OK, AccessCheck::EXEC_OK};
			VERIFY(sc.mode.checks() == checks);
		}), EXIT_VERIFY_CB(AccessSystemCall, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				syscall32(SyscallNr32::ACCESS,
					alloc_str32("/etc/"), R_OK|X_OK);
			})
		}
	},
#endif
	TestSpec{SystemCallNr::FACCESSAT, []() {
			auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_faccessat, dirfd, "etc", R_OK|X_OK);
		}, ENTRY_VERIFY_CB(FAccessAtSystemCall, {
			check_faccessat_entry(sc, good);
		}), EXIT_VERIFY_CB(FAccessAtSystemCall, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
				syscall32(SyscallNr32::FACCESSAT, dirfd, alloc_str32("etc"), R_OK|X_OK);
			})
		}
	}, TestSpec{SystemCallNr::FACCESSAT2, []() {
			auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_faccessat2, dirfd, "etc", R_OK|X_OK, AT_EACCESS);
		}, ENTRY_VERIFY_CB(FAccessAt2SystemCall, {
			check_faccessat_entry(sc, good);
			if (!good)
				return;
			using AtFlags = clues::item::AtFlagsValue::AtFlags;
			using enum clues::item::AtFlagsValue::AtFlag;
			VERIFY(sc.flags.flags() == AtFlags{EACCESS})
		}), EXIT_VERIFY_CB(FAccessAt2SystemCall, {
			VERIFY(!sc.hasErrorCode());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
					auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
					syscall32(SyscallNr32::FACCESSAT2, dirfd, alloc_str32("etc"), R_OK|X_OK, AT_EACCESS);
			})
		}
#ifdef CLUES_HAVE_ALARM
	}, TestSpec{SystemCallNr::ALARM, []() {
			/* make two calls so that we get a non-zero return
			 * value */
			alarm(1234);
			alarm(4321);
		}, ENTRY_VERIFY_CB(AlarmSystemCall, {
			VERIFY(sc.seconds.value() == 4321);
		}), EXIT_VERIFY_CB(AlarmSystemCall, {
			VERIFY(sc.old_seconds.value() == 1234);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				syscall32(SyscallNr32::ALARM, 1234);
				syscall32(SyscallNr32::ALARM, 4321);
			})
		}
#endif
	}, TestSpec{SystemCallNr::BREAK, []() {
			syscall(SYS_brk, 0x4711);
		}, ENTRY_VERIFY_CB(BreakSystemCall, {
			VERIFY(sc.req_addr.ptr() == ForeignPtr{0x4711});
		}), EXIT_VERIFY_CB(BreakSystemCall, {
			VERIFY(!sc.hasErrorCode());
			VERIFY(sc.ret_addr.ptr() != ForeignPtr::NO_POINTER);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				/* on i386 BREAK is a different system call */
				syscall32(SyscallNr32::BRK, 0x4711);
			})
		}
	}, TestSpec{SystemCallNr::CLOCK_NANOSLEEP, []() {
			struct timespec ts;
			ts.tv_sec = 5;
			ts.tv_nsec = 500;
			/* avoid using the glibc wrapper, which does extra
			 * stuff on 32-bit */
			syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, &ts);
		}, ENTRY_VERIFY_CB(ClockNanoSleepSystemCall, {
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
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto ts32 = alloc_struct32<clues::timespec32>();
				ts32->tv_sec = 5;
				ts32->tv_nsec = 500;
				syscall32(SyscallNr32::CLOCK_NANOSLEEP,
						CLOCK_MONOTONIC,
						TIMER_ABSTIME,
						ts32, ts32);
			})
		}
	}, TestSpec{SystemCallNr::CLONE, []() {
			pid_t child_tid = 9000;

			long flags = CLONE_PARENT_SETTID|SIGCHLD;
			if (sizeof(long) == 8) {
				/*
				 * this flag requires 64-bit registers, if we
				 * pass it, then `syscall()` will split it up
				 * to two registers, breaking our test.
				 */
				flags |= CLONE_CLEAR_SIGHAND;
			}
#if defined(COSMOS_X86) or defined(COSMOS_AARCH64)
			// the first three parameters are all the same on these architectures
			auto res = syscall(SYS_clone, flags, nullptr, &child_tid);
#else
#	error "adapt unit test to your ABI"
#endif
			if (res == 0) {
				_exit(123);
			} else {
				wait(NULL);
			}
		}, ENTRY_VERIFY_CB(CloneSystemCall, {
			using enum cosmos::CloneFlag;
			if (sc.abi() != clues::ABI::I386 && sizeof(long) == 8) {
				VERIFY(sc.flags.flags() == cosmos::CloneFlags{CLEAR_SIGHAND, PARENT_SETTID});
			} else {
				/* on 32-bit ABIs the CLEAR_SIGHAND bit cannot
				 * be passed in the 32-bit register */
				VERIFY(sc.flags.flags() == cosmos::CloneFlags{PARENT_SETTID});
			}
			VERIFY(*(sc.flags.exitSignal()) == cosmos::SignalNr::CHILD);
			VERIFY(sc.stack.ptr() == ForeignPtr::NO_POINTER);
			const auto parent_tid = *sc.parent_tid;
			/* when tracing cross-ABI then there are no stack
			 * addresses used in the invoker code */
			VERIFY(((uintptr_t)parent_tid.pointer() & STACK_ADDR) == STACK_ADDR ||
					!clues::is_default_abi(sc.abi()));
		}), EXIT_VERIFY_CB(CloneSystemCall, {
			VERIFY(!sc.hasErrorCode());
			const auto parent_tid = *sc.parent_tid;
			VERIFY(sc.new_pid.pid() == parent_tid.value());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, [](){
				auto child_tid = alloc_struct32<pid_t>();
				*child_tid = 9000;

				long flags = CLONE_PARENT_SETTID|SIGCHLD;
				auto res = syscall32(SyscallNr32::CLONE, flags, nullptr, child_tid);
				if (res == 0) {
					_exit(123);
				} else {
					wait(NULL);
				}
			})
		}
	}, TestSpec{SystemCallNr::CLONE3, []() {
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
		}, ENTRY_VERIFY_CB(Clone3SystemCall, {
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
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto pidfd = alloc_struct32<int>();
				auto child_tid = alloc_struct32<int>();
				auto args = alloc_struct32<struct clone_args>();
				memset(args, 0, sizeof(*args));
				args->flags = CLONE_CLEAR_SIGHAND|CLONE_PIDFD|CLONE_PARENT_SETTID;
				args->exit_signal = SIGCHLD;
				args->pidfd = (uintptr_t)pidfd;
				args->parent_tid = (uintptr_t)child_tid;
				if (syscall32(SyscallNr32::CLONE3, args, sizeof(*args)) == 0) {
					_exit(123);
				} else {
					wait(NULL);
				}
			})
		}
	}, TestSpec{SystemCallNr::CLOSE, []() {
			close(2);
		}, ENTRY_VERIFY_CB(CloseSystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum{2});
		}), EXIT_VERIFY_CB(CloseSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::CLOSE, 2);
			})
		}
	}, TestSpec{SystemCallNr::EXECVE, []() {
			const char* const args[] = {exiter.c_str(), "5", NULL};
			const char* const env[] = {"THIS=THAT", "ME=YOU", NULL};
			::execve(exiter.c_str(), const_cast<char *const*>(args), const_cast<char*const*>(env));
			_exit(128);
		}, ENTRY_VERIFY_CB(ExecveSystemCall, {
			VERIFY(sc.pathname.data() == exiter);
			VERIFY(sc.argv.data() == cosmos::StringVector{exiter, "5"});
			VERIFY(sc.envp.data() == cosmos::StringVector{"THIS=THAT", "ME=YOU"});
		}), EXIT_VERIFY_CB(ExecveSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{6}, []() {
				/*
				 * setting up pointers to pointers is
				 * especially awkward when having to limit
				 * everything to a 32-bit address space.
				 */
				constexpr auto PTR_SIZE32 = sizeof(uint32_t);
				auto args = alloc32<uint32_t* const>(PTR_SIZE32*3);
				auto env = alloc32<uint32_t* const>(PTR_SIZE32*3);
				auto exiter32 = alloc_str32(exiter.c_str());
				args[0] = (uintptr_t)exiter32;
				args[1] = (uintptr_t)alloc_str32("5");
				args[2] = 0;
				env[0] = (uintptr_t)alloc_str32("THIS=THAT");
				env[1] = (uintptr_t)alloc_str32("ME=YOU");
				env[2] = 0;
				syscall32(SyscallNr32::EXECVE, exiter32, args, env);
				_exit(128);
			})
		}
	}, TestSpec{SystemCallNr::EXECVEAT, []() {
			int fd = open(exiter.c_str(), O_RDONLY|O_PATH);
			const char* const args[] = {exiter.c_str(), "5", NULL};
			const char* const env[] = {"THIS=THAT", "ME=YOU", NULL};
			execveat(fd, "",
					const_cast<char * const *>(args),
					const_cast<char * const *>(env),
					AT_EMPTY_PATH);
			_exit(128);
		}, ENTRY_VERIFY_CB(ExecveAtSystemCall, {
			VERIFY(sc.dirfd.fd() == FIRST_FD);
			VERIFY(sc.pathname.data() == "");
			VERIFY(sc.argv.data() == cosmos::StringVector{exiter, "5"});
			VERIFY(sc.envp.data() == cosmos::StringVector{"THIS=THAT", "ME=YOU"});
			using AtFlags = clues::item::AtFlagsValue::AtFlags;
			using enum clues::item::AtFlagsValue::AtFlag;
			VERIFY(sc.flags.flags() == AtFlags{EMPTY_PATH});
		}), EXIT_VERIFY_CB(ExecveAtSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{8}, [](){
				int fd = open(exiter.c_str(), O_RDONLY|O_PATH);
				/*
				 * setting up pointers to pointers is
				 * especially awkward when having to limit
				 * everything to a 32-bit address space.
				 */
				constexpr auto PTR_SIZE32 = sizeof(uint32_t);
				auto args = alloc32<uint32_t* const>(PTR_SIZE32*3);
				auto env = alloc32<uint32_t* const>(PTR_SIZE32*3);
				auto exiter32 = alloc_str32(exiter.c_str());
				auto empty = alloc_str32("");
				args[0] = (uintptr_t)exiter32;
				args[1] = (uintptr_t)alloc_str32("5");
				args[2] = 0;
				env[0] = (uintptr_t)alloc_str32("THIS=THAT");
				env[1] = (uintptr_t)alloc_str32("ME=YOU");
				env[2] = 0;
				syscall32(SyscallNr32::EXECVEAT, fd, empty, args, env, AT_EMPTY_PATH);
				_exit(128);
			})
		}
	}, TestSpec{SystemCallNr::EXIT_GROUP, []() {
			syscall(SYS_exit_group, 99);
		}, ENTRY_VERIFY_CB(ExitGroupSystemCall, {
			VERIFY(sc.status.status() == cosmos::ExitStatus{99});
		}), EXIT_VERIFY_CB(ExitGroupSystemCall, {
			/* there will be no syscall return event for exit
			 * system calls */
			(void)sc;
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::EXIT_GROUP, 99);
			})
		}
	   /* TODO: cover more operations from fcntl */
	}, TestSpec{SystemCallNr::FCNTL, []() { /* F_GETFD test */
			int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
			syscall(SYS_fcntl, fd, F_GETFD);
		}, ENTRY_VERIFY_CB(FcntlSystemCall, {
			using Oper = clues::item::FcntlOperation::Oper;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.operation.operation() == Oper::GETFD);
		}), EXIT_VERIFY_CB(FcntlSystemCall, {
			VERIFY(sc.hasResultValue());
			using DescFlags = cosmos::FileDescriptor::DescFlags;
			using enum cosmos::FileDescriptor::DescFlag;
			VERIFY(sc.ret_fd_flags->flags() == DescFlags{CLOEXEC});
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
				syscall32(SyscallNr32::FCNTL, fd, F_GETFD);
			})
		},
		"GETFD"
	}, TestSpec{SystemCallNr::FCNTL, []() { /* F_SETFD test */
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC);
		}, ENTRY_VERIFY_CB(FcntlSystemCall, {
			using Oper = clues::item::FcntlOperation::Oper;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.operation.operation() == Oper::SETFD);
			using DescFlags = cosmos::FileDescriptor::DescFlags;
			using enum cosmos::FileDescriptor::DescFlag;
			VERIFY(sc.fd_flags_arg->flags() == DescFlags{CLOEXEC});
		}), EXIT_VERIFY_CB(FcntlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
				syscall32(SyscallNr32::FCNTL, fd, F_SETFD, FD_CLOEXEC);
			})
		},
		"SETFD"
	}, TestSpec{SystemCallNr::FCNTL64, []() {
#ifdef COSMOS_I386
			int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
			syscall(SYS_fcntl64, fd, F_GETFD);
#endif
		}, ENTRY_VERIFY_CB(FcntlSystemCall, {
			using Oper = clues::item::FcntlOperation::Oper;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.operation.operation() == Oper::GETFD);
		}), EXIT_VERIFY_CB(FcntlSystemCall, {
			using DescFlags = cosmos::FileDescriptor::DescFlags;
			using enum cosmos::FileDescriptor::DescFlag;
			VERIFY(sc.hasResultValue());
			VERIFY(sc.ret_fd_flags->flags() == DescFlags{CLOEXEC});
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
				syscall32(SyscallNr32::FCNTL64, fd, F_GETFD);
			})
		},
		"",
		{clues::ABI::I386}
#ifdef CLUES_HAVE_FORK
	}, TestSpec{SystemCallNr::FORK, []() {
			/* the fork() wrapper may invoke SYS_clone instead */
			if (syscall(SYS_fork) == 0) {
				_exit(0);
			} else {
				wait(NULL);
			}
		}, ENTRY_VERIFY_CB(ForkSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(ForkSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				if (syscall32(SyscallNr32::FORK) == 0) {
					_exit(0);
				} else {
					wait(NULL);
				}
			})
		},
#endif
	}, TestSpec{SystemCallNr::FSTAT, []() {
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			struct stat st;
			syscall(SYS_fstat, fd, &st);
		}, ENTRY_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &sb = *sc.statbuf.status();
			VERIFY(sb.valid());
			VERIFY(sb.mode().mask().raw() == 0755);
			VERIFY(sb.type().isDirectory());
			VERIFY(sb.uid() == cosmos::UserID::ROOT);
			VERIFY(sb.gid() == cosmos::GroupID::ROOT);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				/* the size of this struct stat is too big,
				 * but it doesn't matter as long as we don't
				 * interpret it in this callback */
				auto st = alloc_struct32<struct stat>();
				syscall32(SyscallNr32::FSTAT, fd, st);
			})
		},
	}, TestSpec{SystemCallNr::FSTAT64, []() {
#ifdef COSMOS_I386
			int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
			struct stat st;
			syscall(SYS_fstat64, fd, &st);
#endif
		}, ENTRY_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &sb = *sc.statbuf.status();
			VERIFY(sb.valid());
			VERIFY(sb.mode().mask().raw() == 0755);
			VERIFY(sb.type().isDirectory());
			VERIFY(sb.uid() == cosmos::UserID::ROOT);
			VERIFY(sb.gid() == cosmos::GroupID::ROOT);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				auto st = alloc_struct32<struct stat>();
				syscall32(SyscallNr32::FSTAT64, fd, st);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::OLDFSTAT, []() {
#ifdef COSMOS_I386
			int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
			/* the struct will be too big, bug that should be no
			 * matter as long as we don't touch it here */
			struct stat st;
			TWICE(syscall(SYS_oldfstat, fd, &st));
#endif
		}, ENTRY_VERIFY_CB(FstatSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(FstatSystemCall, {
			/* NOTE: this call could fail if some of the metadata
			 * doesn't fit in the old stat structure */
			VERIFY(sc.hasResultValue());
			const auto &sb = *sc.statbuf.status();
			VERIFY(sb.valid());
			VERIFY(sb.mode().mask().raw() == 0755);
			VERIFY(sb.type().isDirectory());
			VERIFY(sb.uid() == cosmos::UserID::ROOT);
			VERIFY(sb.gid() == cosmos::GroupID::ROOT);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				auto st = alloc_struct32<struct stat>();
				syscall32(SyscallNr32::OLDFSTAT, fd, st);
			})
		},
		"",
		{clues::ABI::I386}
	   /* TODO cover more operations of futex() */
	}, TestSpec{SystemCallNr::FUTEX, []() {
			uint32_t fux = 123;
			struct timespec ts;
			ts.tv_sec = 5;
			ts.tv_nsec = 500;
			syscall(SYS_futex, &fux, FUTEX_WAIT|FUTEX_CLOCK_REALTIME, 1, &ts);
		}, ENTRY_VERIFY_CB(FutexSystemCall, {
			using FuxOp = clues::item::FutexOperation;
			VERIFY(sc.operation.command() == FuxOp::Command::WAIT);
			using enum FuxOp::Flag;
			using Flags = FuxOp::Flags;
			VERIFY(sc.operation.flags() == Flags{REALTIME});
			VERIFY(sc.value->value() == 1);
			VERIFY(sc.timeout.has_value() == 1);
			VERIFY(sc.timeout.has_value() == 1);
			const auto &ts = *sc.timeout->spec();
			VERIFY(ts.tv_sec == 5);
			VERIFY(ts.tv_nsec == 500);
		}), EXIT_VERIFY_CB(FutexSystemCall, {
			/* contrary to what the man page says, CLOCK_REALTIME
			 * is _not_ supported (or not anymore) with
			 * FUTEX_WAIT. Thus is returns ENOSYS. */
			VERIFY(sc.hasErrorCode());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto fux = alloc_struct32<uint32_t>();
				auto ts = alloc_struct32<clues::timespec32>();
				ts->tv_sec = 5;
				ts->tv_nsec = 500;
				syscall32(SyscallNr32::FUTEX, fux, FUTEX_WAIT|FUTEX_CLOCK_REALTIME, 1, ts);
			})
		},
#ifdef CLUES_HAVE_LEGACY_GETDENTS
	}, TestSpec{SystemCallNr::GETDENTS, []() {
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			char buffer[65535];
			/* do it TWICE, but we need to seek back to the
			 * beginning of the directory here, thus it needs
			 * extra code */
			syscall(SYS_getdents, fd, buffer, sizeof(buffer));
			lseek(fd, 0, SEEK_SET);
			syscall(SYS_getdents, fd, buffer, sizeof(buffer));
		}, ENTRY_VERIFY_CB(GetDentsSystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum{FIRST_FD});
			VERIFY(sc.dirent.entries().size() == 0);
			VERIFY(sc.size.value() == 65535);
		}), EXIT_VERIFY_CB(GetDentsSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto bytes = sc.ret_bytes.value();
			VERIFY(bytes > 0 && bytes < 65535);
			const auto &entries = sc.dirent.entries();
			// a least ".", ".."
			VERIFY(entries.size() > 2);
			bool found_tmp = false;
			bool found_root = false;

			using enum cosmos::DirEntry::Type;

			for (const auto &entry: entries) {
				if (entry.name == "tmp") {
					found_tmp = true;
					VERIFY(entry.type == DIRECTORY);
				} else if (entry.name == "root") {
					found_root = true;
					VERIFY(entry.type == DIRECTORY);
				}
			}

			VERIFY(found_tmp && found_root);
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				char *buffer = alloc32<char*>(65535);
				syscall32(SyscallNr32::GETDENTS, fd, buffer, 65535);
			})
		}
#endif
	}, TestSpec{SystemCallNr::GETDENTS64, []() {
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			char buffer[65535];
			syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
		}, ENTRY_VERIFY_CB(GetDentsSystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum{FIRST_FD});
			VERIFY(sc.size.value() == 65535);
		}), EXIT_VERIFY_CB(GetDentsSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto bytes = sc.ret_bytes.valueAs<unsigned int>();
			VERIFY(bytes > 0 && bytes < 65535);
			const auto &entries = sc.dirent.entries();
			// a least ".", ".."
			VERIFY(entries.size() > 2);
			bool found_tmp = false;
			bool found_root = false;

			using enum cosmos::DirEntry::Type;

			for (const auto &entry: entries) {
				if (entry.name == "tmp") {
					found_tmp = true;
					VERIFY(entry.type == DIRECTORY);
				} else if (entry.name == "root") {
					found_root = true;
					VERIFY(entry.type == DIRECTORY);
				}
			}

			VERIFY(found_tmp && found_root);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				char *buffer = alloc32<char*>(65535);
				syscall32(SyscallNr32::GETDENTS64, fd, buffer, 65535);
			})
		}
	}, TestSpec{SystemCallNr::GETUID, []() {
			syscall(SYS_getuid);
		}, ENTRY_VERIFY_CB(GetUidSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetUidSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.uid() == cosmos::proc::get_real_user_id());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETUID);
			})
		},
	}, TestSpec{SystemCallNr::GETUID32, []() {
#ifdef COSMOS_I386
			syscall(SYS_getuid32);
#endif
		}, ENTRY_VERIFY_CB(GetUidSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetUidSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.uid() == cosmos::proc::get_real_user_id());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETUID32);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::GETEUID, []() {
			syscall(SYS_geteuid);
		}, ENTRY_VERIFY_CB(GetEuidSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetEuidSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.uid() == cosmos::proc::get_effective_user_id());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETEUID);
			})
		},
	}, TestSpec{SystemCallNr::GETEUID32, []() {
#ifdef COSMOS_I386
			syscall(SYS_geteuid32);
#endif
		}, ENTRY_VERIFY_CB(GetEuidSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetEuidSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.uid() == cosmos::proc::get_effective_user_id());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETEUID32);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::GETGID, []() {
			syscall(SYS_getgid);
		}, ENTRY_VERIFY_CB(GetGidSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetGidSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.gid() == cosmos::proc::get_real_group_id());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETGID);
			})
		},
	}, TestSpec{SystemCallNr::GETGID32, []() {
#ifdef COSMOS_I386
			syscall(SYS_getgid32);
#endif
		}, ENTRY_VERIFY_CB(GetGidSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetGidSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.gid() == cosmos::proc::get_real_group_id());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETGID32);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::GETEGID, []() {
			syscall(SYS_getegid);
		}, ENTRY_VERIFY_CB(GetEgidSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetEgidSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.gid() == cosmos::proc::get_effective_group_id());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETEGID);
			})
		},
	}, TestSpec{SystemCallNr::GETEGID32, []() {
#ifdef COSMOS_I386
			syscall(SYS_getegid32);
#endif
		}, ENTRY_VERIFY_CB(GetEgidSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetEgidSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.gid() == cosmos::proc::get_effective_group_id());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETEGID32);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::GETRLIMIT, []() {
			struct rlimit lim;
			syscall(SYS_getrlimit, RLIMIT_CORE, &lim);
		}, ENTRY_VERIFY_CB(GetRlimitSystemCall, {
			VERIFY(sc.type.type() == cosmos::LimitType::CORE);
			VERIFY(sc.limit.limit() == std::nullopt);
		}), EXIT_VERIFY_CB(GetRlimitSystemCall, {
			VERIFY(sc.limit.limit().has_value());
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto lim = alloc_struct32<clues::rlimit32>();
				syscall32(SyscallNr32::GETRLIMIT, RLIMIT_CORE, lim);
			})
		}
	}, TestSpec{SystemCallNr::SETRLIMIT, []() {
#ifdef COSMOS_I386
			clues::rlimit32 lim;
#else
			struct rlimit lim;
#endif
			lim.rlim_cur = 1000;
			lim.rlim_max = 10000;
			syscall(SYS_setrlimit, RLIMIT_CORE, &lim);
		}, ENTRY_VERIFY_CB(SetRlimitSystemCall, {
			VERIFY(sc.type.type() == cosmos::LimitType::CORE);
			VERIFY(sc.limit.limit().has_value());
			const auto limspec = *sc.limit.limit();
			VERIFY(limspec.getSoftLimit() == 1000);
			VERIFY(limspec.getHardLimit() == 10000);
		}), EXIT_VERIFY_CB(SetRlimitSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto lim = alloc_struct32<clues::rlimit32>();
				lim->rlim_cur = 1000;
				lim->rlim_max = 10000;
				syscall32(SyscallNr32::SETRLIMIT, RLIMIT_CORE, lim);
			})
		}
	}, TestSpec{SystemCallNr::PRLIMIT64, []() {
			struct rlimit old_lim;
			struct rlimit new_lim;
			new_lim.rlim_cur = 1000;
			new_lim.rlim_max = 10000;
			TWICE(prlimit(0, RLIMIT_CORE, &new_lim, &old_lim));
		}, ENTRY_VERIFY_CB(Prlimit64SystemCall, {
			VERIFY(sc.pid.pid() == cosmos::ProcessID::SELF);
			VERIFY(sc.type.type() == cosmos::LimitType::CORE);
			VERIFY(sc.limit.limit().has_value());
			const auto newlim = *sc.limit.limit();
			VERIFY(newlim.getSoftLimit() == 1000);
			VERIFY(newlim.getHardLimit() == 10000);
			VERIFY(sc.old_limit.limit() == std::nullopt);
		}), EXIT_VERIFY_CB(Prlimit64SystemCall, {
			VERIFY(sc.old_limit.limit().has_value());
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto lim = alloc_struct32<struct rlimit>();
				lim->rlim_cur = 1000;
				lim->rlim_max = 10000;
				auto old_lim = alloc_struct32<struct rlimit>();
				syscall32(SyscallNr32::PRLIMIT64, 0, RLIMIT_CORE, lim, old_lim);
			})
		}
	}, TestSpec{SystemCallNr::GET_ROBUST_LIST, []() {
			char buffer[65535];
			size_t sizep = sizeof(buffer);
			syscall(SYS_get_robust_list, 0, buffer, &sizep);
		}, ENTRY_VERIFY_CB(GetRobustListSystemCall, {
			VERIFY(sc.thread_id.tid() == cosmos::ThreadID::SELF);
			using TraceePtr = decltype(sc.list_head.pointer());
			VERIFY(sc.list_head.pointer() != TraceePtr::NO_POINTER);
			VERIFY(sc.size_ptr.value() == 65535);
		}), EXIT_VERIFY_CB(GetRobustListSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.size_ptr.value() != 65535);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto buffer = alloc32<char*>(65535);
				auto sizep = alloc_struct32<size_t>();
				*sizep = 65535;
				syscall32(SyscallNr32::GET_ROBUST_LIST, 0, buffer, sizep);
			})
		}
	}, TestSpec{SystemCallNr::SET_ROBUST_LIST, []() {
			char ch;
			syscall(SYS_set_robust_list, &ch, 0);
		}, ENTRY_VERIFY_CB(SetRobustListSystemCall, {
			VERIFY(sc.list_head.ptr() != ForeignPtr::NO_POINTER);
			VERIFY(sc.size.value() == 0);
		}), EXIT_VERIFY_CB(SetRobustListSystemCall, {
			/* since we're applying a zero-size buffer here it
			 * will fail with EINVAL */
			VERIFY(sc.hasErrorCode());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto ch = alloc32<char*>(8);
				syscall32(SyscallNr32::SET_ROBUST_LIST, ch, 0);
			})
		}
	}, TestSpec{SystemCallNr::IOCTL, []() {
			int fd = open("/", O_RDONLY|O_DIRECTORY);
			int attr;
			ioctl(fd, FS_IOC_GETFLAGS, &attr);
		}, ENTRY_VERIFY_CB(IoCtlSystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum{FIRST_FD});
			VERIFY(sc.request.value() == FS_IOC_GETFLAGS);
		}), EXIT_VERIFY_CB(IoCtlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/", O_RDONLY|O_DIRECTORY);
				auto attr = alloc32<int*>(sizeof(int));
				/* this has the highest bit set, avoid any
				 * surprises by explicitly forcing it into an
				 * int32_t */
				constexpr int32_t flags = FS_IOC_GETFLAGS;
				syscall32(SyscallNr32::IOCTL, fd, flags, attr);
			})
		}
#ifdef CLUES_HAVE_LSTAT
	}, TestSpec{SystemCallNr::LSTAT, []() {
			struct stat st;
			TWICE(syscall(SYS_lstat, "/", &st));
		}, ENTRY_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				/* struct will be too big, but that doesn't
				 * matter for testing */
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::LSTAT, path, st);
			})
		}
#endif
	}, TestSpec{SystemCallNr::LSTAT64, []() {
#ifdef COSMOS_I386
			struct stat st;
			TWICE(syscall(SYS_lstat64, "/", &st));
#endif
		}, ENTRY_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.path.data() == "/");
		}), EXIT_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::LSTAT64, path, st);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::OLDLSTAT, []() {
#ifdef COSMOS_I386
			/* the struct will be too big, bug that should be no
			 * matter as long as we don't touch it here */
			struct stat st;
			TWICE(syscall(SYS_oldlstat, "/", &st));
#endif
		}, ENTRY_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(LstatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::OLDLSTAT, path, st);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::STAT64, []() {
#ifdef COSMOS_I386
			struct stat st;
			TWICE(syscall(SYS_stat64, "/", &st));
#endif
		}, ENTRY_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::STAT64, path, st);
			})
		},
		"",
		{clues::ABI::I386}
#ifdef CLUES_HAVE_STAT
	}, TestSpec{SystemCallNr::STAT, []() {
			struct stat st;
			TWICE(syscall(SYS_stat, "/", &st));
		}, ENTRY_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::STAT, path, st);
			})
		}
#endif
	}, TestSpec{SystemCallNr::OLDSTAT, []() {
#ifdef COSMOS_I386
			struct stat st;
			TWICE(syscall(SYS_oldstat, "/", &st));
#endif
		}, ENTRY_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.path.data() == "/");
			VERIFY(sc.statbuf.status() == std::nullopt);
		}), EXIT_VERIFY_CB(StatSystemCall, {
			VERIFY(sc.hasResultValue());
			const auto &st = *sc.statbuf.status();
			VERIFY(st.uid() == cosmos::UserID::ROOT);
			VERIFY(st.gid() == cosmos::GroupID::ROOT);
			VERIFY(st.type().isDirectory());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto st = alloc_struct32<struct stat>();
				auto path = alloc_str32("/");
				syscall32(SyscallNr32::OLDSTAT, path, st);
			})
		},
		"",
		{clues::ABI::I386}
	},
	/*
	 * mmap() and mmap2() are especially problematic cases, because mmap()
	 * on i386 is completely different from mmap() on other ABIs, while
	 * mmap2() on i386 matches mmap() on other ABIs.
	 *
	 * This doesn't match our modeling very well. We need to create
	 * dedicated TestSpecs for all possible variants to avoid conflicts.
	 */
	TestSpec{SystemCallNr::MMAP, []() {
			/* pass offset explicitly as ULL literal constant,
			 * otherwise I've observed garbage left over in the
			 * upper 4 bytes of the argument in the clang static
			 * build config */
			syscall(SYS_mmap, nullptr, 1234,
					PROT_READ|PROT_WRITE,
					MAP_PRIVATE|MAP_ANONYMOUS, -1, 0ULL);
		}, ENTRY_VERIFY_CB(MmapSystemCall, {
			VERIFY(sc.hint.ptr() == ForeignPtr::NO_POINTER);
			VERIFY(sc.length.value() == 1234);
			using enum cosmos::mem::AccessFlag;
			using AccessFlags = cosmos::mem::AccessFlags;
			VERIFY(sc.protection.prot() == AccessFlags{READ, WRITE});
			VERIFY(sc.flags.type() == cosmos::mem::MapType::PRIVATE);
			using enum cosmos::mem::MapFlag;
			using MapFlags = cosmos::mem::MapFlags;
			VERIFY(sc.flags.flags() == MapFlags{ANONYMOUS});
			VERIFY(sc.fd.fd() == cosmos::FileNum::INVALID);
			VERIFY(sc.offset.valueAs<off_t>() == 0);
			VERIFY(!sc.isOldMmap());
		}), EXIT_VERIFY_CB(MmapSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
		},
		"",
		{clues::ABI::X86_64, clues::ABI::AARCH64}
	}, TestSpec{SystemCallNr::MMAP, []() {
#ifdef COSMOS_I386
			clues::mmap_arg_struct args;
			std::memset(&args, 0, sizeof(args));
			args.len = 1234;
			args.prot = PROT_READ|PROT_WRITE;
			args.flags = MAP_PRIVATE|MAP_ANONYMOUS;
			args.fd = -1;
			syscall(SYS_mmap, &args);
#endif
		}, ENTRY_VERIFY_CB(MmapSystemCall, {
			VERIFY(sc.isOldMmap());
			const auto &args = *sc.old_args;
			VERIFY(args.valid());
			VERIFY(args.addr() == clues::ForeignPtr::NO_POINTER);
			VERIFY(args.length() == 1234);
			VERIFY(args.offset() == 0);
			VERIFY(args.type() == cosmos::mem::MapType::PRIVATE);
			using enum cosmos::mem::MapFlag;
			using MapFlags = cosmos::mem::MapFlags;
			VERIFY(args.flags() == MapFlags{ANONYMOUS});
			using enum cosmos::mem::AccessFlag;
			using AccessFlags = cosmos::mem::AccessFlags;
			VERIFY(args.prot() == AccessFlags{READ, WRITE});
			VERIFY(args.fd() == cosmos::FileNum::INVALID);

			/*
			 * and now do the same more the non-legacy arguments
			 * which should be synced with the legacy data.
			 */
			VERIFY(sc.hint.ptr() == ForeignPtr::NO_POINTER);
			VERIFY(sc.length.value() == 1234);
			VERIFY(sc.protection.prot() == AccessFlags{READ, WRITE});
			VERIFY(sc.flags.type() == cosmos::mem::MapType::PRIVATE);
			VERIFY(sc.flags.flags() == MapFlags{ANONYMOUS});
			VERIFY(sc.fd.fd() == cosmos::FileNum::INVALID);
			VERIFY(sc.offset.valueAs<off_t>() == 0);
		}), EXIT_VERIFY_CB(MmapSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto args = alloc_struct32<clues::mmap_arg_struct>();
				std::memset(args, 0, sizeof(*args));
				args->len = 1234;
				args->prot = PROT_READ|PROT_WRITE;
				args->flags = MAP_PRIVATE|MAP_ANONYMOUS;
				args->fd = -1;
				syscall32(SyscallNr32::MMAP, args);
			})
		},
		"legacy",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::MMAP2, []() {
#ifdef COSMOS_I386
			syscall(SYS_mmap2, nullptr, 1234,
					PROT_READ|PROT_WRITE,
					MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#endif
		}, ENTRY_VERIFY_CB(MmapSystemCall, {
			VERIFY(!sc.isOldMmap());
			VERIFY(sc.hint.ptr() == ForeignPtr::NO_POINTER);
			VERIFY(sc.length.value() == 1234);
			using enum cosmos::mem::AccessFlag;
			using AccessFlags = cosmos::mem::AccessFlags;
			VERIFY(sc.protection.prot() == AccessFlags{READ, WRITE});
			VERIFY(sc.flags.type() == cosmos::mem::MapType::PRIVATE);
			using enum cosmos::mem::MapFlag;
			using MapFlags = cosmos::mem::MapFlags;
			VERIFY(sc.flags.flags() == MapFlags{ANONYMOUS});
			VERIFY(sc.fd.fd() == cosmos::FileNum::INVALID);
			VERIFY(sc.offset.valueAs<off_t>() == 0);
		}), EXIT_VERIFY_CB(MmapSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::MMAP2, nullptr,
					1234, PROT_READ|PROT_WRITE,
					MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::MPROTECT, []() {
			auto mem = mmap(nullptr, 1024, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			mprotect(mem, 1024, PROT_READ|PROT_WRITE);
		}, ENTRY_VERIFY_CB(MprotectSystemCall, {
			VERIFY(sc.addr.ptr() != ForeignPtr::NO_POINTER);
			VERIFY(sc.length.value() == 1024);
			using enum cosmos::mem::AccessFlag;
			using AccessFlags = cosmos::mem::AccessFlags;
			VERIFY(sc.protection.prot() == AccessFlags{READ, WRITE});
			VERIFY(sc.protection.prot() ==  AccessFlags{READ, WRITE});
		}), EXIT_VERIFY_CB(MprotectSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto mem = syscall32(SyscallNr32::MMAP2, nullptr,
					1024, PROT_READ,
					MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
				syscall32(SyscallNr32::MPROTECT, mem, 1024, PROT_READ|PROT_WRITE);
			})
		}
	}, TestSpec{SystemCallNr::MUNMAP, []() {
			auto mem = mmap(nullptr, 1024, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			munmap(mem, 1024);
		},  ENTRY_VERIFY_CB(MunmapSystemCall, {
			VERIFY(sc.addr.ptr() != ForeignPtr::NO_POINTER);
			VERIFY(sc.length.value() == 1024);
		}), EXIT_VERIFY_CB(MunmapSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto mem = syscall32(SyscallNr32::MMAP2, nullptr,
					1024, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
				syscall32(SyscallNr32::MUNMAP, mem, 1024);
			})
		}
	}, TestSpec{SystemCallNr::NANOSLEEP, []() {
			struct timespec ts;
			ts.tv_sec = 0;
			ts.tv_nsec = 500;
			syscall(SYS_nanosleep, &ts, &ts);
		}, ENTRY_VERIFY_CB(NanoSleepSystemCall, {
			VERIFY(sc.req_time.asPtr() == sc.rem_time.asPtr());
			const auto &ts = *sc.req_time.spec();
			VERIFY(ts.tv_sec == 0);
			VERIFY(ts.tv_nsec == 500);
		}), EXIT_VERIFY_CB(NanoSleepSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto ts32 = alloc_struct32<clues::timespec32>();
				ts32->tv_sec = 0;
				ts32->tv_nsec = 500;
				syscall32(SyscallNr32::NANOSLEEP, ts32, ts32);
			})
		}
#ifdef CLUES_HAVE_OPEN
	}, TestSpec{SystemCallNr::OPEN, []() {
			syscall(SYS_open, "/etc/fstab", O_RDONLY|O_CLOEXEC);
		}, ENTRY_VERIFY_CB(OpenSystemCall, {
			VERIFY(sc.filename.data() == "/etc/fstab");
			using enum cosmos::OpenMode;
			using enum cosmos::OpenFlag;
			using OpenFlags = cosmos::OpenFlags;
			VERIFY(sc.flags.flags() == OpenFlags{CLOEXEC});
			VERIFY(sc.flags.mode() == READ_ONLY);
			VERIFY(!sc.mode.has_value());
		}), EXIT_VERIFY_CB(OpenSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto path = alloc_str32("/etc/fstab");
				syscall32(SyscallNr32::OPEN, path, O_RDONLY|O_CLOEXEC);
			})
		}
	}, TestSpec{SystemCallNr::OPEN, []() {
			syscall(SYS_open, "/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
		}, ENTRY_VERIFY_CB(OpenSystemCall, {
			VERIFY(sc.filename.data() == "/tmp");
			using enum cosmos::OpenMode;
			using enum cosmos::OpenFlag;
			using OpenFlags = cosmos::OpenFlags;
			VERIFY(sc.flags.flags() == OpenFlags{CLOEXEC,TMPFILE});
			VERIFY(sc.flags.mode() == WRITE_ONLY);
			VERIFY(sc.mode.has_value());
			const auto &mode_par = *sc.mode;
			VERIFY(mode_par.mode() == cosmos::FileMode{cosmos::FileModeBit{0755}});
		}), EXIT_VERIFY_CB(OpenSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto path = alloc_str32("/tmp");
				syscall32(SyscallNr32::OPEN, path, O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
			})
		},
		"CREAT"
#endif
	}, TestSpec{SystemCallNr::OPENAT, []() {
			auto fd = open("/etc", O_RDONLY|O_DIRECTORY);
			syscall(SYS_openat, fd, "fstab", O_RDONLY|O_CLOEXEC);
		}, ENTRY_VERIFY_CB(OpenAtSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD)
			VERIFY(sc.filename.data() == "fstab");
			using enum cosmos::OpenMode;
			using enum cosmos::OpenFlag;
			using OpenFlags = cosmos::OpenFlags;
			VERIFY(sc.flags.flags() == OpenFlags{CLOEXEC});
			VERIFY(sc.flags.mode() == READ_ONLY);
			VERIFY(!sc.mode.has_value());
		}), EXIT_VERIFY_CB(OpenAtSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == SECOND_FD);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto dirpath = alloc_str32("/etc");
				auto filepath = alloc_str32("fstab");
				auto fd = open(dirpath, O_RDONLY|O_DIRECTORY);
				syscall32(SyscallNr32::OPENAT, fd, filepath, O_RDONLY|O_CLOEXEC);
			})
		},
	}, TestSpec{SystemCallNr::OPENAT, []() {
			auto fd = open("/tmp", O_RDONLY|O_DIRECTORY);
			syscall(SYS_openat, fd, ".", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
		}, ENTRY_VERIFY_CB(OpenAtSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD)
			VERIFY(sc.filename.data() == ".");
			using enum cosmos::OpenMode;
			using enum cosmos::OpenFlag;
			using OpenFlags = cosmos::OpenFlags;
			VERIFY(sc.flags.flags() == OpenFlags{CLOEXEC,TMPFILE});
			VERIFY(sc.flags.mode() == WRITE_ONLY);
			VERIFY(sc.mode.has_value());
			const auto &mode_par = *sc.mode;
			VERIFY(mode_par.mode() == cosmos::FileMode{cosmos::FileModeBit{0755}});
		}), EXIT_VERIFY_CB(OpenAtSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == SECOND_FD);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto dirpath = alloc_str32("/tmp");
				auto filepath = alloc_str32(".");
				auto fd = open(dirpath, O_RDONLY|O_DIRECTORY);
				syscall32(SyscallNr32::OPENAT, fd, filepath, O_WRONLY|O_CLOEXEC|O_TMPFILE, 0755);
			})
		},
		"CREAT"
	}, TestSpec{SystemCallNr::READ, []() {
			int fd = open("/etc/fstab", O_RDONLY);
			char buffer[1024];
			if (read(fd, buffer, sizeof(buffer)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.count.value() == 1024);
		}), EXIT_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.buf.availableBytes() > 0);
			VERIFY(sc.buf.data().size() <= sc.buf.availableBytes());
			VERIFY(sc.read.value() == sc.buf.availableBytes());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto path = alloc_str32("/etc/fstab");
				int fd = open(path, O_RDONLY);
				auto buffer = alloc32<char*>(1024);
				if (syscall32(SyscallNr32::READ, fd, buffer, 1024) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::WRITE, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
			const char buffer[] = "abcdefgh";
			if (write(fd, buffer, sizeof(buffer)) < 0) {

			}
		}, ENTRY_VERIFY_CB(WriteSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.buf.data().size() == 9);
			std::string s;
			for (const auto byte: sc.buf.data()) {
				if (byte)
					s.push_back(byte);
			}
			VERIFY(s == "abcdefgh");
			VERIFY(sc.count.value() == 9);
			VERIFY(sc.buf.availableBytes() == 9);
		}), EXIT_VERIFY_CB(WriteSystemCall, {
			VERIFY(sc.hasResultValue());
			// partial writes should not occur here
			VERIFY(sc.written.value() == 9);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0755);
				auto buffer = alloc_str32("abcdefgh");
				syscall32(SyscallNr32::WRITE, fd, buffer, strlen(buffer) + 1);
			})
		}
	}, TestSpec{SystemCallNr::RT_SIGACTION, []() {
			using sig_handler_t = void(*)(int);
			struct sigaction act, oldact;
			memset(&act, 0, sizeof(act));
			act.sa_handler = (sig_handler_t)0x1234;
			sigaddset(&act.sa_mask, SIGCHLD);
			act.sa_flags = SA_RESTART|SA_RESETHAND;
			TWICE(::sigaction(SIGUSR1, &act, &oldact));
		}, ENTRY_VERIFY_CB(RtSigActionSystemCall, {
			VERIFY(sc.signum.nr() == cosmos::signal::USR1.raw());
			const auto &action = *sc.action.action();
			VERIFY(action.raw()->sa_handler == (void*)0x1234);
			using enum cosmos::SigAction::Flag;
			using Flags = cosmos::SigAction::Flags;
			const auto flags = Flags{{RESTART, RESET_HANDLER}};
			/* libc adds SA_RESTORER implicitly, so be prepared
			 * for that */
			VERIFY(action.getFlags() == flags || action.getFlags() == flags + Flags{RESTORER});
			VERIFY(action.mask().isSet(cosmos::signal::CHILD));
			VERIFY(sc.old_action.action() == std::nullopt);
			VERIFY(sc.sigset_size.value() == 8);
		}), EXIT_VERIFY_CB(RtSigActionSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.old_action.action().has_value());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto act = alloc_struct32<clues::kernel_sigaction32>();
				auto oldact = alloc_struct32<clues::kernel_sigaction32>();
				memset(act, 0, sizeof(*act));
				act->handler = (uint32_t)(0x1234);
				sigset_t ss;
				sigaddset(&ss, SIGCHLD);
				memcpy(&act->mask, &ss, sizeof(act->mask));
				act->flags = SA_RESTART|SA_RESETHAND;
				syscall32(SyscallNr32::RT_SIGACTION, SIGUSR1, act, oldact, 8);
			})
		}
	}, TestSpec{SystemCallNr::SIGACTION, []() {
#ifdef COSMOS_I386
			clues::kernel_old_sigaction act, oldact;
			cosmos::zero_object(act);
			act.handler = 0x1234;
			act.mask |= 1 << (SIGCHLD - 1);
			act.flags = SA_RESTART|SA_RESETHAND;
			TWICE(::syscall(SYS_sigaction, SIGUSR1, &act, &oldact));
#endif
		}, ENTRY_VERIFY_CB(SigActionSystemCall, {
			VERIFY(sc.signum.nr() == cosmos::signal::USR1.raw());
			const auto &action = *sc.action.action();
			VERIFY(action.raw()->sa_handler == (void*)0x1234);
			using enum cosmos::SigAction::Flag;
			using Flags = cosmos::SigAction::Flags;
			const auto flags = Flags{{RESTART, RESET_HANDLER}};
			/* libc adds SA_RESTORER implicitly, so be prepared
			 * for that */
			VERIFY(action.getFlags() == flags || action.getFlags() == flags + Flags{RESTORER});
			VERIFY(action.mask().isSet(cosmos::signal::CHILD));
			VERIFY(sc.old_action.action() == std::nullopt);
		}), EXIT_VERIFY_CB(SigActionSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.old_action.action().has_value());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto act = alloc_struct32<clues::kernel_old_sigaction>();
				auto oldact = alloc_struct32<clues::kernel_old_sigaction>();
				memset(act, 0, sizeof(*act));
				act->handler = (uint32_t)(0x1234);
				act->mask |= 1 << (SIGCHLD - 1);
				act->flags = SA_RESTART|SA_RESETHAND;
				syscall32(SyscallNr32::SIGACTION, SIGUSR1, act, oldact);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::RT_SIGPROCMASK, []() {
			sigset_t set, old;
			sigemptyset(&set);
			sigaddset(&set, SIGUSR1);
			sigfillset(&old);
			sigprocmask(SIG_BLOCK, &set, &old);
		}, ENTRY_VERIFY_CB(RtSigProcMaskSystemCall, {
			VERIFY(sc.operation.op() == clues::item::SigSetOperation::Op::BLOCK);
			const auto new_set = *sc.new_mask.sigset();

			VERIFY(new_set.isSet(cosmos::signal::USR1));
			VERIFY(sc.old_mask.sigset() == std::nullopt);
			VERIFY(sc.sigset_size.value() == 8);
		}), EXIT_VERIFY_CB(RtSigProcMaskSystemCall, {
			const auto old_set = *sc.old_mask.sigset();
			VERIFY(!old_set.isSet(cosmos::signal::USR1));
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto set = alloc_struct32<sigset_t>();
				auto old = alloc_struct32<sigset_t>();
				sigemptyset(set);
				sigemptyset(old);
				sigaddset(set, SIGUSR1);
				syscall32(SyscallNr32::RT_SIGPROCMASK, SIG_BLOCK, set, old, 8);
			})
		}
	}, TestSpec{SystemCallNr::SIGPROCMASK, []() {
#ifdef COSMOS_I386
			uint32_t set = 0, old;
			set |= 1 << (SIGUSR1 - 1);
			syscall(SYS_sigprocmask, SIG_BLOCK, &set, &old);
#endif
		}, ENTRY_VERIFY_CB(SigProcMaskSystemCall, {
			VERIFY(sc.operation.op() == clues::item::SigSetOperation::Op::BLOCK);
			const auto new_set = *sc.new_mask.sigset();

			VERIFY(new_set.isSet(cosmos::signal::USR1));
		}), EXIT_VERIFY_CB(SigProcMaskSystemCall, {
			const auto old_set = *sc.old_mask.sigset();
			VERIFY(!old_set.isSet(cosmos::signal::USR1));
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto set = alloc_struct32<uint32_t>();
				auto old = alloc_struct32<uint32_t>();
				*set = 0;
				*set |= 1 << (SIGUSR1 - 1);
				syscall32(SyscallNr32::SIGPROCMASK, SIG_BLOCK, set, old);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::SET_TID_ADDRESS, []() {
			int tptr;
			syscall(SYS_set_tid_address, &tptr);
		}, ENTRY_VERIFY_CB(SetTIDAddressSystemCall, {
			VERIFY(sc.address.ptr() != ForeignPtr::NO_POINTER);
		}), EXIT_VERIFY_CB(SetTIDAddressSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.caller_tid.tid() != cosmos::ThreadID::INVALID);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto tptr = alloc_struct32<int>();
				syscall32(SyscallNr32::SET_TID_ADDRESS, tptr);
			})
		}
	}, TestSpec{SystemCallNr::TGKILL, []() {
			::tgkill(getpid(), gettid(), 0);
		}, ENTRY_VERIFY_CB(TgKillSystemCall, {
			VERIFY(sc.thread_group.pid() == tracee.pid());
			VERIFY(cosmos::as_pid(sc.thread_id.tid()) == tracee.pid());
			VERIFY(sc.signum.nr() == cosmos::SignalNr::NONE);
		}), EXIT_VERIFY_CB(TgKillSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				syscall32(SyscallNr32::TGKILL, getpid(), gettid(), 0);
			})
		}
	}, TestSpec{SystemCallNr::WAIT4, []() {
			/* don't use SYS_fork here which is not available on
			 * all ABIs.
			 * libc's fork() issues multiple system calls,
			 * however, difficult to keep track of.
			 * */
			if (const auto pid = syscall(SYS_fork); pid == 0) {
				::_exit(10);
			} else {
				int status;
				struct rusage ru;
				::syscall(SYS_wait4, pid, &status, WCONTINUED, &ru);
			}
		}, ENTRY_VERIFY_CB(Wait4SystemCall, {
			VERIFY(cosmos::to_integral(sc.pid.pid()) > 0);
			using enum cosmos::WaitFlag;
			const auto options = sc.options.options();
			VERIFY(options[WAIT_FOR_CONTINUED]);
		}), EXIT_VERIFY_CB(Wait4SystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(cosmos::to_integral(sc.event_pid.pid()) > 0);
			VERIFY(sc.pid.pid() == sc.event_pid.pid());
			const auto status = sc.wstatus.status();
			VERIFY(status != std::nullopt);
			VERIFY(status->exited() && status->status() == cosmos::ExitStatus{10});
			VERIFY(sc.rusage.usage() != std::nullopt);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				if (const auto pid = ::syscall(SYS_fork); pid == 0) {
					::_exit(10);
				} else {
					auto status = alloc_struct32<int>();
					auto ru = alloc_struct32<struct rusage>();
					syscall32(SyscallNr32::WAIT4, pid, status, WCONTINUED, ru);
				}
			})
		}
#ifdef CLUES_HAVE_PIPE1
	}, TestSpec{SystemCallNr::PIPE, []() {
			int pipes[2];
			TWICE({
				syscall(SYS_pipe, pipes);
				close(pipes[0]);
				close(pipes[1]);
			});
		}, ENTRY_VERIFY_CB(PipeSystemCall, {
			VERIFY(sc.ends.readEnd() == cosmos::FileNum::INVALID);
			VERIFY(sc.ends.writeEnd() == cosmos::FileNum::INVALID);
		}), EXIT_VERIFY_CB(PipeSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.ends.readEnd() == FIRST_FD);
			VERIFY(sc.ends.writeEnd() == SECOND_FD);
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				TWICE({
					syscall32(SyscallNr32::PIPE, pipes);
					close(pipes[0]);
					close(pipes[1]);
				});
			})
		}
#endif
	}, TestSpec{SystemCallNr::PIPE2, []() {
			int pipes[2];
			TWICE({
				if (pipe2(pipes, O_CLOEXEC|O_NONBLOCK) < 0) {
					_exit(1);
				}
				close(pipes[0]);
				close(pipes[1]);
			});
		}, ENTRY_VERIFY_CB(Pipe2SystemCall, {
			VERIFY(sc.ends.readEnd() == cosmos::FileNum::INVALID);
			VERIFY(sc.ends.writeEnd() == cosmos::FileNum::INVALID);
			const auto flags = sc.flags.flags();
			using enum clues::item::PipeFlags::Flag;
			VERIFY(flags == clues::item::PipeFlags::Flags{CLOEXEC, NONBLOCK});
		}), EXIT_VERIFY_CB(Pipe2SystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.ends.readEnd() == FIRST_FD);
			VERIFY(sc.ends.writeEnd() == SECOND_FD);
		}), IgnoreCalls{3}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				TWICE({
					syscall32(SyscallNr32::PIPE2, pipes, O_CLOEXEC|O_NONBLOCK);
					close(pipes[0]);
					close(pipes[1]);
				});
			})
		}
	},
#ifdef COSMOS_X86
	TestSpec{SystemCallNr::ARCH_PRCTL, []() {
			// disable SET_CPUID instruction
			syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
		}, ENTRY_VERIFY_CB(ArchPrctlSystemCall, {
			VERIFY(sc.op.operation() == clues::item::ArchOpParameter::Operation::SET_CPUID);
			VERIFY_FALSE(sc.set_addr || sc.get_addr || sc.on_off_ret);
			VERIFY(sc.on_off->value() == 0);
		}), EXIT_VERIFY_CB(ArchPrctlSystemCall, {
			/* either success or ENODEV is to be expected for this
			 * test */
			VERIFY(!sc.hasErrorCode() || *sc.error()->errorCode() == cosmos::Errno::NO_DEVICE);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::ARCH_PRCTL, ARCH_SET_CPUID, 0);
			})
		}
	},
#endif
};

} // end anon ns

void SyscallTest::runTests() {
	exiter = findHelper("exiter");

	if (m_argv.size() == 2) {
		m_syscall_filter = m_argv[1];
	}

	for (const auto &spec: TESTS) {
		if (spec.isSupportedABI()) {
			runTrace(spec.nr, spec.invoker,
					spec.enter_verify,
					spec.exit_verify,
					spec.ignore_calls,
					clues::ABI::UNKNOWN,
					spec.variant);
		}

		/*
		 * extra ABIs can also be supported if the system call is not
		 * otherwise not natively supported on this ABI, e.g.
		 * fcntl64() is used in 32-bit emulation for I386 only, when
		 * running a x86_64 tracer.
		 */
		for (const auto &extra_abi: spec.extra_abi_tests) {
			runTrace(spec.nr, extra_abi.invoker,
				spec.enter_verify,
				spec.exit_verify,
				extra_abi.ignore_calls,
				extra_abi.abi,
				spec.variant);
		}
	}
}

void SyscallTest::runTrace(
		const SystemCallNr nr,
		SyscallInvoker invoker,
		TraceVerifyCB enter_verify,
		TraceVerifyCB exit_verify,
		const IgnoreCalls ignore_calls,
		const clues::ABI abi,
		const std::string_view variant) {
	const auto name = clues::SYSTEM_CALL_NAMES[cosmos::to_integral(nr)];

	if (!m_syscall_filter.empty()) {
		if (m_syscall_filter != name) {
			return;
		}
	}

	std::vector<std::string_view> extra_labels;
	if (abi != clues::ABI::UNKNOWN) {
		extra_labels.push_back(clues::get_abi_label(abi));
	}
	if (!variant.empty()) {
		extra_labels.push_back(variant);
	}

	std::string extra_label;

	if (!extra_labels.empty()) {
		extra_label += " [";
		std::string comma;
		for (const auto label: extra_labels) {
			if (!comma.empty()) {
				extra_label += comma;
			} else {
				comma = ", ";
			}
			extra_label += label;
		}
		extra_label += "]";
	}

	START_TEST(cosmos::sprintf("testing system call %s%s",
				&name[0],
				extra_label.c_str()
	));
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

int main(const int argc, const char **argv) {
	SyscallTest test;
	return test.run(argc, argv);
}
