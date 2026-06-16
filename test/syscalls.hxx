// C++
#include <cstdlib>
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
#include <clues/private/kernel/iovec.hxx>
#include <clues/private/kernel/mmap.hxx>
#include <clues/private/kernel/other.hxx>
#include <clues/private/kernel/sigaction.hxx>
#include <clues/private/kernel/time.hxx>
#include <clues/syscalls/all.hxx>
#include <clues/Tracee.hxx>
#include <clues/utils.hxx>

// Test
#include "TestBase.hxx"
#include "TraceeCreator.hxx"

using namespace std::string_literals;

/*
 * This is a template for collective unit tests for individual single system
 * calls.
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
constexpr off_t LARGE_OFFSET64 = (1ULL << 32) + 2;

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
		(void)_; \
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

const char* alloc_str32(const char *s) {
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

using SyscallNr32 = clues::SystemCallNrI386;

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

template <typename TEST_ARRAY>
class SyscallTest :
	public cosmos::TestBase {
public:
	explicit SyscallTest(const TEST_ARRAY &tests) :
		m_tests{tests} {
	}

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
	const TEST_ARRAY &m_tests;
};

/// path to the exiter helper
std::string exiter;

template <typename TEST_ARRAY>
void SyscallTest<TEST_ARRAY>::runTests() {
	exiter = findHelper("exiter");

	if (m_argv.size() == 2) {
		m_syscall_filter = m_argv[1];
	}

	for (const auto &spec: m_tests) {
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

template <typename TEST_ARRAY>
void SyscallTest<TEST_ARRAY>::runTrace(
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
