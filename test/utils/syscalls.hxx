// C++
#include <charconv>
#include <cstdlib>
#include <iostream>
#include <map>
#include <type_traits>
#include <vector>

// cosmos
#include <cosmos/compiler.hxx>
#include <cosmos/fs/filesystem.hxx>
#include <cosmos/fs/types.hxx>
#include <cosmos/memory.hxx>
#include <cosmos/proc/process.hxx>
#include <cosmos/string.hxx>

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
#include "syscall32.hxx"

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
using TraceVerifyCB = std::function<void (Tracee &, const SystemCall &, bool &good)>;
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

/// An entry read from /proc/<pid>/maps
struct TraceeMemoryRange {
	uintptr_t start = 0;
	uintptr_t end = 0;
	std::string access;
	off_t offset = 0;
	cosmos::DeviceID dev{0};
	cosmos::Inode inode{0};
	std::string path;

	bool matches(const clues::ForeignPtr ptr) const {
		const auto raw_ptr = cosmos::to_integral(ptr);
		return raw_ptr >= start && raw_ptr < end;
	}
};

struct MemoryRangeVector :
		public std::vector<TraceeMemoryRange> {
	bool isStackPointer(const clues::ForeignPtr ptr) const {
		return containedInObjects(ptr, {"[stack]"});
	}

	bool isHeapPointer(const clues::ForeignPtr ptr) const {
		return containedInObjects(ptr, {"[heap]"});
	}

	bool isVariablePointer(const clues::ForeignPtr ptr) const {
		return containedInObjects(ptr, {
				"[heap]",
				"[stack]",
#ifdef __SANITIZE_ADDRESS__
				/* when running with address sanitizer then
				 * the memory is arranged differently in a lot
				 * of anonymous memory mappings, so be more
				 * forgiving in this context */
				"",
#endif
		});
	}

	bool containedInObjects(const clues::ForeignPtr ptr,
			const std::initializer_list<std::string_view> paths) const {
		auto matches_paths = [paths](const std::string &path) -> bool {
			for (const auto cand: paths) {
				if (path == cand)
					return true;
			}

			return false;
		};

		for (const auto &range: *this) {
			if (!matches_paths(range.path))
				continue;

			if (range.matches(ptr))
				return true;
		}

		return false;
	}

	bool containedAnywhere(const clues::ForeignPtr ptr) const {
		for (const auto &range: *this) {
			if (range.matches(ptr))
				return true;
		}

		return false;
	}
};

MemoryRangeVector parse_memory_map(const Tracee &proc);

/*
 * the first file descriptor number which will be used in tracee context.
 * used for comparison of file descriptor values observed.
 */
constexpr cosmos::FileNum FIRST_FD{4};
constexpr cosmos::FileNum SECOND_FD{5};
constexpr uintptr_t STACK_ADDR = sizeof(void*) == 8 ? 0x700000000000 : 0x70000000;
constexpr off_t LARGE_OFFSET64 = (1ULL << 32) + 2;
/*
 * global test state which can be used to carry over information from one test
 * case to another.
 */
static std::map<std::string, bool> test_ctx_flags;
/*
 * this is updated for each tracee child process to contain its memory areas
 * from /proc/<pid>/maps.
 * it can be used to verify pointers observed during tracing are coming from
 * legit memory areas.
 */
static MemoryRangeVector tracee_mem_ranges;
/*
 * this contains specially mapped 32-bit memory areas for 32-bit cross ABI
 * emulation tracing. These are updating during tracing runtime as soon as
 * mmap() calls with MAP_32BIT are observed during ignored system call
 * sequences. See SyscallTracer::check32BitMemMap().
 */
static MemoryRangeVector tracee_32bit_ranges;

static bool is_valid_variable_ptr(const clues::SystemCall &sc, const clues::ForeignPtr ptr) {
	if (tracee_mem_ranges.isVariablePointer(ptr))
		return true;

	if (sc.is32BitEmulationABI()) {
		return tracee_32bit_ranges.containedAnywhere(ptr);
	}

	return false;
}

#define VERIFY(...) if (!(__VA_ARGS__)) { \
	std::cerr << "check |" << #__VA_ARGS__ << "| failed\n"; \
	good = false; \
	return; \
}

#define VERIFY_FALSE(expr) VERIFY(!(expr))

#define ENTRY_VERIFY_CB(SYSTEM_CALL_TYPE, ...) [](Tracee &tracee, const SystemCall &_sc, bool &good) { \
	(void)tracee; \
	good = true; \
	try { \
		const auto &sc = downcast<clues::SYSTEM_CALL_TYPE>(_sc); \
		__VA_ARGS__ \
	} catch (...) { \
		good = false; \
		throw; \
	} \
}

#define ENTRY_VERIFY_CB_CAPTURE(CAPTURE, SYSTEM_CALL_TYPE, ...) [CAPTURE](Tracee &tracee, const SystemCall &_sc, bool &good) { \
	(void)tracee; \
	good = true; \
	try { \
		const auto &sc = downcast<clues::SYSTEM_CALL_TYPE>(_sc); \
		__VA_ARGS__ \
	} catch (...) { \
		good = false; \
		throw; \
	} \
}

#define EXIT_VERIFY_CB(SYSTEM_CALL_TYPE, ...) [](Tracee &tracee, const SystemCall &_sc, bool &good) { \
	(void)tracee; \
	good = true; \
	try { \
		const auto &sc = downcast<clues::SYSTEM_CALL_TYPE>(_sc); \
		__VA_ARGS__ \
	} catch (...) { \
		good = false; \
		throw; \
	} \
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
			check32BitMemMap(call);
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

	void attached(clues::Tracee &proc) override {
		tracee_mem_ranges = parse_memory_map(proc);
		tracee_32bit_ranges.clear();
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

	void check32BitMemMap(const SystemCall &call) {
#ifdef COSMOS_X86
		/*
		 * for 32-bit cross ABI emulation tracing we place
		 * memory into a specially mmap'ed 32-bit memory area.
		 * this happens during the ignored system call phase.
		 *
		 * check for this situation to extract the memory
		 * range returned by the kernel to use it for pointer
		 * verification in tests.
		 */
		if (call.callNr() != SystemCallNr::MMAP)
			return;
		const auto &mmap_call = dynamic_cast<const clues::MmapSystemCall&>(call);
		const auto flags = mmap_call.flags.flags();
		using enum cosmos::mem::MapFlag;
		if (!flags.allOf({INTO_32BIT, ANONYMOUS}) ||
				mmap_call.flags.type() != cosmos::mem::MapType::PRIVATE)
			return;
		if (mmap_call.offset.value() != 0)
			return;
		if (mmap_call.fd.fd() != cosmos::FileNum::INVALID)
			return;

		/*
		 * synthesize a TraceeMemoryRange from this
		 */
		TraceeMemoryRange range;
		range.start = cosmos::to_integral(mmap_call.addr.ptr());
		range.end = range.start + mmap_call.length.value();
		range.access = "rw-p";
		tracee_32bit_ranges.emplace_back(range);
#else
		(void)call;
#endif
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

MemoryRangeVector parse_memory_map(const Tracee &proc) {

	MemoryRangeVector ret;

	auto from_hex = [](const std::string &s, auto &val) {
		std::from_chars(s.data(), s.data() + s.size(), val, 16);
	};

	auto parser = [from_hex, &ret](const std::string &line) -> bool {
		TraceeMemoryRange range;
		const auto parts = cosmos::split(line, " ");
		/* <memory-range> <access-bits> <offset> <dev-major>:<dev-minor> <inocde> [<path>] */
		if (parts.size() < 5 || parts.size() > 6)
			return false;

		const auto addrs = cosmos::split(parts[0], "-");

		if (addrs.size() != 2)
			return false;

		from_hex(addrs[0], range.start);
		from_hex(addrs[1], range.end);
		range.access = parts[1];
		from_hex(parts[2], range.offset);

		/* maj:min dev id */

		const auto devids = cosmos::split(parts[3], ":");
		if (devids.size() != 2)
			return false;

		unsigned int min, maj;

		from_hex(devids[0], maj);
		from_hex(devids[1], min);

		range.dev = cosmos::fs::make_device(cosmos::DeviceMajor{maj}, cosmos::DeviceMinor{min});

		ino_t inode;

		/* inode */
		from_hex(parts[4], inode);

		range.inode = cosmos::Inode{inode};

		if (parts.size() == 6) {
			range.path = parts[5];
		}

		ret.emplace_back(range);

		return false;
	};

	clues::parse_proc_file(proc, "maps", parser);
	return ret;
}

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
	// suppress unused function warning
	(void)is_valid_variable_ptr;

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
