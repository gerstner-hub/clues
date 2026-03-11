// Linux
#include <sys/syscall.h>
#include <asm/prctl.h>

// C++
#include <iostream>

// cosmos
#include <cosmos/compiler.hxx>

// clues
#include <clues/syscalls/fs.hxx>
#include <clues/syscalls/memory.hxx>
#include <clues/syscalls/process.hxx>
#include <clues/syscalls/signals.hxx>
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
using TraceVerifyCB = std::function<bool (const SystemCall &)>;
using SyscallInvoker = std::function<void (void)>;
using clues::SystemCallNr;
/*
 * the first file descriptor number which will be used in tracee context.
 * used for comparison of file descriptor values observed.
 */
constexpr cosmos::FileNum FIRST_FD{4};

#define VERIFY(expr) if (!(expr)) { \
	std::cerr << "check |" << #expr << "| failed\n"; \
	return false; \
}

#define VERIFY_FALSE(expr) VERIFY(!(expr))

#define VERIFY_RETURN(expr) VERIFY(expr); return true;

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

		m_entry_good = m_enter_verify(call);
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

		m_exit_good = m_exit_verify(call);
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
		[](const SystemCall &sc) {
			auto &access_sc = downcast<clues::AccessSystemCall>(sc);
			VERIFY(access_sc.path.data() == "/etc/");
			using cosmos::fs::AccessCheck;
			using cosmos::fs::AccessChecks;
			const AccessChecks checks{AccessCheck::READ_OK, AccessCheck::EXEC_OK};
			VERIFY((*access_sc.mode.checks()) == checks);
			return true;
		}, [](const SystemCall &sc) {
			VERIFY_RETURN(!sc.hasErrorCode());
		});

	/* shared entry check for faccessat1/2 */
	auto check_faccessat_entry = [](const auto &access_sc) -> bool {
		VERIFY(access_sc.dirfd.fd() == FIRST_FD);
		VERIFY(access_sc.path.data() == "etc");

		using cosmos::fs::AccessCheck;
		using cosmos::fs::AccessChecks;
		const AccessChecks checks{AccessCheck::READ_OK, AccessCheck::EXEC_OK};
		VERIFY((*access_sc.mode.checks()) == checks);

		return true;
	};

	runTrace(SystemCallNr::FACCESSAT,
		[]() {
			auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_faccessat, dirfd, "etc", R_OK|X_OK);
		},
		[check_faccessat_entry](const SystemCall &sc) {
			auto &access_sc = downcast<clues::FAccessAtSystemCall>(sc);
			return check_faccessat_entry(access_sc);
		}, [](const SystemCall &sc) {
			VERIFY_RETURN(!sc.hasErrorCode());
		},
		1);

	runTrace(SystemCallNr::FACCESSAT2,
		[]() {
			auto dirfd = open("/", O_RDONLY|O_DIRECTORY);
			syscall(SYS_faccessat2, dirfd, "etc", R_OK|X_OK, AT_EACCESS);
		},
		[check_faccessat_entry](const SystemCall &sc) {
			auto &access_sc = downcast<clues::FAccessAt2SystemCall>(sc);
			if (!check_faccessat_entry(access_sc))
				return false;
			using AtFlags = clues::item::AtFlagsValue::AtFlags;
			using enum clues::item::AtFlagsValue::AtFlag;
			VERIFY(access_sc.flags.flags() == AtFlags{EACCESS})

			return true;
		}, [](const SystemCall &sc) {
			VERIFY_RETURN(!sc.hasErrorCode());
		},
		1);

	runTrace(SystemCallNr::ALARM,
		[]() {
			/* make two calls so that we get a non-zero return
			 * value */
			alarm(1234);
			alarm(4321);
		},
		[](const SystemCall &sc) {
			auto &alarm_call = downcast<clues::AlarmSystemCall>(sc);
			VERIFY_RETURN(alarm_call.seconds.value() == 4321);
		},
		[](const SystemCall &sc) {
			auto &alarm_call = downcast<clues::AlarmSystemCall>(sc);
			VERIFY_RETURN(alarm_call.old_seconds.value() == 1234);
		},
		1);

#ifdef COSMOS_X86
	runTrace(SystemCallNr::ARCH_PRCTL,
		[]() {
			// disable SET_CPUID instruction
			syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
		},
		[](const SystemCall &sc) {
			auto &prctl_call = downcast<clues::ArchPrctlSystemCall>(sc);
			VERIFY(prctl_call.op.operation() == clues::item::ArchOpParameter::Operation::SET_CPUID);
			VERIFY_FALSE(prctl_call.set_addr || prctl_call.get_addr || prctl_call.on_off_ret);
			VERIFY_RETURN(prctl_call.on_off->value() == 0);
		},
		[](const SystemCall &sc) {
			/* either success or ENODEV is to be expected for this
			 * test */
			VERIFY_RETURN(!sc.hasErrorCode() || *sc.error()->errorCode() == cosmos::Errno::NO_DEVICE);
		});
#endif

	runTrace(SystemCallNr::BREAK,
		[]() {
			syscall(SYS_brk, 0x4711);
		},
		[](const SystemCall &sc) {
			auto &break_call = downcast<clues::BreakSystemCall>(sc);
			VERIFY_RETURN(break_call.req_addr.ptr() == (void*)0x4711);
		},
		[](const SystemCall &sc) {
			auto &break_call = downcast<clues::BreakSystemCall>(sc);
			VERIFY(!sc.hasErrorCode());
			VERIFY_RETURN(break_call.ret_addr.ptr() != nullptr);
		});
}

int main(const int argc, const char **argv) {
	SyscallTest test;
	return test.run(argc, argv);
}
