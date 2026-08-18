// test
#include "utils/syscalls.hxx"

// Linux
#include <sys/utsname.h>

namespace {

/* common verify function for the three uname system calls */
void check_uname(const cosmos::Uname &uts, bool &good) {
	VERIFY(uts.sysName() == "Linux");
	VERIFY(!uts.nodeName().empty());
	VERIFY(!uts.release().empty());
	VERIFY(!uts.version().empty());
	VERIFY(!uts.machine().empty());
	/* domainname can be empty */
}

const auto TESTS = std::array{
	TestSpec{SystemCallNr::GETRANDOM, []() {
			uint8_t buf[16];
			syscall(SYS_getrandom, buf, 16, GRND_NONBLOCK);
		}, ENTRY_VERIFY_CB(GetRandomSystemCall, {
			VERIFY(sc.count.value() == 16);
			VERIFY(sc.flags.flags() == cosmos::GetRandomFlags{cosmos::GetRandomFlag::NONBLOCK});
		}), EXIT_VERIFY_CB(GetRandomSystemCall, {
			/* we need to consider the situation that the kernel
			 * couldn't provide all data or any at all. */
			if (sc.hasResultValue()) {
				VERIFY(sc.obtained.value() > 0 && sc.obtained.value() <= 16);
			} else {
				VERIFY(sc.error()->errorCode() == cosmos::Errno::AGAIN);
			}
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				const auto *buffer = alloc32<uint8_t*>(16);
				syscall32(SyscallNr32::GETRANDOM, buffer, 16, GRND_NONBLOCK);
			})
		}
	}, TestSpec{SystemCallNr::UNAME, []() {
			struct utsname uts;
			uname(&uts);
		}, ENTRY_VERIFY_CB(UnameSystemCall, {
			// only output parameters
			(void)sc;
		}), EXIT_VERIFY_CB(UnameSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.utsname.uname());
			check_uname(*sc.utsname.uname(), good);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto uts = alloc_struct32<struct utsname>();
				syscall32(SyscallNr32::UNAME, uts);
			})
		}
	}, TestSpec{SystemCallNr::OLDUNAME, []() {
#ifdef COSMOS_I386
			/* use the current utsname struct, it is big enough */
			struct utsname uts;
			syscall(SYS_olduname, &uts);
#endif
		}, ENTRY_VERIFY_CB(UnameSystemCall, {
			// only output parameters
			(void)sc;
		}), EXIT_VERIFY_CB(UnameSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.utsname.uname());
			check_uname(*sc.utsname.uname(), good);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				/* use the current utsname struct, it is big enough */
				auto uts = alloc_struct32<struct utsname>();
				syscall32(SyscallNr32::OLDUNAME, uts);
			})
		},
		"",
		{clues::ABI::I386}
	}, TestSpec{SystemCallNr::OLDOLDUNAME, []() {
#ifdef COSMOS_I386
			/* use the current utsname struct, it is big enough */
			struct utsname uts;
			syscall(SYS_oldolduname, &uts);
#endif
		}, ENTRY_VERIFY_CB(UnameSystemCall, {
			// only output parameters
			(void)sc;
		}), EXIT_VERIFY_CB(UnameSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.utsname.uname());
			check_uname(*sc.utsname.uname(), good);
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				/* use the current utsname struct, it is big enough */
				auto uts = alloc_struct32<struct utsname>();
				syscall32(SyscallNr32::OLDOLDUNAME, uts);
			})
		},
		"",
		{clues::ABI::I386}
	},
};

} // end ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
