// test
#include "syscalls.hxx"

#ifdef CLUES_HAVE_ARCH_PRCTL
#include <asm/prctl.h>
#endif

namespace {

const auto TESTS = std::array{
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
	TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_DUMPABLE, 1);
			prctl(PR_GET_DUMPABLE);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::GET_DUMPABLE);
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.res);
			VERIFY(sc.bool_res.has_value());
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.bool_res->value() == true);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				prctl(PR_SET_DUMPABLE, 1);
				syscall32(SyscallNr32::PRCTL, PR_GET_DUMPABLE);
			})
		}, "GET_DUMPABLE"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_DUMPABLE, 1);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_DUMPABLE);
			VERIFY(sc.bool_setting.has_value());
			VERIFY(sc.bool_setting->value() == true);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_DUMPABLE, 1);
			})
		}, "SET_DUMPABLE"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_KEEPCAPS, 1);
			prctl(PR_GET_KEEPCAPS);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::GET_KEEPCAPS);
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.res);
			VERIFY(sc.bool_res.has_value());
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.bool_res->value() == true);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				prctl(PR_SET_KEEPCAPS, 1);
				syscall32(SyscallNr32::PRCTL, PR_GET_KEEPCAPS);
			})
		}, "GET_KEEPCAPS"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_KEEPCAPS, 1);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_KEEPCAPS);
			VERIFY(sc.bool_setting.has_value());
			VERIFY(sc.bool_setting->value() == true);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_KEEPCAPS, 1);
			})
		}, "SET_KEEPCAPS"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_CHILD_SUBREAPER, 1);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_CHILD_SUBREAPER);
			VERIFY(sc.bool_setting.has_value());
			VERIFY(sc.bool_setting->value() == true);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_CHILD_SUBREAPER, 1);
			})
		}, "SET_CHILD_SUBREAPER"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_GET_IO_FLUSHER);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::GET_IO_FLUSHER);
			VERIFY(!sc.bool_setting);
			VERIFY(!sc.res);
			VERIFY(sc.bool_res.has_value());
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			/* this call requires special permissions */
			(void)sc;
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_GET_IO_FLUSHER);
			})
		}, "GET_IO_FLUSHER"
	}, TestSpec{SystemCallNr::PRCTL, []() {
			prctl(PR_SET_IO_FLUSHER, 1);
		}, ENTRY_VERIFY_CB(PrCtlSystemCall, {
			VERIFY(sc.op.operation() ==
					clues::item::ProcessOp::SET_IO_FLUSHER);
			VERIFY(sc.bool_setting.has_value());
			VERIFY(sc.bool_setting->value() == true);
			VERIFY(sc.res.has_value());
			VERIFY(!sc.bool_res);
		}), EXIT_VERIFY_CB(PrCtlSystemCall, {
			(void)sc;
			/* this call requires special permissions */
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::PRCTL, PR_SET_IO_FLUSHER, 1);
			})
		}, "SET_IO_FLUSHER"
	}
};

} // end ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
