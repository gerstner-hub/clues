// test
#include "utils/syscalls.hxx"

// Linux
#include <fcntl.h>
#include <unistd.h>

namespace {

void setup_sigset(sigset_t &ss) {
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGUSR1);
}

bool verify_sigset(const cosmos::SigSet &ss, const bool usr2 = false) {
	if (
		!ss.isSet(cosmos::signal::INTERRUPT) ||
		!ss.isSet(cosmos::signal::USR1) ||
		usr2 != ss.isSet(cosmos::signal::USR2)) {
		return false;
	}

	return true;
}

const auto TESTS = std::array{
	TestSpec{SystemCallNr::RT_SIGACTION, []() {
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
	},
#ifdef SYS_signalfd
	TestSpec{SystemCallNr::SIGNALFD, []() {
			sigset_t ss;
			setup_sigset(ss);
			int fd = syscall(SYS_signalfd, -1, &ss, 8);
			close(fd);
		}, ENTRY_VERIFY_CB(SignalFDSystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum::INVALID);
			const auto mask = *sc.mask.sigset();
			VERIFY(verify_sigset(mask));
			VERIFY(sc.sigset_size.value() == 8);
		}), EXIT_VERIFY_CB(SignalFDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto ss = alloc_struct32<sigset_t>();
				setup_sigset(*ss);
				syscall32(SyscallNr32::SIGNALFD, -1, ss, 8);
			})
		}
	},
#endif
	TestSpec{SystemCallNr::SIGNALFD4, []() {
			sigset_t ss;
			setup_sigset(ss);
			int fd = signalfd(-1, &ss, SFD_CLOEXEC);
			close(fd);
		}, ENTRY_VERIFY_CB(SignalFD4SystemCall, {
			VERIFY(sc.fd.fd() == cosmos::FileNum::INVALID);
			const auto mask = *sc.mask.sigset();
			VERIFY(verify_sigset(mask));
			VERIFY(sc.sigset_size.value() == 8);
			VERIFY(sc.flags.flags()[cosmos::SignalFD::Flag::CLOEXEC]);
		}), EXIT_VERIFY_CB(SignalFD4SystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto ss = alloc_struct32<sigset_t>();
				setup_sigset(*ss);
				syscall32(SyscallNr32::SIGNALFD4, -1, ss, 8, SFD_CLOEXEC);
			})
		}
	}, TestSpec{SystemCallNr::SIGNALFD4, []() {
			sigset_t ss;
			setup_sigset(ss);
			int fd = signalfd(-1, &ss, SFD_CLOEXEC);
			sigaddset(&ss, SIGUSR2);
			fd = signalfd(fd, &ss, 0);
			close(fd);
		}, ENTRY_VERIFY_CB(SignalFD4SystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			const auto mask = *sc.mask.sigset();
			VERIFY(verify_sigset(mask, true));
			VERIFY(sc.sigset_size.value() == 8);
			VERIFY(sc.flags.flags().none());
		}), EXIT_VERIFY_CB(SignalFD4SystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_fd.fd() == FIRST_FD);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto ss = alloc_struct32<sigset_t>();
				setup_sigset(*ss);
				int fd = signalfd(-1, ss, SFD_CLOEXEC);
				sigaddset(ss, SIGUSR2);
				fd = syscall32(SyscallNr32::SIGNALFD4, fd, ss, 8, 0);
			})
		},
		"reconfig"
	},
};

} // end ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
