// test
#include "utils/syscalls.hxx"

// Linux
#include <linux/fs.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

namespace {
const auto TESTS = std::array{
#ifdef CLUES_HAVE_ALARM
	TestSpec{SystemCallNr::ALARM, []() {
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
	},
#endif
	TestSpec{SystemCallNr::BREAK, []() {
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
	}, TestSpec{SystemCallNr::GETRANDOM, []() {
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
	}, TestSpec{SystemCallNr::GETUID, []() {
			syscall(SYS_getuid);
		}, ENTRY_VERIFY_CB(GetUIDSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetUIDSystemCall, {
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
		}, ENTRY_VERIFY_CB(GetUIDSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetUIDSystemCall, {
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
		}, ENTRY_VERIFY_CB(GetEUIDSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetEUIDSystemCall, {
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
		}, ENTRY_VERIFY_CB(GetEUIDSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetEUIDSystemCall, {
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
		}, ENTRY_VERIFY_CB(GetGIDSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetGIDSystemCall, {
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
		}, ENTRY_VERIFY_CB(GetGIDSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetGIDSystemCall, {
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
		}, ENTRY_VERIFY_CB(GetEGIDSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetEGIDSystemCall, {
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
		}, ENTRY_VERIFY_CB(GetEGIDSystemCall, {
			/* no input parameters */
			(void)sc;
		}), EXIT_VERIFY_CB(GetEGIDSystemCall, {
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
	}, TestSpec{SystemCallNr::GETPID, []() {
			getpid();
		}, ENTRY_VERIFY_CB(GetPIDSystemCall, {
			(void)sc;
		}), EXIT_VERIFY_CB(GetPIDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.pid() == tracee.pid());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETPID);
			})
		}
	}, TestSpec{SystemCallNr::GETPPID, []() {
			getppid();
		}, ENTRY_VERIFY_CB(GetPPIDSystemCall, {
			(void)sc;
		}), EXIT_VERIFY_CB(GetPPIDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.pid() == cosmos::proc::get_own_pid());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{0}, []() {
				syscall32(SyscallNr32::GETPPID);
			})
		}
	}, TestSpec{SystemCallNr::GETPGID, []() {
			getpgid(getpid());
		}, ENTRY_VERIFY_CB(GetPGIDSystemCall, {
			VERIFY(sc.pid.pid() == tracee.pid());
		}), EXIT_VERIFY_CB(GetPGIDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.pgid() ==
					cosmos::proc::get_process_group_of(cosmos::proc::get_own_pid()));
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				const auto pid = getpid();
				syscall32(SyscallNr32::GETPGID, pid);
			})
		}
	}, TestSpec{SystemCallNr::GETTID, []() {
			gettid();
		}, ENTRY_VERIFY_CB(GetTIDSystemCall, {
			(void)sc;
		}), EXIT_VERIFY_CB(GetTIDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(cosmos::as_pid(sc.id.tid()) == tracee.pid());
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{}, []() {
				syscall32(SyscallNr32::GETTID);
			})
		}
	}, TestSpec{SystemCallNr::GETSID, []() {
			getsid(getpid());
		}, ENTRY_VERIFY_CB(GetSIDSystemCall, {
			VERIFY(sc.pid.pid() == tracee.pid());
		}), EXIT_VERIFY_CB(GetSIDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.id.sid() == cosmos::proc::get_session_of(cosmos::proc::get_own_pid()));
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				syscall32(SyscallNr32::GETSID, getpid());
			})
		}
	}, TestSpec{SystemCallNr::SETSID, []() {
			setsid();
		}, ENTRY_VERIFY_CB(SetSIDSystemCall, {
			(void)sc;
		}), EXIT_VERIFY_CB(SetSIDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_sid.sid() == cosmos::proc::get_session_of(tracee.pid()));
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{}, []() {
				syscall32(SyscallNr32::SETSID);
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
	/*
	 * mmap() and mmap2() are especially problematic cases, because mmap()
	 * on i386 is completely different from mmap() on other ABIs, while
	 * mmap2() on i386 matches mmap() on other ABIs.
	 *
	 * This doesn't match our modeling very well. We need to create
	 * dedicated TestSpecs for all possible variants to avoid conflicts.
	 */
	}, TestSpec{SystemCallNr::MMAP, []() {
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
	}, TestSpec{SystemCallNr::READ, []() {
			int fd = open("/etc/fstab", O_RDONLY);
			char buffer[1024];
			if (read(fd, buffer, sizeof(buffer)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.count.value() == 1024);
		}), EXIT_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.hasResultValue());
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
	}, TestSpec{SystemCallNr::READ, []() {
			int pipes[2];
			if (pipe2(pipes, O_NONBLOCK) < 0) {

			}
			char buffer[1024];
			if (read(pipes[0], buffer, sizeof(buffer)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.count.value() == 1024);
		}), EXIT_VERIFY_CB(ReadSystemCall, {
			VERIFY(sc.hasErrorCode());
			VERIFY(sc.buf.availableBytes() == 0);
			VERIFY(sc.buf.data().empty());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				if (pipe2(pipes, O_NONBLOCK) < 0) {
				}
				auto buffer = alloc32<char*>(1024);
				if (syscall32(SyscallNr32::READ, pipes[0], buffer, 1024) < 0) {
				}
			})
		},
		"failed read"
	}, TestSpec{SystemCallNr::READV, []() {
			int pipes[2];
			if (pipe2(pipes, 0) < 0) {

			}

			constexpr std::string_view DATA{"test"};

			if (::write(pipes[1], DATA.data(), DATA.size()) != DATA.size()) {

			}

			char buf1[128];
			char buf2[200];
			struct iovec vec[2];
			vec[0].iov_base = (void*)buf1;
			vec[0].iov_len = sizeof(buf1);
			vec[1].iov_base = (void*)buf2;
			vec[1].iov_len = sizeof(buf2);
			if (::readv(pipes[0], vec, sizeof(vec) / sizeof(struct iovec)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ReadVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 128);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].len == 200);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.iov_count.value() == NUM_VECS);
		}), EXIT_VERIFY_CB(ReadVSystemCall, {
			VERIFY(sc.hasResultValue());
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].filled == 4);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.read.value() == 4);
			const std::string_view data{(const char*)buffers[0].data.data(), buffers[0].data.size()};
			VERIFY(data == "test");
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{7}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				if (pipe2(pipes, 0) < 0) {
				}
				auto buf1 = alloc32<char*>(128);
				auto buf2 = alloc32<char*>(200);
				auto data = alloc_str32("test");
				if (write(pipes[1], data, 4) != 4) {

				}

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 128;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 200;
				if (syscall32(SyscallNr32::READV, pipes[0], vec, 2) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::READV, []() {
			int pipes[2];
			if (pipe2(pipes, O_NONBLOCK) < 0) {

			}

			char buf1[128];
			char buf2[200];
			struct iovec vec[2];
			vec[0].iov_base = (void*)buf1;
			vec[0].iov_len = sizeof(buf1);
			vec[1].iov_base = (void*)buf2;
			vec[1].iov_len = sizeof(buf2);
			if (::readv(pipes[0], vec, sizeof(vec) / sizeof(struct iovec)) < 0) {

			}
		}, ENTRY_VERIFY_CB(ReadVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 128);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].len == 200);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.iov_count.value() == NUM_VECS);
		}), EXIT_VERIFY_CB(ReadVSystemCall, {
			VERIFY(sc.hasErrorCode());
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.read.value() == 0);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{5}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				if (pipe2(pipes, O_NONBLOCK) < 0) {
				}
				auto buf1 = alloc32<char*>(128);
				auto buf2 = alloc32<char*>(200);

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 128;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 200;
				if (syscall32(SyscallNr32::READV, pipes[0], vec, 2) < 0) {
				}
			})
		},
		"failed read"
	}, TestSpec{SystemCallNr::PREADV, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			if (fd < 0)
				return;

			constexpr std::string_view DATA{"test data for positioned vector read"};

			if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
				return;
			}

			char buf1[10];
			char buf2[20];
			struct iovec vec[2];
			vec[0].iov_base = (void*)buf1;
			vec[0].iov_len = sizeof(buf1);
			vec[1].iov_base = (void*)buf2;
			vec[1].iov_len = sizeof(buf2);
			if (::preadv(fd, vec, sizeof(vec) / sizeof(struct iovec), 5) < 0) {

			}
		}, ENTRY_VERIFY_CB(PReadVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 10);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].len == 20);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			VERIFY(sc.offset.value() == 5);
		}), EXIT_VERIFY_CB(PReadVSystemCall, {
			VERIFY(sc.hasResultValue());
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].filled == 10);
			VERIFY(buffers[1].filled == 20);
			VERIFY(sc.read.value() == 30);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{6}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);
				auto buf1 = alloc32<char*>(10);
				auto buf2 = alloc32<char*>(20);
				auto data = alloc_str32("test data for positioned vector read");
				const ssize_t len = strlen(data);
				if (write(fd, data, len) != len) {
					return;
				}

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 10;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 20;
				if (syscall32(SyscallNr32::PREADV, fd, vec, 2, 5, 0) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PREADV, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			if (fd < 0)
				return;

			char buf[64];
			struct iovec vec;
			vec.iov_base = (void*)buf;
			vec.iov_len = sizeof(buf);
			if (::preadv(fd, &vec, 1, LARGE_OFFSET64) < 0) {

			}
		}, ENTRY_VERIFY_CB(PReadVSystemCall, {
			VERIFY(sc.offset.value() == LARGE_OFFSET64);
		}), EXIT_VERIFY_CB(PReadVSystemCall, {
			(void)sc;
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

				auto buf = alloc32<char*>(20);
				auto vec = alloc_struct32<clues::iovec32>();
				vec->iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf));
				vec->iov_len = 20;
				/* large offset composed of 1 high bit and one low bit */
				if (syscall32(SyscallNr32::PREADV, fd, vec, 1, 2, 1) < 0) {
				}
			})
		}, "64-bit offset"
	}, TestSpec{SystemCallNr::PREADV2, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			if (fd < 0)
				return;

			constexpr std::string_view DATA{"test data for positioned vector read"};

			if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
				return;
			}

			char buf1[10];
			char buf2[20];
			struct iovec vec[2];
			vec[0].iov_base = (void*)buf1;
			vec[0].iov_len = sizeof(buf1);
			vec[1].iov_base = (void*)buf2;
			vec[1].iov_len = sizeof(buf2);
			if (::preadv2(fd, vec, sizeof(vec) / sizeof(struct iovec), 5, RWF_HIPRI) < 0) {

			}
		}, ENTRY_VERIFY_CB(PReadV2SystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 10);
			VERIFY(buffers[0].filled == 0);
			VERIFY(buffers[1].len == 20);
			VERIFY(buffers[1].filled == 0);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			VERIFY(sc.offset.value() == 5);
			VERIFY(sc.flags.flags() == cosmos::StreamIO::ReadWriteFlag::HIGH_PRIO);
		}), EXIT_VERIFY_CB(PReadV2SystemCall, {
			VERIFY(sc.hasResultValue());
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].filled == 10);
			VERIFY(buffers[1].filled == 20);
			VERIFY(sc.read.value() == 30);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{6}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);
				auto buf1 = alloc32<char*>(10);
				auto buf2 = alloc32<char*>(20);
				auto data = alloc_str32("test data for positioned vector read");
				const ssize_t len = strlen(data);
				if (write(fd, data, len) != len) {
					return;
				}

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 10;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 20;
				if (syscall32(SyscallNr32::PREADV2, fd, vec, 2, 5, 0, RWF_HIPRI) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::WRITE, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			const char buffer[] = "abcdefgh";
			if (write(fd, buffer, sizeof(buffer)) < 0) {

			}
		}, ENTRY_VERIFY_CB(WriteSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.buf.data().size() == 9);
			std::string s;
			for (const auto byte: sc.buf.data()) {
				const auto ch = static_cast<char>(byte);
				if (ch)
					s.push_back(ch);
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
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buffer = alloc_str32("abcdefgh");
				syscall32(SyscallNr32::WRITE, fd, buffer, strlen(buffer) + 1);
			})
		}
	}, TestSpec{SystemCallNr::WRITEV, []() {
			int pipes[2];
			if (pipe2(pipes, 0) < 0) {

			}

			constexpr std::string_view DATA1{"test1"};
			constexpr std::string_view DATA2{"test20"};

			struct iovec vec[2];
			vec[0].iov_base = (void*)DATA1.data();
			vec[0].iov_len = DATA1.size();
			vec[1].iov_base = (void*)DATA2.data();
			vec[1].iov_len = DATA2.size();

			if (::writev(pipes[1], vec, sizeof(vec) / sizeof(struct iovec)) != DATA1.size() + DATA2.size()) {

			}

		}, ENTRY_VERIFY_CB(WriteVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == SECOND_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 5);
			VERIFY(buffers[0].filled == 5);
			VERIFY(buffers[1].len == 6);
			VERIFY(buffers[1].filled == 6);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			const std::string_view data1{(const char*)buffers[0].data.data(), buffers[0].data.size()};
			const std::string_view data2{(const char*)buffers[1].data.data(), buffers[1].data.size()};
			VERIFY(data1 == "test1");
			VERIFY(data2 == "test20");
		}), EXIT_VERIFY_CB(WriteVSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.written.value() == 11);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{5}, []() {
				auto pipes = *alloc_struct32<int[2]>();
				if (pipe2(pipes, 0) < 0) {
				}
				auto buf1 = alloc_str32("test1");
				auto buf2 = alloc_str32("test20");

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 5;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 6;
				if (syscall32(SyscallNr32::WRITEV, pipes[1], vec, 2) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PWRITEV, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			if (fd < 0)
				return;

			constexpr std::string_view DATA1{"test1"};
			constexpr std::string_view DATA2{"test20"};

			struct iovec vec[2];
			vec[0].iov_base = (void*)DATA1.data();
			vec[0].iov_len = DATA1.size();
			vec[1].iov_base = (void*)DATA2.data();
			vec[1].iov_len = DATA2.size();

			if (::pwritev(fd, vec, sizeof(vec) / sizeof(struct iovec), 15) != DATA1.size() + DATA2.size()) {
				return;
			}
		}, ENTRY_VERIFY_CB(PWriteVSystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 5);
			VERIFY(buffers[0].filled == 5);
			VERIFY(buffers[1].len == 6);
			VERIFY(buffers[1].filled == 6);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			VERIFY(sc.offset.value() == 15);
		}), EXIT_VERIFY_CB(PWriteVSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.written.value() == 11);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buf1 = alloc_str32("test1");
				auto buf2 = alloc_str32("test20");

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 5;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 6;
				if (syscall32(SyscallNr32::PWRITEV, fd, vec, 2, 15, 0) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PWRITEV, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			if (fd < 0)
				return;

			constexpr std::string_view DATA1{"test1"};

			struct iovec vec;
			vec.iov_base = (void*)DATA1.data();
			vec.iov_len = DATA1.size();

			if (::pwritev(fd, &vec, 1, LARGE_OFFSET64) < 0) {
				return;
			}
		}, ENTRY_VERIFY_CB(PWriteVSystemCall, {
			VERIFY(sc.offset.value() == LARGE_OFFSET64);
		}), EXIT_VERIFY_CB(PWriteVSystemCall, {
			(void)sc;
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buf1 = alloc_str32("test1");

				auto vec = alloc_struct32<clues::iovec32>();
				vec->iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec->iov_len = 5;
				/* 64-bit offset comprised of 1 high bit and 1 low bit */
				if (syscall32(SyscallNr32::PWRITEV, fd, vec, 1, 2, 1) < 0) {
				}
			})
		}, "64-bit offset"
	}, TestSpec{SystemCallNr::PWRITEV2, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			if (fd < 0)
				return;

			constexpr std::string_view DATA1{"test1"};
			constexpr std::string_view DATA2{"test20"};

			struct iovec vec[2];
			vec[0].iov_base = (void*)DATA1.data();
			vec[0].iov_len = DATA1.size();
			vec[1].iov_base = (void*)DATA2.data();
			vec[1].iov_len = DATA2.size();

			if (::pwritev2(fd, vec, sizeof(vec) / sizeof(struct iovec), 15, RWF_HIPRI) != DATA1.size() + DATA2.size()) {
				return;
			}
		}, ENTRY_VERIFY_CB(PWriteV2SystemCall, {
			constexpr auto NUM_VECS = 2;
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.iov.count() == NUM_VECS);
			const auto &buffers = sc.iov.buffers();
			VERIFY(buffers.size() == NUM_VECS);
			VERIFY(buffers[0].len == 5);
			VERIFY(buffers[0].filled == 5);
			VERIFY(buffers[1].len == 6);
			VERIFY(buffers[1].filled == 6);
			VERIFY(sc.iov_count.value() == NUM_VECS);
			VERIFY(sc.offset.value() == 15);
			VERIFY(sc.flags.flags() == cosmos::StreamIO::ReadWriteFlag::HIGH_PRIO);
		}), EXIT_VERIFY_CB(PWriteVSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.written.value() == 11);
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{4}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buf1 = alloc_str32("test1");
				auto buf2 = alloc_str32("test20");

				auto vec = *alloc_struct32<clues::iovec32[2]>();
				vec[0].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf1));
				vec[0].iov_len = 5;
				vec[1].iov_base = static_cast<uint32_t>(reinterpret_cast<intptr_t>(buf2));
				vec[1].iov_len = 6;
				if (syscall32(SyscallNr32::PWRITEV2, fd, vec, 2, 15, 0, RWF_HIPRI) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PREAD64, []() {
			int fd = open("/etc/fstab", O_RDONLY);
			char buffer[1024];
			if (pread(fd, buffer, sizeof(buffer), 100) < 0) {

			}
		}, ENTRY_VERIFY_CB(PRead64SystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.count.value() == 1024);
			VERIFY(sc.offset.value() == 100);
		}), EXIT_VERIFY_CB(PRead64SystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.buf.availableBytes() > 0);
			VERIFY(sc.buf.data().size() <= sc.buf.availableBytes());
			VERIFY(sc.read.value() == sc.buf.availableBytes());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				auto path = alloc_str32("/etc/fstab");
				int fd = open(path, O_RDONLY);
				auto buffer = alloc32<char*>(1024);
				if (syscall32(SyscallNr32::PREAD64, fd, buffer, 1024, 100) < 0) {
				}
			})
		}
	}, TestSpec{SystemCallNr::PWRITE64, []() {
			int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
			const char buffer[] = "abcdefgh";
			if (write(fd, buffer, sizeof(buffer)) < 0) {

			}
			if (pwrite(fd, buffer, sizeof(buffer), sizeof(buffer) / 2) < 0) {

			}
		}, ENTRY_VERIFY_CB(PWrite64SystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.buf.data().size() == 9);
			std::string s;
			for (const auto byte: sc.buf.data()) {
				const auto ch = static_cast<char>(byte);
				if (ch)
					s.push_back(ch);
			}
			VERIFY(s == "abcdefgh");
			VERIFY(sc.count.value() == 9);
			VERIFY(sc.buf.availableBytes() == 9);
			VERIFY(sc.offset.value() == (off_t)sc.count.value() / 2);
		}), EXIT_VERIFY_CB(PWrite64SystemCall, {
			VERIFY(sc.hasResultValue());
			// partial writes should not occur here
			VERIFY(sc.written.value() == 9);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int fd = open("/tmp", O_WRONLY|O_TMPFILE|O_CLOEXEC, 0600);
				auto buffer = alloc_str32("abcdefgh");
				syscall32(SyscallNr32::WRITE, fd, buffer, strlen(buffer) + 1);
				syscall32(SyscallNr32::PWRITE64, fd, buffer, strlen(buffer) + 1, (strlen(buffer) + 1) / 2);
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
			/*
			 * fork() is not available on all ABIs and libc's
			 * fork() can create additional syscall noise, so
			 * directly use clone3() for this purpose.
			 */
			struct clone_args cl;
			cosmos::zero_object(cl);
			cl.exit_signal = SIGCHLD;
			if (const auto pid = syscall(SYS_clone3, &cl, sizeof(cl)); pid == 0) {
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
	}, TestSpec{SystemCallNr::LSEEK, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			constexpr std::string_view DATA{"arbitrary data for testing lseek"};

			if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
				return;
			}

			syscall(SYS_lseek, fd, -10L, SEEK_END);
		}, ENTRY_VERIFY_CB(LSeekSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.offset.value() == -10);
			VERIFY(sc.whence.type() == cosmos::StreamIO::SeekType::END);
		}), EXIT_VERIFY_CB(LSeekSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.new_offset.value() == 22);
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);
				constexpr std::string_view DATA{"arbitrary data for testing lseek"};
				if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
					return;
				}

				syscall32(SyscallNr32::LSEEK, fd, -10L, SEEK_END);
			})
		},
	}, TestSpec{SystemCallNr::LLSEEK, []() {
			int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);

			constexpr std::string_view DATA{"arbitrary data for testing lseek"};

			if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
				return;
			}

			/* this will automatically be translated into llseek() by glibc */
			lseek(fd, LARGE_OFFSET64, SEEK_SET);
		}, ENTRY_VERIFY_CB(LLSeekSystemCall, {
			VERIFY(sc.fd.fd() == FIRST_FD);
			VERIFY(sc.offset.value() == LARGE_OFFSET64);
			VERIFY(sc.whence.type() == cosmos::StreamIO::SeekType::SET);
		}), EXIT_VERIFY_CB(LLSeekSystemCall, {
			VERIFY(sc.hasResultValue());
		}), IgnoreCalls{2}, {
			I386_CROSS_ABI(IgnoreCalls{3}, []() {
				int fd = open("/tmp", O_TMPFILE|O_RDWR|O_CLOEXEC, 0600);
				constexpr std::string_view DATA{"arbitrary data for testing lseek"};
				if (::write(fd, DATA.data(), DATA.size()) != DATA.size()) {
					return;
				}

				auto new_off = alloc_struct32<off_t>();

				syscall32(SyscallNr32::LLSEEK, fd, 1, 2, new_off, SEEK_SET);
			})
		}, "", {clues::ABI::I386}
	}, TestSpec{SystemCallNr::RSEQ, []() {
			constexpr size_t RS_SIZE = 64;
			struct rseq *rs = (struct rseq*)std::aligned_alloc(32, RS_SIZE);
			rs->cpu_id_start = 0;
			rs->cpu_id = -1;
			rs->rseq_cs = 0;
			rs->flags = RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL;
			rs->node_id = 0;
			rs->mm_cid = 0;
			syscall(SYS_rseq, rs, RS_SIZE, 0, 0x12345678);
		}, ENTRY_VERIFY_CB(RSeqSystemCall, {
			VERIFY(sc.rseq_len.value() == 64);
			VERIFY(sc.flags.flags().raw() == 0);
			VERIFY(sc.signature.value() == 0x12345678);
		}), EXIT_VERIFY_CB(RSeqSystemCall, {
			/*
			 * re-registering a struct rseq actually doesn't work
			 * without us knowing the existing registration done
			 * by glibc, thus we'll have to live with an error
			 * code here.
			 */
			VERIFY(sc.hasErrorCode());
		}), IgnoreCalls{0}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				constexpr size_t RS_SIZE = 64;
				struct rseq *rs = alloc32<struct rseq*>(RS_SIZE);
				rs->cpu_id_start = 0;
				rs->cpu_id = -1;
				rs->rseq_cs = 0;
				rs->flags = RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL;
				rs->node_id = 0;
				rs->mm_cid = 0;
				syscall32(SyscallNr32::RSEQ, rs, RS_SIZE, 0, 0x12345678);
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
};

} // end anon ns


int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
