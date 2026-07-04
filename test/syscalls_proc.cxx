// test
#include "utils/syscalls.hxx"

namespace {

/*
* fork() is not available on all ABIs and libc's
* fork() can create additional syscall noise, so
* directly use clone3() for this purpose.
*/
pid_t plain_fork() {
	struct clone_args cl;
	cosmos::zero_object(cl);
	cl.exit_signal = SIGCHLD;
	return syscall(SYS_clone3, &cl, sizeof(cl));
}

const auto TESTS = std::array{
	TestSpec{SystemCallNr::CLONE, []() {
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
	},
#ifdef CLUES_HAVE_FORK
	TestSpec{SystemCallNr::FORK, []() {
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
	},
#endif
	TestSpec{SystemCallNr::GETUID, []() {
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
	}, TestSpec{SystemCallNr::WAIT4, []() {
			if (const auto pid = plain_fork(); pid == 0) {
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
	}, TestSpec{SystemCallNr::WAITID, []() {
			if (const auto pid = plain_fork(); pid == 0) {
				::_exit(10);
			} else {
				siginfo_t sinfo;
				::waitid(P_PID, pid, &sinfo, WEXITED);
			}
		}, ENTRY_VERIFY_CB(WaitIDSystemCall, {
			VERIFY(sc.idtype.type() == clues::item::WaitID::PID);
			VERIFY(!sc.id_pgid);
			VERIFY(!sc.id_pidfd);
			VERIFY(sc.id_pid.has_value());
			VERIFY(!sc.siginfo.info());
			VERIFY(sc.options.options() == cosmos::WaitFlag::WAIT_FOR_EXITED);
			VERIFY(!sc.rusage.usage());
		}), EXIT_VERIFY_CB(WaitIDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(sc.siginfo.info().has_value());
			const auto &info = *sc.siginfo.info();
			VERIFY(info.sigNr() == cosmos::signal::CHILD);
			const auto child_data = *info.childData();
			VERIFY(child_data.exited());
			VERIFY(child_data.child.uid == cosmos::proc::get_real_user_id());
			VERIFY(*child_data.status == cosmos::ExitStatus{10});
			VERIFY(child_data.user_time.has_value());
			VERIFY(child_data.system_time.has_value());
			VERIFY(!sc.rusage.usage());
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				if (const auto pid = plain_fork(); pid == 0) {
					::_exit(10);
				} else {
					auto sinfo = alloc_struct32<siginfo_t>();
					syscall32(SyscallNr32::WAITID, P_PID, pid, sinfo, WEXITED, nullptr);
				}
			})
		}
	}, TestSpec{SystemCallNr::WAITPID, []() {
#ifdef COSMOS_I386
			if (const auto pid = plain_fork(); pid == 0) {
				::_exit(10);
			} else {
				int status;
				::syscall(SYS_waitpid, pid, &status, WCONTINUED);
			}
#endif
		}, ENTRY_VERIFY_CB(WaitPIDSystemCall, {
			VERIFY(cosmos::to_integral(sc.pid.pid()) > 0);
			VERIFY(!sc.wstatus.status());
			VERIFY(sc.options.options() == cosmos::WaitFlag::WAIT_FOR_CONTINUED);
		}), EXIT_VERIFY_CB(WaitPIDSystemCall, {
			VERIFY(sc.hasResultValue());
			VERIFY(cosmos::to_integral(sc.event_pid.pid()) > 0);
			VERIFY(sc.wstatus.status().has_value());
			const auto status = *sc.wstatus.status();
			VERIFY(status.exited());
			VERIFY(status.status() == cosmos::ExitStatus{10});
		}), IgnoreCalls{1}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				if (const auto pid = plain_fork(); pid == 0) {
					::_exit(10);
				} else {
					auto status = alloc32<int*>(sizeof(int));;
					syscall32(SyscallNr32::WAITPID, pid, status, WCONTINUED);
				}
			})
		},
		"",
		{clues::ABI::I386}
	}
};

} // end ns

int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
