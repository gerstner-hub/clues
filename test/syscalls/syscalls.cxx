// test
#include "utils/syscalls.hxx"
#include "utils/types.hxx"

// Linux
#include <sched.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

namespace {

using ABI = clues::ABI;

void verify_clock_nanosleep_entry(const clues::ClockNanoSleepSystemCall &sc, bool &good) {
	VERIFY(sc.clockid.type() == cosmos::ClockType::MONOTONIC);
	using enum clues::item::ClockNanoSleepFlags::Flag;
	using Flags = clues::item::ClockNanoSleepFlags::Flags;
	VERIFY(sc.flags.flags() == Flags{ABSTIME});
	const auto &sleep_time = *sc.time.spec();
	VERIFY(sleep_time.tv_sec == 5);
	VERIFY(sleep_time.tv_nsec == 500);
}

void verify_clock_nanosleep_exit(const clues::ClockNanoSleepSystemCall &sc, bool &good) {
	VERIFY(!sc.hasErrorCode());
	/* remain is unused when TIMER_ABSTIME is passed or
	 * no EINTR occurred. */
	VERIFY(!sc.remaining.spec());
}

void verify_futex_exit(const clues::FutexSystemCall &sc, bool &good) {
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
}

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
			canon_timespec ts;
			ts.tv_sec = 5;
			ts.tv_nsec = 500;
			/* avoid using the glibc wrapper, which does extra
			 * stuff on 32-bit */
			syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, &ts);
		}, ENTRY_VERIFY_CB(ClockNanoSleepSystemCall, {
			verify_clock_nanosleep_entry(sc, good);
		}), EXIT_VERIFY_CB(ClockNanoSleepSystemCall, {
			verify_clock_nanosleep_exit(sc, good);
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
	},
#ifdef COSMOS_X86
	TestSpec{SystemCallNr::CLOCK_NANOSLEEP_TIME64, []() {
#ifdef COSMOS_I386
			struct timespec ts;
			ts.tv_sec = 5;
			ts.tv_nsec = 500;
			syscall(SYS_clock_nanosleep_time64, CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, &ts);
#endif
		}, ENTRY_VERIFY_CB(ClockNanoSleepSystemCall, {
			verify_clock_nanosleep_entry(sc, good);
		}), EXIT_VERIFY_CB(ClockNanoSleepSystemCall, {
			verify_clock_nanosleep_exit(sc, good);
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{1}, []() {
				auto ts = alloc_struct32<struct timespec>();
				ts->tv_sec = 5;
				ts->tv_nsec = 500;
				syscall32(SyscallNr32::CLOCK_NANOSLEEP_TIME64,
						CLOCK_MONOTONIC, TIMER_ABSTIME, ts, ts);
			})
		}, "", {ABI::I386}
	},
#endif
	TestSpec{SystemCallNr::CLOSE, []() {
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
	},
	/* TODO cover more operations of futex() */
	TestSpec{SystemCallNr::FUTEX, []() {
			uint32_t fux = 123;
			canon_timespec ts;
			ts.tv_sec = 5;
			ts.tv_nsec = 500;
			syscall(SYS_futex, &fux, FUTEX_WAIT|FUTEX_CLOCK_REALTIME, 1, &ts);
		}, ENTRY_VERIFY_CB(FutexSystemCall, {
			verify_futex_exit(sc, good);
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
	},
#ifdef COSMOS_X86
	TestSpec{SystemCallNr::FUTEX_TIME64, []() {
#ifdef COSMOS_I386
			uint32_t fux = 123;
			struct timespec ts;
			ts.tv_sec = 5;
			ts.tv_nsec = 500;
			syscall(SYS_futex_time64, &fux, FUTEX_WAIT|FUTEX_CLOCK_REALTIME, 1, &ts);
#endif
		}, ENTRY_VERIFY_CB(FutexSystemCall, {
			verify_futex_exit(sc, good);
		}), EXIT_VERIFY_CB(FutexSystemCall, {
			/* contrary to what the man page says, CLOCK_REALTIME
			 * is _not_ supported (or not anymore) with
			 * FUTEX_WAIT. Thus is returns ENOSYS. */
			VERIFY(sc.hasErrorCode());
		}), IgnoreCalls{}, {
			I386_CROSS_ABI(IgnoreCalls{2}, []() {
				auto fux = alloc_struct32<uint32_t>();
				auto ts = alloc_struct32<struct timespec>();
				ts->tv_sec = 5;
				ts->tv_nsec = 500;
				syscall32(SyscallNr32::FUTEX_TIME64, fux,
						FUTEX_WAIT|FUTEX_CLOCK_REALTIME, 1, ts);
			})
		}, "", {ABI::I386}
	},
#endif
	TestSpec{SystemCallNr::GETRLIMIT, []() {
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
		{ABI::X86_64, ABI::AARCH64}
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
		{ABI::I386}
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
		{ABI::I386}
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
			canon_timespec ts;
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
	}
};

} // end anon ns


int main(const int argc, const char **argv) {
	SyscallTest test{TESTS};
	return test.run(argc, argv);
}
