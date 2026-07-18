// C++
#include "sysnrs/i386.hxx"
#include <utility>

// clues
#include <clues/syscalls/fs.hxx>
#include <clues/syscalls/io.hxx>
#include <clues/syscalls/memory.hxx>
#include <clues/syscalls/other.hxx>
#include <clues/syscalls/prctl.hxx>
#include <clues/syscalls/process.hxx>
#include <clues/syscalls/signals.hxx>
#include <clues/syscalls/thread.hxx>
#include <clues/syscalls/time.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCallInfo.hxx>

namespace clues {

namespace {

// alias for creating SystemCall instances below
template <typename T, typename... Args>
std::pair<SystemCallPtr, bool> new_sys(Args&&... args) {
	    return std::make_pair(
			    std::make_shared<T>(std::forward<Args>(args)...),
			    true);
}

// alias for creating multi-typed SystemCall instances below
template <typename T, typename... Args>
std::pair<SystemCallPtr, bool> new_multi_sys(Args&&... args) {
	    return std::make_pair(
			    T::createSystemCall(std::forward<Args>(args)...),
			    false);
}

std::pair<SystemCallPtr, bool> create_syscall(const SystemCallInfo &info) {
	const auto nr = info.sysNr();

	switch (nr) {
	case SystemCallNr::ACCESS:          return new_sys<AccessSystemCall>();
	case SystemCallNr::FACCESSAT:       return new_sys<FAccessAtSystemCall>();
	case SystemCallNr::FACCESSAT2:      return new_sys<FAccessAt2SystemCall>();
	case SystemCallNr::ALARM:           return new_sys<AlarmSystemCall>();
#ifdef CLUES_HAVE_ARCH_PRCTL
	case SystemCallNr::ARCH_PRCTL:      return new_sys<ArchPrctlSystemCall>();
#endif
	case SystemCallNr::BRK:             return new_sys<BreakSystemCall>();
	case SystemCallNr::CLOCK_NANOSLEEP: [[ fallthrough ]];
	case SystemCallNr::CLOCK_NANOSLEEP_TIME64: return new_sys<ClockNanoSleepSystemCall>(nr);
	case SystemCallNr::CLONE:           return new_sys<CloneSystemCall>();
	case SystemCallNr::CLONE3:          return new_sys<Clone3SystemCall>();
	case SystemCallNr::CLOSE:           return new_sys<CloseSystemCall>();
	case SystemCallNr::EXECVE:          return new_sys<ExecveSystemCall>();
	case SystemCallNr::EXECVEAT:        return new_sys<ExecveAtSystemCall>();
	case SystemCallNr::EXIT:            return new_sys<ExitSystemCall>();
	case SystemCallNr::EXIT_GROUP:      return new_sys<ExitGroupSystemCall>();
	case SystemCallNr::FCNTL:           [[fallthrough]];
	case SystemCallNr::FCNTL64:         return new_sys<FcntlSystemCall>(nr);
	case SystemCallNr::FORK:            return new_sys<ForkSystemCall>();
	case SystemCallNr::OLDFSTAT:        [[fallthrough]];
	case SystemCallNr::FSTAT:           [[fallthrough]];
	case SystemCallNr::FSTAT64:         return new_sys<FstatSystemCall>(nr);
	case SystemCallNr::FSTATAT64:       [[fallthrough]];
	case SystemCallNr::NEWFSTATAT:      return new_sys<FstatAtSystemCall>(nr);
	case SystemCallNr::FUTEX:           [[fallthrough]];
	case SystemCallNr::FUTEX_TIME64:    return new_sys<FutexSystemCall>(nr);
	case SystemCallNr::GETDENTS:        [[fallthrough]];
	case SystemCallNr::GETDENTS64:      return new_sys<GetDentsSystemCall>(nr);
	case SystemCallNr::GETUID:          [[fallthrough]];
	case SystemCallNr::GETUID32:        return new_sys<GetUIDSystemCall>(nr);
	case SystemCallNr::GETEGID32:       [[fallthrough]];
	case SystemCallNr::GETEGID:         return new_sys<GetEGIDSystemCall>(nr);
	case SystemCallNr::GETEUID32:       [[fallthrough]];
	case SystemCallNr::GETEUID:         return new_sys<GetEUIDSystemCall>(nr);
	case SystemCallNr::GETGID32:        [[fallthrough]];
	case SystemCallNr::GETGID:          return new_sys<GetGIDSystemCall>(nr);
	case SystemCallNr::GETPID:          return new_sys<GetPIDSystemCall>(nr);
	case SystemCallNr::GETPPID:         return new_sys<GetPPIDSystemCall>(nr);
	case SystemCallNr::GETPGID:         return new_sys<GetPGIDSystemCall>();
	case SystemCallNr::GETTID:          return new_sys<GetTIDSystemCall>(nr);
	case SystemCallNr::GETSID:          return new_sys<GetSIDSystemCall>();
	case SystemCallNr::SETSID:          return new_sys<SetSIDSystemCall>();
	case SystemCallNr::GETRLIMIT:       return new_sys<GetRlimitSystemCall>();
	case SystemCallNr::SETRLIMIT:       return new_sys<SetRlimitSystemCall>();
	case SystemCallNr::PRLIMIT64:       return new_sys<Prlimit64SystemCall>();
	case SystemCallNr::GET_ROBUST_LIST: return new_sys<GetRobustListSystemCall>();
	case SystemCallNr::SET_ROBUST_LIST: return new_sys<SetRobustListSystemCall>();
	case SystemCallNr::IOCTL:           return new_sys<IoCtlSystemCall>();
	case SystemCallNr::LSTAT:           [[fallthrough]];
	case SystemCallNr::LSTAT64:         [[fallthrough]];
	case SystemCallNr::OLDLSTAT:        return new_sys<LstatSystemCall>(nr);
	case SystemCallNr::MMAP:            [[fallthrough]];
	case SystemCallNr::MMAP2:           return new_sys<MmapSystemCall>(nr);
	case SystemCallNr::MPROTECT:        return new_sys<MprotectSystemCall>();
	case SystemCallNr::MUNMAP:          return new_sys<MunmapSystemCall>();
	case SystemCallNr::NANOSLEEP:       return new_sys<NanoSleepSystemCall>();
	case SystemCallNr::OPENAT:          return new_sys<OpenAtSystemCall>();
	case SystemCallNr::OPEN:            return new_sys<OpenSystemCall>();
	case SystemCallNr::READ:            return new_sys<ReadSystemCall>();
	case SystemCallNr::RESTART_SYSCALL: return new_sys<RestartSystemCall>();
	case SystemCallNr::RT_SIGACTION:    return new_sys<RtSigActionSystemCall>();
	case SystemCallNr::SIGACTION:       return new_sys<SigActionSystemCall>();
	case SystemCallNr::RT_SIGPROCMASK:  return new_sys<RtSigProcMaskSystemCall>();
	case SystemCallNr::SIGPROCMASK:     return new_sys<SigProcMaskSystemCall>();
	case SystemCallNr::SET_TID_ADDRESS: return new_sys<SetTIDAddressSystemCall>();
	case SystemCallNr::OLDSTAT:         [[fallthrough]];
	case SystemCallNr::STAT64:          [[fallthrough]];
	case SystemCallNr::STAT:            return new_sys<StatSystemCall>(nr);
	case SystemCallNr::TGKILL:          return new_sys<TgKillSystemCall>();
	case SystemCallNr::WAIT4:           return new_sys<Wait4SystemCall>();
	case SystemCallNr::WAITID:          return new_sys<WaitIDSystemCall>();
	case SystemCallNr::WAITPID:         return new_sys<WaitPIDSystemCall>();
	case SystemCallNr::WRITE:           return new_sys<WriteSystemCall>();
	case SystemCallNr::PIPE:            return new_sys<PipeSystemCall>();
	case SystemCallNr::PIPE2:           return new_sys<Pipe2SystemCall>();
	case SystemCallNr::PWRITE64:        return new_sys<PWrite64SystemCall>();
	case SystemCallNr::PREAD64:         return new_sys<PRead64SystemCall>();
	case SystemCallNr::READV:           return new_sys<ReadVSystemCall>();
	case SystemCallNr::WRITEV:          return new_sys<WriteVSystemCall>();
	case SystemCallNr::PREADV:          return new_sys<PReadVSystemCall>();
	case SystemCallNr::PREADV2:         return new_sys<PReadV2SystemCall>();
	case SystemCallNr::PWRITEV:         return new_sys<PWriteVSystemCall>();
	case SystemCallNr::PWRITEV2:        return new_sys<PWriteV2SystemCall>();
	case SystemCallNr::GETRANDOM:       return new_sys<GetRandomSystemCall>();
	case SystemCallNr::LSEEK:           return new_sys<LSeekSystemCall>();
	case SystemCallNr::LLSEEK:          return new_sys<LLSeekSystemCall>();
	case SystemCallNr::RSEQ:            return new_sys<RSeqSystemCall>();
	case SystemCallNr::PRCTL:           return new_multi_sys<PrCtlSystemCall>(info);
	case SystemCallNr::FADVISE64:       /* fallthrough */
	case SystemCallNr::FADVISE64_64:    return new_sys<FAdviseSystemCall>(nr);
	case SystemCallNr::UMASK:           return new_sys<UmaskSystemCall>();
	case SystemCallNr::OLDOLDUNAME:     /* fallthrough */
	case SystemCallNr::OLDUNAME:        /* fallthrough */
	case SystemCallNr::UNAME:           return new_sys<UnameSystemCall>(nr);
	case SystemCallNr::READLINK:        return new_sys<ReadLinkSystemCall>();
	case SystemCallNr::READLINKAT:      return new_sys<ReadLinkAtSystemCall>();
	case SystemCallNr::PIDFD_OPEN:      return new_sys<PIDFDOpenSystemCall>();
	case SystemCallNr::PIDFD_GETFD:     return new_sys<PIDFDGetFDSystemCall>();
	case SystemCallNr::PIDFD_SEND_SIGNAL: return new_sys<PIDFDSendSignalSystemCall>();
	case SystemCallNr::EVENTFD:         return new_sys<EventFDSystemCall>();
	case SystemCallNr::EVENTFD2:        return new_sys<EventFD2SystemCall>();
	case SystemCallNr::AFS_SYSCALL:     [[fallthrough]];
	case SystemCallNr::PUTPMSG:
	case SystemCallNr::GETPMSG:
	case SystemCallNr::VSERVER:
	case SystemCallNr::BREAK:
	case SystemCallNr::FTIME:
	case SystemCallNr::GTTY:
	case SystemCallNr::LOCK:
	case SystemCallNr::MPX:
	case SystemCallNr::PROF:
	case SystemCallNr::ULIMIT:
	case SystemCallNr::STTY:
	case SystemCallNr::SECURITY:
	case SystemCallNr::TUXCALL:         return new_sys<DroppedSystemCall>(nr);
	case SystemCallNr::STATFS:          [[ fallthrough ]];
	case SystemCallNr::STATFS64:        return new_sys<StatFSSystemCall>(nr);
	case SystemCallNr::FSTATFS:         [[ fallthrough ]];
	case SystemCallNr::FSTATFS64:       return new_sys<FStatFSSystemCall>(nr);
	case SystemCallNr::SIGNALFD:        return new_sys<SignalFDSystemCall>();
	case SystemCallNr::SIGNALFD4:       return new_sys<SignalFD4SystemCall>();
	case SystemCallNr::SELECT:          [[ fallthrough ]];
	case SystemCallNr::NEWSELECT:       return new_sys<SelectSystemCall>(nr);
	case SystemCallNr::PSELECT6:        [[ fallthrough ]];
	case SystemCallNr::PSELECT6_TIME64: return new_sys<PSelectSystemCall>(nr);
	case SystemCallNr::EPOLL_CREATE:    [[ fallthrough ]];
	case SystemCallNr::EPOLL_CREATE1:   return new_sys<EPollCreateSystemCall>(nr);
	case SystemCallNr::DUP:             return new_sys<DupSystemCall>();
	case SystemCallNr::DUP2:            return new_sys<Dup2SystemCall>();
	case SystemCallNr::DUP3:            return new_sys<Dup3SystemCall>();
	default: {
		if (nr == SystemCallNr::UNKNOWN) {
			/* either a new system call we don't know about yet,
			 * or an invalid system call number */
			return new_sys<UnknownSystemCall>(nr);
		} else {
			/* known but not yet implemented system call */
			return new_sys<NotImplementedSystemCall>(nr);
		}
	}}
}

} // end anon ns

SystemCallPtr SystemCallDB::get(const SystemCallInfo &info) {
	const auto nr = info.sysNr();

	if (auto it = m_map.find(nr); it != m_map.end()) {
		return it->second;
	} else {
		auto [syscall, do_cache] = create_syscall(info);

		if (do_cache) {
			auto res = m_map.insert(std::make_pair(nr, syscall));
			it = res.first;
			return it->second;
		} else {
			/*
			 * For a few multi-personality system calls (i.e.
			 * highly overloaded system calls in an ioctl() style)
			 * we are using multiple specializes types to reduce
			 * the complexity of individual classes. The current
			 * caching scheme doesn't allow this, since we expect
			 * a 1:1 relationship between system call nr and
			 * system call type.
			 *
			 * For the moment simply disable caching for these
			 * instances, which are expect to be few. In the
			 * future we could decide to go for a std::multimap
			 * cache data structure, where each instance in the
			 * bucket needs to be checked whether it is suitable
			 * for the current `info` context.
			 */
			return syscall;
		}
	}
}

} // end ns
