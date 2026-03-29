// C++
#include <cassert>

// cosmos
#include <cosmos/error/errno.hxx>
#include <cosmos/io/ILogger.hxx>

// clues
#include <clues/logger.hxx>
#include <clues/syscalls/fs.hxx>
#include <clues/syscalls/io.hxx>
#include <clues/syscalls/memory.hxx>
#include <clues/syscalls/other.hxx>
#include <clues/syscalls/process.hxx>
#include <clues/syscalls/signals.hxx>
#include <clues/syscalls/thread.hxx>
#include <clues/syscalls/time.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCall.hxx>
#include <clues/SystemCallInfo.hxx>
#include <clues/SystemCallItem.hxx>
#include <clues/Tracee.hxx>
#include <clues/types.hxx>

namespace clues {

const char* SystemCall::name(const SystemCallNr nr) {
	return SYSTEM_CALL_NAMES[cosmos::to_integral(nr)].data();
}

bool SystemCall::validNr(const SystemCallNr nr) {
	return cosmos::to_integral(nr) < SYSTEM_CALL_NAMES.size();
}

SystemCall::SystemCall(const SystemCallNr nr) :
		m_nr{nr}, m_name{SystemCall::name(nr)} {
}

void SystemCall::fillParameters(const Tracee &proc, const SystemCallInfo &info) {
	const auto args = info.entryInfo()->args();
	for (size_t numpar = 0; numpar < m_pars.size(); numpar++) {
		auto &par = *m_pars[numpar];
		if (item::is_unused_par(par))
			continue;
		par.fill(proc, Word{static_cast<Word>(args[numpar])});
	}
}

void SystemCall::setEntryInfo(const Tracee &proc, const SystemCallInfo &info) {
	m_abi = info.abi();
	m_error.reset();
	m_info = &info;

	prepareNewSystemCall();

	fillParameters(proc, info);

	if (check2ndPass(proc)) {
		fillParameters(proc, info);
	}

	m_info = nullptr;
}

bool SystemCall::hasOutParameter() const {
	for (auto &par: m_pars) {
		if (par->needsUpdate())
			return true;
	}

	return false;
}

void SystemCall::setExitInfo(const Tracee &proc, const SystemCallInfo &info) {
	m_info = &info;
	const auto exit_info = *info.exitInfo();

	if (exit_info.isValue()) {
		m_return->fill(proc, Word{static_cast<Word>(*exit_info.retVal())});
	} else {
		m_error = ErrnoResult{*exit_info.errVal()};
	}

	for (auto &par: m_pars) {
		if (par->needsUpdate()) {
			par->updateData(proc);
		}
	}

	if (exit_info.isValue()) {
		updateFDTracking(proc);
	}

	m_info = nullptr;
}

// alias for creating SystemCall instances below
template <typename T, typename... Args>
std::shared_ptr<T> new_sys(Args&&... args)
{
	    return std::make_shared<T>(std::forward<Args>(args)...);
}

SystemCallPtr create_syscall(const SystemCallNr nr) {
	switch (nr) {
	case SystemCallNr::ACCESS:          return new_sys<AccessSystemCall>();
	case SystemCallNr::FACCESSAT:       return new_sys<FAccessAtSystemCall>();
	case SystemCallNr::FACCESSAT2:      return new_sys<FAccessAt2SystemCall>();
	case SystemCallNr::ALARM:           return new_sys<AlarmSystemCall>();
	case SystemCallNr::ARCH_PRCTL:      return new_sys<ArchPrctlSystemCall>();
	case SystemCallNr::BRK:             return new_sys<BreakSystemCall>();
	case SystemCallNr::CLOCK_NANOSLEEP: return new_sys<ClockNanoSleepSystemCall>();
	case SystemCallNr::CLONE:           return new_sys<CloneSystemCall>();
	case SystemCallNr::CLONE3:          return new_sys<Clone3SystemCall>();
	case SystemCallNr::CLOSE:           return new_sys<CloseSystemCall>();
	case SystemCallNr::EXECVE:          return new_sys<ExecveSystemCall>();
	case SystemCallNr::EXECVEAT:        return new_sys<ExecveAtSystemCall>();
	case SystemCallNr::EXIT_GROUP:      return new_sys<ExitGroupSystemCall>();
	case SystemCallNr::FCNTL:           [[fallthrough]];
	case SystemCallNr::FCNTL64:         return new_sys<FcntlSystemCall>(nr);
	case SystemCallNr::FORK:            return new_sys<ForkSystemCall>();
	case SystemCallNr::OLDFSTAT:        [[fallthrough]];
	case SystemCallNr::FSTAT:           [[fallthrough]];
	case SystemCallNr::FSTAT64:         return new_sys<FstatSystemCall>(nr);
	case SystemCallNr::FSTATAT64:       [[fallthrough]];
	case SystemCallNr::NEWFSTATAT:      return new_sys<FstatAtSystemCall>(nr);
	case SystemCallNr::FUTEX:           return new_sys<FutexSystemCall>();
	case SystemCallNr::GETDENTS:        [[fallthrough]];
	case SystemCallNr::GETDENTS64:      return new_sys<GetDentsSystemCall>(nr);
	case SystemCallNr::GETUID:          [[fallthrough]];
	case SystemCallNr::GETUID32:        return new_sys<GetUidSystemCall>(nr);
	case SystemCallNr::GETEGID32:       [[fallthrough]];
	case SystemCallNr::GETEGID:         return new_sys<GetEgidSystemCall>(nr);
	case SystemCallNr::GETEUID32:       [[fallthrough]];
	case SystemCallNr::GETEUID:         return new_sys<GetEuidSystemCall>(nr);
	case SystemCallNr::GETGID32:        [[fallthrough]];
	case SystemCallNr::GETGID:          return new_sys<GetGidSystemCall>(nr);
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
	case SystemCallNr::RT_SIGACTION:    [[fallthrough]];
	case SystemCallNr::SIGACTION:       return new_sys<SigActionSystemCall>(nr);
	case SystemCallNr::RT_SIGPROCMASK:  return new_sys<SigProcMaskSystemCall>();
	case SystemCallNr::SET_TID_ADDRESS: return new_sys<SetTIDAddressSystemCall>();
	case SystemCallNr::OLDSTAT:         [[fallthrough]];
	case SystemCallNr::STAT64:          [[fallthrough]];
	case SystemCallNr::STAT:            return new_sys<StatSystemCall>(nr);
	case SystemCallNr::TGKILL:          return new_sys<TgKillSystemCall>();
	case SystemCallNr::WAIT4:           return new_sys<Wait4SystemCall>();
	case SystemCallNr::WRITE:           return new_sys<WriteSystemCall>();
	case SystemCallNr::PIPE:            return new_sys<PipeSystemCall>();
	case SystemCallNr::PIPE2:           return new_sys<Pipe2SystemCall>();
	default:                            return new_sys<UnknownSystemCall>(nr);
	}
}

void SystemCall::dropFD(const Tracee &proc, const cosmos::FileNum num) {
	proc.dropFD(num);
}

void SystemCall::trackFD(const Tracee &proc, FDInfo &&info) {
	proc.trackFD(std::move(info));
}

} // end ns

std::ostream& operator<<(std::ostream &o, const clues::SystemCall &sc) {
	o << sc.name() << " (" << cosmos::to_integral(sc.callNr()) << "): " << sc.numPars() << " parameters";

	for (const auto &par: sc.m_pars) {
		o << "\n\t" << *par;
	}

	o << "\n\tResult -> " << *(sc.m_return);

	return o;
}
