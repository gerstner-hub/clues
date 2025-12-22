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
#include <clues/syscalls/time.hxx>
#include <clues/syscalls/thread.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCall.hxx>
#include <clues/SystemCallInfo.hxx>
#include <clues/SystemCallItem.hxx>
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

void SystemCall::setEntryInfo(const Tracee &proc, const SystemCallInfo &info) {
	m_abi = info.abi();

	const uint64_t *args = info.entryInfo()->args();
	for (size_t numpar = 0; numpar < m_pars.size(); numpar++) {
		auto &par = *m_pars[numpar];
		par.fill(proc, Word{static_cast<Word>(args[numpar])});
	}

	m_error.reset();
}

bool SystemCall::hasOutParameter() const {
	for (auto &par: m_pars) {
		if (par->needsUpdate())
			return true;
	}

	return false;
}

void SystemCall::setExitInfo(const Tracee &proc, const SystemCallInfo &info) {
	const auto &exit_info = *info.exitInfo();

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
}

void SystemCall::updateOpenFiles(FDInfoMap &mapping) {
	using FileNum = cosmos::FileNum;
	// TODO: this implementation is not finished / not sane yet.

	if (hasErrorCode()) {
		return;
	} else if (m_open_id_par) {
		const auto new_fd = static_cast<FileNum>(m_return->value());

		if (new_fd <= FileNum::INVALID)
			return;

		auto res = mapping.insert(
			std::make_pair(new_fd, FDInfo{})
		);

		if (!res.second) {
			LOG_WARN("file descriptor was already open?!");
			// bail out
			return;
		}

		auto &fdinfo = mapping[new_fd];
		fdinfo.fd = new_fd;
		// TODO: we need to differentiate the various types
		// this generally needs a different approach, for system call
		// specific, likely, since we also need to store the mode and
		// flags and so on.
		fdinfo.type = FDInfo::Type::FS_PATH;
		fdinfo.path = m_pars[*m_open_id_par]->str();

		LOG_DEBUG("new path mapping for fd " << cosmos::to_integral(new_fd) << " with open_id " << fdinfo.path);
	} else if (m_close_fd_par) {
		if (m_return->valueAs<cosmos::Errno>() != cosmos::Errno::NO_ERROR)
			// unsuccessful system call, so don't update anything
			return;

		const auto closed_fd = static_cast<FileNum>(
				m_pars[*m_close_fd_par]->value());

		if (mapping.erase(closed_fd) == 0) {
			LOG_WARN("closed fd wasn't open before?!");
		}

		LOG_DEBUG("removed fd " << cosmos::to_integral(closed_fd)
				<< " from registered mappings");
	}
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
	case SystemCallNr::ALARM:           return new_sys<AlarmSystemCall>();
	case SystemCallNr::ARCH_PRCTL:      return new_sys<ArchPrctlSystemCall>();
	case SystemCallNr::BRK:             return new_sys<BreakSystemCall>();
	case SystemCallNr::CLOCK_NANOSLEEP: return new_sys<ClockNanosleepSystemCall>();
	case SystemCallNr::CLONE:           return new_sys<CloneSystemCall>();
	case SystemCallNr::CLOSE:           return new_sys<CloseSystemCall>();
	case SystemCallNr::EXECVE:          return new_sys<ExecveSystemCall>();
	case SystemCallNr::EXIT_GROUP:      return new_sys<ExitGroupSystemCall>();
	case SystemCallNr::FCNTL:           return new_sys<FcntlSystemCall>();
	case SystemCallNr::FORK:            return new_sys<ForkSystemCall>();
	case SystemCallNr::FSTAT:           return new_sys<FstatSystemCall>();
	case SystemCallNr::FUTEX:           return new_sys<FutexSystemCall>();
	case SystemCallNr::GETDENTS:        return new_sys<GetdentsSystemCall>();
	case SystemCallNr::GETEGID:         return new_sys<GetEgidSystemCall>();
	case SystemCallNr::GETEUID:         return new_sys<GetEuidSystemCall>();
	case SystemCallNr::GETGID:          return new_sys<GetGidSystemCall>();
	case SystemCallNr::GETRLIMIT:       return new_sys<GetrlimitSystemCall>();
	case SystemCallNr::GET_ROBUST_LIST: return new_sys<GetRobustListSystemCall>();
	case SystemCallNr::GETUID:          return new_sys<GetUidSystemCall>();
	case SystemCallNr::IOCTL:           return new_sys<IoctlSystemCall>();
	case SystemCallNr::LSTAT:           return new_sys<LstatSystemCall>();
	case SystemCallNr::MMAP:            return new_sys<MmapSystemCall>();
	case SystemCallNr::MPROTECT:        return new_sys<MprotectSystemCall>();
	case SystemCallNr::MUNMAP:          return new_sys<MunmapSystemCall>();
	case SystemCallNr::NANOSLEEP:       return new_sys<NanosleepSystemCall>();
	case SystemCallNr::OPENAT:          return new_sys<OpenatSystemCall>();
	case SystemCallNr::OPEN:            return new_sys<OpenSystemCall>();
	case SystemCallNr::READ:            return new_sys<ReadSystemCall>();
	case SystemCallNr::RESTART_SYSCALL: return new_sys<RestartSystemCall>();
	case SystemCallNr::RT_SIGACTION:    return new_sys<SigactionSystemCall>();
	case SystemCallNr::RT_SIGPROCMASK:  return new_sys<SigprocmaskSystemCall>();
	case SystemCallNr::SET_ROBUST_LIST: return new_sys<SetRobustListSystemCall>();
	case SystemCallNr::SET_TID_ADDRESS: return new_sys<SetTidAddressSystemCall>();
	case SystemCallNr::STAT:            return new_sys<StatSystemCall>();
	case SystemCallNr::TGKILL:          return new_sys<TgKillSystemCall>();
	case SystemCallNr::WAIT4:           return new_sys<Wait4SystemCall>();
	case SystemCallNr::WRITE:           return new_sys<WriteSystemCall>();
	default:                            return new_sys<UnknownSystemCall>(nr);
	}
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
