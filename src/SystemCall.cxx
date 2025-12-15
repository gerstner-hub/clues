// C++
#include <cassert>

// cosmos
#include <cosmos/error/errno.hxx>
#include <cosmos/io/ILogger.hxx>

// clues
#include <clues/items/files.hxx>
#include <clues/items/futex.hxx>
#include <clues/items/items.hxx>
#include <clues/items/limits.hxx>
#include <clues/items/mmap.hxx>
#include <clues/items/prctl.hxx>
#include <clues/items/signal.hxx>
#include <clues/items/strings.hxx>
#include <clues/items/time.hxx>
#include <clues/logger.hxx>
#include <clues/sysnrs/generic.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCall.hxx>
#include <clues/SystemCallItem.hxx>
#include <clues/types.hxx>

namespace clues {

const char* SystemCall::name(const SystemCallNr nr) {
	return SYSTEM_CALL_NAMES[cosmos::to_integral(nr)].data();
}

bool SystemCall::validNr(const SystemCallNr nr) {
	return cosmos::to_integral(nr) < SYSTEM_CALL_NAMES.size();
}

SystemCall::SystemCall(
		const SystemCallNr nr,
		ParameterVector &&pars,
		SystemCallItemPtr ret) :
		m_nr{nr}, m_name{SystemCall::name(nr)},
		m_return{ret}, m_pars{pars} {

	for (auto &par: m_pars)
		par->setSystemCall(*this);

	setOpenIDPar();
	setCloseFDPar();
}

void SystemCall::setEntryInfo(const Tracee &proc,
		const cosmos::ptrace::SyscallInfo::EntryInfo &info) {
	const uint64_t *args = info.args();
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

void SystemCall::setExitInfo(const Tracee &proc,
		const cosmos::ptrace::SyscallInfo::ExitInfo &info) {
	if (info.isValue()) {
		m_return->fill(proc, Word{static_cast<Word>(*info.retVal())});
	} else {
		m_error = ErrnoResult{*info.errVal()};
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

SystemCallPtr create_syscall(const SystemCallNr nr) {
	using namespace item;
	using ItemPtr = SystemCallItemPtr;

	auto new_call = [nr](
			SystemCall::ParameterVector &&pars,
			ItemPtr ret = nullptr) {
		return std::make_shared<SystemCall>(nr, std::move(pars), ret);
	};

	switch (nr) {
	case SystemCallNr::WRITE:
		return new_call({
				ItemPtr{new FileDescriptor{}},
				ItemPtr{new GenericPointerValue{"buf", "source buffer"}},
				ItemPtr{new ValueInParameter{"count", "buffer length"}}
			},
			ItemPtr{new ReturnValue{"bytes", "bytes written"}}
		);
	case SystemCallNr::READ:
		return new_call({
				ItemPtr{new FileDescriptor{}},
				ItemPtr{new GenericPointerValue{"buf", "target buffer", ItemType::PARAM_OUT}},
				ItemPtr{new ValueInParameter{"count", "buffer length"}}
			},
			ItemPtr{new ReturnValue{"bytes", "bytes read"}}
		);
	case SystemCallNr::BRK:
		return new_call({
				ItemPtr{new GenericPointerValue{"addr", "requested data segment end"}}
			},
			ItemPtr{new GenericPointerValue{"addr", "actual data segment end", ItemType::RETVAL}}
		);
	case SystemCallNr::NANOSLEEP:
		return new_call({
				ItemPtr{new TimespecParameter{"req", "requested"}},
				ItemPtr{new TimespecParameter{"rem", "remaining", ItemType::PARAM_OUT}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::ACCESS:
		return new_call({
				ItemPtr{new StringData{"path"}},
				ItemPtr{new AccessModeParameter{}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::FCNTL:
		return new_call({
				ItemPtr{new FileDescriptor{}},
				ItemPtr{new ValueInParameter{"cmd", "command"}}
				/* TODO: Wolpertinger parameter */
			},
			/* TODO: needs dedicated type */
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::FSTAT:
		return new_call({
				ItemPtr{new FileDescriptor{}},
				ItemPtr{new StatParameter{}}
			},
			ItemPtr{new SuccessResult()}
		);
	case SystemCallNr::LSTAT:
	case SystemCallNr::STAT:
		return new_call({
				ItemPtr{new StringData{"path"}},
				ItemPtr{new StatParameter{}}
			},
			ItemPtr{new SuccessResult{}}
		);
#ifdef __x86_64__
	case SystemCallNr::ALARM:
		return new_call({
				ItemPtr{new ValueInParameter{"seconds"}}
			},
			ItemPtr{new ValueOutParameter{"old_seconds", "remaining seconds for previous timer"}}
		);
	case SystemCallNr::MMAP:
		return new_call({
				ItemPtr{new GenericPointerValue{"hint", "address placement hint"}},
				ItemPtr{new ValueInParameter{"len", "length"}},
				ItemPtr{new ValueInParameter{"prot", "protocol"}},
				ItemPtr{new ValueInParameter{"flags"}},
				ItemPtr{new FileDescriptor{}},
				ItemPtr{new ValueInParameter{"offset"}}
			},
			ItemPtr{new GenericPointerValue{"addr", "mapped memory address", ItemType::PARAM_OUT}}
		);
	case SystemCallNr::ARCH_PRCTL:
		return new_call({
				ItemPtr{new ArchCodeParameter{}},
				ItemPtr{new GenericPointerValue{"addr", "request code ('set') or return pointer ('get')"}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::GETRLIMIT:
		return new_call({
				ItemPtr{new ResourceType{}},
				ItemPtr{new ResourceLimit{}}
			},
			ItemPtr{new SuccessResult{}}
		);
#endif
	case SystemCallNr::MUNMAP:
		return new_call({
				ItemPtr{new GenericPointerValue{"addr", "memory addr to unmap"}},
				ItemPtr{new ValueInParameter{"len", "length"}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::MPROTECT:
		return new_call({
				ItemPtr{new GenericPointerValue{"addr"}},
				ItemPtr{new ValueInParameter{"length"}},
				ItemPtr{new MemoryProtectionParameter{}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::OPEN:
		return new_call({
				ItemPtr{new StringData{"filename"}},
				ItemPtr{new OpenFlagsValue{}},
				ItemPtr{new FileModeParameter{}}
			},
			ItemPtr{new FileDescriptor{ItemType::PARAM_OUT}}
		);
	case SystemCallNr::OPENAT:
		return new_call({
				ItemPtr{new FileDescriptor{ItemType::PARAM_IN, item::AtSemantics{true}}},
				ItemPtr{new StringData{"filename"}},
				ItemPtr{new OpenFlagsValue{}},
				ItemPtr{new FileModeParameter{}}
			},
			ItemPtr{new FileDescriptor{ItemType::PARAM_OUT}}
		);
	case SystemCallNr::CLOSE:
		return new_call({
				ItemPtr{new FileDescriptor{}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::RT_SIGACTION:
		return new_call({
				ItemPtr{new SignalNumber{}},
				ItemPtr{new SigactionParameter{}},
				ItemPtr{new SigactionParameter{"old_action"}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::RT_SIGPROCMASK:
		return new_call({
				ItemPtr{new SigSetOperation{}},
				ItemPtr{new SigSetParameter{"new_mask"}},
				ItemPtr{new SigSetParameter{"old_mask"}},
				ItemPtr{new ValueInParameter{"size", "size of signal sets in bytes"}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::CLONE:
		/*
		 * NOTE: the order of parameters for clone differs between
		 * architectures
		 */
		return new_call({
				ItemPtr{new ValueInParameter{"flags", "clone flags"}},
				ItemPtr{new GenericPointerValue{"stack", "stack address"}},
				ItemPtr{new GenericPointerValue{"parent tid", "parent thread id", ItemType::PARAM_OUT}},
				ItemPtr{new GenericPointerValue{"child tid", "child thread id", ItemType::PARAM_OUT}},
				ItemPtr{new GenericPointerValue{"tls", "thread local storage"}}
			},
			ItemPtr{new ValueOutParameter("pid", "child pid")}
		);
	case SystemCallNr::FORK:
		return new_call({
			},
			ItemPtr{new ValueOutParameter{"pid", "child pid"}}
		);
	case SystemCallNr::EXECVE:
		return new_call({
				ItemPtr{new StringData{"filename"}},
				ItemPtr{new StringArrayData{"argv", "argument vector"}},
				ItemPtr{new StringArrayData{"envp", "environment block pointer"}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::IOCTL:
		// TODO: the number of parameters can vary here.
		// can we find out during runtime if additional parameters
		// have been passed?
		// some well-known commands could be interpreted, but we don't
		// know of what type a file descriptor is, or do we?
		return new_call({
				ItemPtr{new FileDescriptor{}},
				ItemPtr{new GenericPointerValue{"request", "ioctl request number"}}
			},
			/* TODO: some ioctls may return non-zero data here */
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::GETDENTS:
		return new_call({
				ItemPtr{new FileDescriptor{}},
				ItemPtr{new DirEntries{}},
				ItemPtr{new ValueInParameter{"size", "dirent size in bytes"}}
			},
			ItemPtr{new ValueOutParameter{"bytes", "size of dirent"}}
		);
	case SystemCallNr::GETUID:
	case SystemCallNr::GETEUID: {
		const bool is_uid = nr == SystemCallNr{SYS_getuid};
		return new_call({
			},
			ItemPtr{new ValueOutParameter{is_uid ? "uid" : "euid",
				is_uid ? "real user ID" : "effective user ID"}}
		);
	}
	case SystemCallNr::SET_TID_ADDRESS:
		return new_call({
				ItemPtr{new GenericPointerValue{"thread ID location"}}
			},
			ItemPtr{new ValueOutParameter{"tid", "caller thread ID"}}
		);
	case SystemCallNr::GET_ROBUST_LIST:
		return new_call({
				ItemPtr{new ValueInParameter{"tid", "thread id"}},
				ItemPtr{new GenericPointerValue{"robust_list_head"}},
				// TODO: new parameter type that also prints
				// the size value at the pointed to address
				ItemPtr{new GenericPointerValue{"len_ptr"}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::SET_ROBUST_LIST:
		return new_call({
				ItemPtr{new GenericPointerValue{"robust_list_head"}},
				ItemPtr{new ValueInParameter{"len"}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::FUTEX:
		return new_call({
			// TODO: requires context-sensitive interpr. of the
			// non-error returns (the FutexOperation is the
			// necessary context)
			// TODO: allows for a number of additional operations
			// that aren't well documented
				ItemPtr{new GenericPointerValue{"futex_int"}},
				ItemPtr{new FutexOperation{}},
				ItemPtr{new ValueInParameter{"val"}},
				ItemPtr{new TimespecParameter{"timeout"}},
				ItemPtr{new GenericPointerValue{"requeue_futex"}},
				ItemPtr{new ValueInParameter{"requeue_check_val"}}
			},
			ItemPtr{new ValueOutParameter{"nwokenup", "processes woken up"}}
		);
	case SystemCallNr::TGKILL:
		return new_call({
				ItemPtr{new ValueInParameter("tgid")},
				ItemPtr{new ValueInParameter("tid")},
				ItemPtr{new SignalNumber{}},
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::CLOCK_NANOSLEEP:
		return new_call({
				ItemPtr{new ClockID{}},
				ItemPtr{new ClockNanoSleepFlags{}},
				ItemPtr{new TimespecParameter{"req", "requested"}},
				// TODO: this is only filled in if the call failed with EINTR
				ItemPtr{new TimespecParameter{"rem", "remaining", ItemType::PARAM_OUT}}
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::RESTART_SYSCALL:
		return new_call({
			},
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::EXIT_GROUP:
		return new_call({
				ItemPtr{new ValueInParameter("status", "exit code")}
			},
			// this call never returns, but since some form of
			// return item is expected simply make it a
			// SuccessResult.
			ItemPtr{new SuccessResult{}}
		);
	case SystemCallNr::WAIT4:
		return new_call({
				ItemPtr{new ValueInParameter{"pid", "pid to wait for"}},
				ItemPtr{new GenericPointerValue{"status", "ptr to status"}},
				ItemPtr{new ValueInParameter{"options", "wait options"}},
				ItemPtr{new GenericPointerValue{"rusage", "resource usage"}}
			},
			ItemPtr{new ValueOutParameter{"pid", "pid of child with status change"}}
		);
	default:
		return new_call({
			},
			ItemPtr{new ValueOutParameter{"result", {}}}
		);
	}
}

void SystemCall::setOpenIDPar() {
	switch (m_nr) {
	default: break;
	case SystemCallNr::OPEN:
		 m_open_id_par = 0; /* pathname */
		 break;
	case SystemCallNr::OPENAT:
		 m_open_id_par = 1; /* pathname comes 2nd in openat() */
		 break;
	}

	assert(!m_open_id_par || *m_open_id_par < m_pars.size());
}

void SystemCall::setCloseFDPar() {
	switch (m_nr) {
	default: break;
	case SystemCallNr::CLOSE:
		 m_close_fd_par = 0; /* the single fd parameter to close */
		 break;
	}

	assert(!m_close_fd_par || *m_close_fd_par < m_pars.size());
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
