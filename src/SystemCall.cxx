// C++
#include <cassert>

// cosmos
#include <cosmos/error/errno.hxx>
#include <cosmos/io/ILogger.hxx>

// clues
#include <clues/clues.hxx>
#include <clues/items/items.hxx>
#include <clues/SystemCallDB.hxx>
#include <clues/SystemCall.hxx>
#include <clues/SystemCallItem.hxx>
#include <clues/types.hxx>

// generated
#include <clues/syscallnrs.h>

namespace clues {

SystemCall::SystemCall(
		const SystemCallNr nr,
		const char *name,
		ParameterVector &&pars,
		SystemCallItem *ret,
		const size_t open_id_par,
		const size_t close_fd_par) :
		m_nr{nr}, m_name{name}, m_return{ret}, m_pars{pars},
		m_open_id_par{open_id_par}, m_close_fd_par{close_fd_par} {

	assert(open_id_par == SIZE_MAX || open_id_par < m_pars.size());
	assert(close_fd_par == SIZE_MAX || close_fd_par < m_pars.size());

	for (auto &par: m_pars)
		par->setSystemCall(*this);
}

SystemCall::~SystemCall() {
	while (!m_pars.empty()) {
		delete m_pars.back();
		m_pars.pop_back();
	}

	delete m_return;
}

void SystemCall::setEntryInfo(const Tracee &proc, const cosmos::ptrace::SyscallInfo::EntryInfo &info) {
	auto args = info.args();
	for (size_t numpar = 0; numpar < m_pars.size(); numpar++) {
		auto &par = *m_pars[numpar];
		par.fill(proc, Word{args[numpar]});
	}

	m_error.reset();
}

void SystemCall::setExitInfo(const Tracee &proc, const cosmos::ptrace::SyscallInfo::ExitInfo &info) {
	if (info.isValue()) {
		m_return->fill(proc, Word{static_cast<uint64_t>(*info.retVal())});
	} else {
		m_error = item::ErrnoResult{};
		// TODO: makes no sense to cast the Errno back to a Word just
		// for ErrnoResult to reverse the effect. We need a dedicated
		// type for this situation.
		auto raw_errno = cosmos::to_integral(*info.errVal());
		m_error->fill(proc, Word{raw_errno >= 0 ? static_cast<elf_greg_t>(-raw_errno) : 0});
	}

	for (auto &par: m_pars) {
		if (par->needsUpdate()) {
			par->updateData(proc);
		}
	}
}

void SystemCall::updateOpenFiles(DescriptorPathMapping &mapping) {
	// TODO: this implementation is not finished / not sane yet.
	if (m_open_id_par != SIZE_MAX) {
		const int new_fd = (int)m_return->value();

		if (new_fd < 0)
			return;

		auto res = mapping.insert(
			std::make_pair(new_fd, m_pars[m_open_id_par]->str())
		);

		if (!res.second) {
			LOG_DEBUG("WARNING: file descriptor already open?!");
		}
	} else if(m_close_fd_par != SIZE_MAX) {
		if (m_return->valueAs<cosmos::Errno>() != cosmos::Errno::NO_ERROR)
			// unsuccessful system call, so don't update anything
			return;

		const int closed_fd = (int)m_pars[m_close_fd_par]->value();

		if (mapping.erase(closed_fd) == 0) {
#if 0
			// this is stdout, stderr & friends
			LOG_WARN("closed file that wasn't open?!");
#endif
		}
	} else {
		return;
	}

	//std::cout << "New path mapping:\n" << mapping << std::endl;
}

SystemCallPtr create_syscall(const SystemCallNr nr) {
	using namespace item;
	using ValueType = SystemCallItem::Type;

	auto new_call = [nr](SystemCall::ParameterVector &&pars,
			SystemCallItem *ret = nullptr, const size_t open_id_par = SIZE_MAX,
			const size_t close_fd_par = SIZE_MAX) {
		const auto LABEL = SYSTEM_CALL_NAMES[cosmos::to_integral(nr)];
		return std::make_shared<SystemCall>(nr, LABEL, std::move(pars), ret, open_id_par, close_fd_par);
	};

	switch (nr) {
	case SystemCallNr::WRITE:
		return new_call({
				new FileDescriptorParameter{},
				new GenericPointerValue{"buf", "source buffer"},
				new ValueInParameter{"count", "buffer length"}
			},
			new ReturnValue{"bytes", "bytes written"}
		);
	case SystemCallNr::READ:
		return new_call({
				new FileDescriptorParameter{},
				new GenericPointerValue{"buf", "target buffer", ValueType::PARAM_OUT},
				new ValueInParameter{"count", "buffer length"}
			},
			new ReturnValue{"bytes", "bytes read"}
		);
	case SystemCallNr::BRK:
		return new_call({
				new GenericPointerValue{"addr", "requested data segment end"}
			},
			new GenericPointerValue{"addr", "actual data segment end", ValueType::RETVAL}
		);
	case SystemCallNr::NANOSLEEP:
		return new_call({
				new TimespecParameter{"req", "requested"},
				new TimespecParameter{"rem", "remaining", ValueType::PARAM_OUT}
			},
			new SuccessResult{}
		);
	case SystemCallNr::ACCESS:
		return new_call({
				new StringData{"path"},
				new AccessModeParameter{}
			},
			new SuccessResult{}
		);
	case SystemCallNr::FCNTL:
		return new_call({
				new FileDescriptorParameter{},
				new ValueInParameter{"cmd", "command"}
				/* TODO: Wolpertinger parameter */
			},
			/* TODO: needs dedicated type */
			new SuccessResult{}
		);
	case SystemCallNr::FSTAT:
		return new_call({
				new FileDescriptorParameter{},
				new StatParameter{}
			},
			new SuccessResult()
		);
	case SystemCallNr::LSTAT:
	case SystemCallNr::STAT:
		return new_call({
				new StringData{"path"},
				new StatParameter{}
			},
			new SuccessResult{}
		);
#ifdef __x86_64__
	case SystemCallNr::ALARM:
		return new_call({
				new ValueInParameter{"seconds"}
			},
			new ValueOutParameter{"old_seconds", "remaining seconds for previous timer"}
		);
	case SystemCallNr::MMAP:
		return new_call({
				new GenericPointerValue{"hint", "address placement hint"},
				new ValueInParameter{"len", "length"},
				new ValueInParameter{"prot", "protocol"},
				new ValueInParameter{"flags"},
				new FileDescriptorParameter{},
				new ValueInParameter{"offset"}
			},
			new GenericPointerValue{"addr", "mapped memory address", SystemCallItem::Type::PARAM_OUT}
		);
	case SystemCallNr::ARCH_PRCTL:
		return new_call({
				new ArchCodeParameter{},
				new GenericPointerValue{"addr", "request code ('set') or return pointer ('get')"}
			},
			new SuccessResult{}
		);
	case SystemCallNr::GETRLIMIT:
		return new_call({
				new ResourceType{},
				new ResourceLimit{}
			},
			new SuccessResult{}
		);
#endif
	case SystemCallNr::MUNMAP:
		return new_call({
				new GenericPointerValue{"addr", "memory addr to unmap"},
				new ValueInParameter{"len", "length"}
			},
			new SuccessResult{}
		);
	case SystemCallNr::MPROTECT:
		return new_call({
				new GenericPointerValue{"addr"},
				new ValueInParameter{"length"},
				new MemoryProtectionParameter{}
			},
			new SuccessResult{}
		);
	case SystemCallNr::OPEN:
		return new_call({
				new StringData{"filename"},
				new OpenFlagsValue{},
				new FileModeParameter{}
			},
			new FileDescriptorReturnValue{},
			0 // number of parameter that is the to-be-opened ID
		);
	case SystemCallNr::OPENAT:
		return new_call({
				new FileDescriptorParameter{true},
				new StringData{"filename"},
				new OpenFlagsValue{},
				new FileModeParameter{}
			},
			new FileDescriptorReturnValue{}
		);
	case SystemCallNr::CLOSE:
		return new_call({
				new FileDescriptorParameter{}
			},
			new SuccessResult{},
			SIZE_MAX,
			0 // number of parameter that is the to-be-closed fd
		);
	case SystemCallNr::RT_SIGACTION:
		return new_call({
				new SignalNumber{},
				new SigactionParameter{},
				new SigactionParameter{"old_action"}
			},
			new SuccessResult{}
		);
	case SystemCallNr::RT_SIGPROCMASK:
		return new_call({
				new SigSetOperation{},
				new SigSetParameter{"new_mask"},
				new SigSetParameter{"old_mask"},
				new ValueInParameter{"size", "size of signal sets in bytes"}
			},
			new SuccessResult{}
		);
	case SystemCallNr::CLONE:
		/*
		 * NOTE: the order of parameters for clone differs between
		 * architectures
		 */
		return new_call({
				new ValueInParameter{"flags", "clone flags"},
				new GenericPointerValue{"stack", "stack address"},
				new GenericPointerValue{"parent tid", "parent thread id", GenericPointerValue::Type::PARAM_OUT},
				new GenericPointerValue{"child tid", "child thread id", GenericPointerValue::Type::PARAM_OUT},
				new GenericPointerValue{"tls", "thread local storage"}
			},
			new ValueOutParameter("pid", "child pid")
		);
	case SystemCallNr::FORK:
		return new_call({
			},
			new ValueOutParameter{"pid", "child pid"}
		);
	case SystemCallNr::EXECVE:
		return new_call({
				new StringData{"filename"},
				new StringArrayData{"argv", "argument vector"},
				new StringArrayData{"envp", "environment block pointer"}
			},
			new SuccessResult{}
		);
	case SystemCallNr::IOCTL:
		// TODO: the number of parameters can vary here.
		// can we find out during runtime if additional parameters
		// have been passed?
		// some well-known commands could be interpreted, but we don't
		// know of what type a file descriptor is, or do we?
		return new_call({
				new FileDescriptorParameter{},
				new GenericPointerValue{"request", "ioctl request number"}
			},
			/* TODO: some ioctls may return non-zero data here */
			new SuccessResult{}
		);
	case SystemCallNr::GETDENTS:
		return new_call({
				new FileDescriptorParameter{},
				new DirEntries{},
				new ValueInParameter{"size", "dirent size in bytes"}
			},
			new ValueOutParameter{"bytes", "size of dirent"}
		);
	case SystemCallNr::GETUID:
	case SystemCallNr::GETEUID: {
		const bool is_uid = nr == SystemCallNr{SYS_getuid};
		return new_call({
			},
			new ValueOutParameter{is_uid ? "uid" : "euid",
				is_uid ? "real user ID" : "effective user ID"}
		);
	}
	case SystemCallNr::SET_TID_ADDRESS:
		return new_call({
				new GenericPointerValue{"thread ID location"}
			},
			new ValueOutParameter{"tid", "caller thread ID"}
		);
	case SystemCallNr::GET_ROBUST_LIST:
		return new_call({
				new ValueInParameter{"tid", "thread id"},
				new GenericPointerValue{"robust_list_head"},
				// TODO: new parameter type that also prints
				// the size value at the pointed to address
				new GenericPointerValue{"len_ptr"}
			},
			new SuccessResult{}
		);
	case SystemCallNr::SET_ROBUST_LIST:
		return new_call({
				new GenericPointerValue{"robust_list_head"},
				new ValueInParameter{"len"}
			},
			new SuccessResult{}
		);
	case SystemCallNr::FUTEX:
		return new_call({
			// TODO: requires context-sensitive interpr. of the
			// non-error returns (the FutexOperation is the
			// necessary context)
			// TODO: allows for a number of additional operations
			// that aren't well documented
				new GenericPointerValue{"futex_int"},
				new FutexOperation{},
				new ValueInParameter{"val"},
				new TimespecParameter{"timeout"},
				new GenericPointerValue{"requeue_futex"},
				new ValueInParameter{"requeue_check_val"}
			},
			new ValueOutParameter{"nwokenup", "processes woken up"}
		);
	case SystemCallNr::TGKILL:
		return new_call({
				new ValueInParameter("tgid"),
				new ValueInParameter("tid"),
				new SignalNumber{},
			},
			new SuccessResult{}
		);
	case SystemCallNr::CLOCK_NANOSLEEP:
		return new_call({
				new ClockID{},
				new ClockNanoSleepFlags{},
				new TimespecParameter{"req", "requested"},
				// TODO: this is only filled in if the call failed with EINTR
				new TimespecParameter{"rem", "remaining", ValueType::PARAM_OUT}
			},
			new SuccessResult{}
		);
	case SystemCallNr::RESTART_SYSCALL:
		return new_call({
			},
			new SuccessResult{}
		);
	default:
		return new_call({
			},
			new ValueOutParameter{"result", nullptr}
		);
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
