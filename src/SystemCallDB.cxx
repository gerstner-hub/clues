// generated
#include <clues/syscallnrs.h>

// clues
#include <clues/SystemCallDB.hxx>
#include <clues/values.hxx>

namespace clues {

const char* SystemCallDB::sysCallLabel(const SystemCallNr nr) {
	return SYSTEM_CALL_NAMES[cosmos::to_integral(nr)];
}

SystemCallDB::~SystemCallDB() {
	for (auto pair: *this) {
		delete pair.second;
	}

	this->clear();
}

SystemCall& SystemCallDB::get(const SystemCallNr nr) {
	iterator it = find(nr);

	if (it == end()) {
		auto res = insert(std::make_pair(nr, createSysCall(nr)));

		it = res.first;
	}

	return *(it->second);
}

SystemCall* SystemCallDB::createSysCall(const SystemCallNr nr) {
	using ValueType = SystemCallValue::Type;

	auto NewCall = [nr](SystemCall::ParameterVector &&pars,
			SystemCallValue *ret = nullptr, const size_t open_id_par = SIZE_MAX,
			const size_t close_fd_par = SIZE_MAX) {
		const auto LABEL = sysCallLabel(nr);
		return new SystemCall{nr, LABEL, std::move(pars), ret, open_id_par, close_fd_par};
	};

	switch (nr) {
	case SystemCallNr::WRITE:
		return NewCall({
				new FileDescriptorParameter{},
				new GenericPointerValue{"buf", "source buffer"},
				new ValueInParameter{"count", "buffer length"}
			},
			new ReturnValue{"written", "bytes written"}
		);
	case SystemCallNr::READ:
		return NewCall({
				new FileDescriptorParameter{},
				new GenericPointerValue{"buf", "target buffer", ValueType::PARAM_OUT},
				new ValueInParameter{"count", "buffer length"}
			},
			new ReturnValue{"read", "bytes read"}
		);
	case SystemCallNr::BRK:
		return NewCall({
				new GenericPointerValue{"addr", "requested data segment end"}
			},
			new GenericPointerValue{"addr", "actual data segment end", ValueType::RETVAL}
		);
	case SystemCallNr::NANOSLEEP:
		return NewCall({
				new TimespecParameter{"req", "requested"},
				new TimespecParameter{"rem", "remaining", ValueType::PARAM_OUT}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::ACCESS:
		return NewCall({
				new StringData{"path"},
				new AccessModeParameter{}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::FCNTL:
		return NewCall({
				new FileDescriptorParameter{},
				new ValueInParameter{"cmd", "command"}
				/* TODO: Wolpertinger parameter */
			},
			new ErrnoResult{}
		);
	case SystemCallNr::FSTAT:
		return NewCall({
				new FileDescriptorParameter{},
				new StatParameter{}
			},
			new ErrnoResult()
		);
	case SystemCallNr::LSTAT:
	case SystemCallNr::STAT:
		return NewCall({
				new StringData{"path"},
				new StatParameter{}
			},
			new ErrnoResult{}
		);
#ifdef __x86_64__
	case SystemCallNr::ALARM:
		return NewCall({
				new ValueInParameter{"seconds"}
			},
			new ValueOutParameter{"old_seconds", "remaining seconds for previous timer"}
		);
	case SystemCallNr::MMAP:
		return NewCall({
				new GenericPointerValue{"hint", "address placement hint"},
				new ValueInParameter{"len", "length"},
				new ValueInParameter{"prot", "protocol"},
				new ValueInParameter{"flags"},
				new FileDescriptorParameter{},
				new ValueInParameter{"offset"}
			},
			new GenericPointerValue{"addr", "mapped memory address", SystemCallValue::Type::PARAM_OUT}
		);
	case SystemCallNr::ARCH_PRCTL:
		return NewCall({
				new ArchCodeParameter{},
				new GenericPointerValue{"addr", "request code ('set') or return pointer ('get')"}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::GETRLIMIT:
		return NewCall({
				new ResourceType{},
				new ResourceLimit{}
			},
			new ErrnoResult{}
		);
#endif
	case SystemCallNr::MUNMAP:
		return NewCall({
				new GenericPointerValue{"addr", "memory addr to unmap"},
				new ValueInParameter{"len", "length"}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::MPROTECT:
		return NewCall({
				new GenericPointerValue{"addr"},
				new ValueInParameter{"length"},
				new MemoryProtectionParameter{}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::OPEN:
		return NewCall({
				new StringData{"filename"},
				new OpenFlagsValue{},
				new FileModeParameter{}
			},
			new FileDescriptorReturnValue{},
			0 // number of parameter that is the to-be-opened ID
		);
	case SystemCallNr::OPENAT:
		return NewCall({
				new FileDescriptorParameter{true},
				new StringData{"filename"},
				new OpenFlagsValue{},
				new FileModeParameter{}
			},
			new FileDescriptorReturnValue{}
		);
	case SystemCallNr::CLOSE:
		return NewCall({
				new FileDescriptorParameter{}
			},
			new ErrnoResult{},
			SIZE_MAX,
			0 // number of parameter that is the to-be-closed fd
		);
	case SystemCallNr::RT_SIGACTION:
		return NewCall({
				new SignalNumber{},
				new SigactionParameter{},
				new SigactionParameter{"old_action"}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::RT_SIGPROCMASK:
		return NewCall({
				new SigSetOperation{},
				new SigSetParameter{"new_mask"},
				new SigSetParameter{"old_mask"},
				new ValueInParameter{"size", "size of signal sets in bytes"}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::CLONE:
		/*
		 * NOTE: the order of parameters for clone differs between
		 * architectures
		 */
		return NewCall({
				new ValueInParameter{"flags", "clone flags"},
				new GenericPointerValue{"stack", "stack address"},
				new GenericPointerValue{"parent tid", "parent thread id", GenericPointerValue::Type::PARAM_OUT},
				new GenericPointerValue{"child tid", "child thread id", GenericPointerValue::Type::PARAM_OUT},
				new GenericPointerValue{"tls", "thread local storage"}
			},
			new ErrnoResult(-1, "child PID")
		);
	case SystemCallNr::FORK:
		return NewCall({
			},
			new ErrnoResult{-1, "child PID"}
		);
	case SystemCallNr::EXECVE:
		return NewCall({
				new StringData{"filename"},
				new StringArrayData{"argv", "argument vector"},
				new StringArrayData{"envp", "environment block pointer"}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::IOCTL:
		return NewCall({
				new FileDescriptorParameter{},
				new GenericPointerValue{"request", "ioctl request number"}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::GETDENTS:
		return NewCall({
				new FileDescriptorParameter{},
				new DirEntries{},
				new ValueInParameter{"size", "dirent size in bytes"}
			},
			new ErrnoResult{-1, "size of dirent"}
		);
	case SystemCallNr::GETUID:
	case SystemCallNr::GETEUID: {
		const bool is_uid = nr == SystemCallNr{SYS_getuid};
		return NewCall({
			},
			new ValueOutParameter{"id", is_uid ? "real user ID" : "effective user ID"}
		);
	}
	case SystemCallNr::SET_TID_ADDRESS:
		return NewCall({
				new GenericPointerValue{"thread ID location"}
			},
			new ValueOutParameter{"tid", "caller thread ID"}
		);
	case SystemCallNr::GET_ROBUST_LIST:
		return NewCall({
				new ValueInParameter{"tid", "thread id"},
				new GenericPointerValue{"robust_list_head"},
				// TODO: new parameter type that also prints
				// the size value at the pointed to address
				new GenericPointerValue{"len_ptr"}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::SET_ROBUST_LIST:
		return NewCall({
				new GenericPointerValue{"robust_list_head"},
				new ValueInParameter{"len"}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::FUTEX:
		return NewCall({
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
			new ErrnoResult{-1, "nwokenup", "processes woken up"}
		);
	case SystemCallNr::TGKILL:
		return NewCall({
				new ValueInParameter("tgid"),
				new ValueInParameter("tid"),
				new SignalNumber{},
			},
			new ErrnoResult{}
		);
	case SystemCallNr::CLOCK_NANOSLEEP:
		return NewCall({
				new ClockID{},
				new ClockNanoSleepFlags{},
				new TimespecParameter{"req", "requested"},
				// TODO: this is only filled in if the call failed with EINTR
				new TimespecParameter{"rem", "remaining", ValueType::PARAM_OUT}
			},
			new ErrnoResult{}
		);
	case SystemCallNr::RESTART_SYSCALL:
		return NewCall({
			},
			new ErrnoResult{}
		);
	default:
		return NewCall({
			},
			new ValueOutParameter{"result", nullptr}
		);
	}
}

} // end ns
