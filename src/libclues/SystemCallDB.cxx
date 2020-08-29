// clues
#include "clues/SystemCallDB.hxx"
#include "clues/values.hxx"

// Linux
#include <sys/syscall.h> // system call nr. constants

namespace clues
{

SystemCallDB::~SystemCallDB()
{
	for( auto &pair: *this )
	{
		delete pair.second;
	}

	this->clear();
}

SystemCall& SystemCallDB::get(const SystemCallNr nr)
{
	iterator it = find(nr);

	if( it == end() )
	{
		auto res = insert(
			std::make_pair(nr, createSysCall(nr))
		);

		it = res.first;
	}

	return *(it->second);
}

SystemCall* SystemCallDB::createSysCall(const SystemCallNr nr)
{
	typedef SystemCall Call;
	typedef SystemCallValue::Type ValueType;

	switch( nr )
	{
	case SYS_write:
		return new Call(nr, "write",
			{
				new FileDescriptorParameter(),
				new GenericPointerValue("buf", "source buffer"),
				new ValueInParameter("count", "buffer length")
			},
			new ReturnValue("written", "bytes written")
		);
	case SYS_read:
		return new Call(nr, "read",
			{
				new FileDescriptorParameter(),
				new GenericPointerValue("buf", "target buffer", ValueType::PARAM_OUT),
				new ValueInParameter("count", "buffer length")
			},
			new ReturnValue("read", "bytes read")
		);
	case SYS_brk:
		return new Call(nr, "brk",
			{
				new GenericPointerValue("addr", "requested data segment end")
			},
			new GenericPointerValue("addr", "actual data segment end", ValueType::RETVAL)
		);
	case SYS_nanosleep:
		return new Call(nr, "nanosleep",
			{
				new TimespecParameter("req", "requested"),
				new TimespecParameter("rem", "remaining", ValueType::PARAM_OUT)
			},
			new ErrnoResult()
		);
	case SYS_access:
		return new Call(nr, "access",
			{
				new StringData("path"),
				new ValueInParameter("mode")
			},
			new ErrnoResult()
		);
	case SYS_fcntl:
		return new Call(nr, "fcntl",
			{
				new FileDescriptorParameter(),
				new ValueInParameter("cmd", "command")
				/* TODO: Wolpertinger parameter */
			},
			new ErrnoResult()
		);
	case SYS_fstat:
		return new Call(nr, "fstat",
			{
				new FileDescriptorParameter(),
				new StatParameter()
			},
			new ErrnoResult()
		);
	case SYS_lstat:
	case SYS_stat:
		return new Call(nr, nr == SYS_stat ? "stat" : "lstat",
			{
				new StringData("path"),
				new StatParameter()
			},
			new ErrnoResult()
		);
#ifdef __x86_64__
	case SYS_alarm:
		return new Call(nr, "alarm",
			{
				new ValueInParameter("seconds")
			},
			new ValueOutParameter("old_seconds", "remaining seconds for previous timer")
		);
	case SYS_mmap:
		return new Call(nr, "mmap",
			{
				new GenericPointerValue("hint", "address placement hint"),
				new ValueInParameter("len", "length"),
				new ValueInParameter("prot", "protocol"),
				new ValueInParameter("flags"),
				new FileDescriptorParameter(),
				new ValueInParameter("offset")
			},
			new GenericPointerValue("addr", "mapped memory address", SystemCallValue::Type::PARAM_OUT)
		);
	case SYS_arch_prctl:
		return new Call(nr, "arch_prctl",
			{
				new ArchCodeParameter(),
				new GenericPointerValue("addr", "request code ('set') or return pointer ('get')")
			},
			new ErrnoResult()
		);
	case SYS_getrlimit:
		return new Call(nr, "getrlimit",
			{
				new ResourceType(),
				new ResourceLimit()
			},
			new ErrnoResult()
		);
#endif
	case SYS_munmap:
		return new Call(nr, "munmap",
			{
				new GenericPointerValue("addr", "memory addr to unmap"),
				new ValueInParameter("len", "length")
			},
			new ErrnoResult()
		);
	case SYS_mprotect:
		return new Call(nr, "mprotect",
			{
				new GenericPointerValue("addr"),
				new ValueInParameter("length"),
				new MemoryProtectionParameter()
			},
			new ErrnoResult()
		);
	case SYS_open:
		return new Call(nr, "open",
			{
				new StringData("filename"),
				new OpenFlagsValue(),
				new FileModeParameter()
			},
			new FileDescriptorReturnValue(),
			0 // number of parameter that is the to-be-opened ID
		);
	case SYS_openat:
		return new Call(nr, "openat",
			{
				new FileDescriptorParameter(true),
				new StringData("filename"),
				new OpenFlagsValue(),
				new FileModeParameter()
			},
			new FileDescriptorReturnValue()
		);
	case SYS_close:
		return new Call(nr, "close",
			{
				new FileDescriptorParameter()
			},
			new ErrnoResult(),
			SIZE_MAX,
			0 // number of parameter that is the to-be-closed fd
		);
	case SYS_rt_sigaction:
		return new Call(nr, "rt_sigaction",
			{
				new SignalNumber(),
				new SigactionParameter(),
				new SigactionParameter("old_action")
			},
			new ErrnoResult()
		);
	case SYS_rt_sigprocmask:
		return new Call(nr, "rt_sigprocmask",
			{
				new SigSetOperation(),
				new SigSetParameter("new_mask"),
				new SigSetParameter("old_mask"),
				new ValueInParameter("size", "size of signal sets in bytes")
			},
			new ErrnoResult()
		);
	case SYS_clone:
		/*
		 * NOTE: the order of parameters for clone differs between
		 * architectures
		 */
		return new Call(nr, "clone",
			{
				new ValueInParameter("flags", "clone flags"),
				new GenericPointerValue("stack", "stack address"),
				new GenericPointerValue("parent tid", "parent thread id", GenericPointerValue::Type::PARAM_OUT),
				new GenericPointerValue("child tid", "child thread id", GenericPointerValue::Type::PARAM_OUT),
				new GenericPointerValue("tls", "thread local storage")
			},
			new ErrnoResult(-1, "child PID")
		);
	case SYS_fork:
		return new Call(nr, "fork",
			{},
			new ErrnoResult(-1, "child PID")
		);
	case SYS_execve:
		return new Call(nr, "execve",
			{
				new StringData("filename"),
				new StringArrayData("argv", "argument vector"),
				new StringArrayData("envp", "environment block pointer")
			},
			new ErrnoResult()
		);
	case SYS_ioctl:
		return new Call(nr, "ioctl",
			{
				new FileDescriptorParameter(),
				new GenericPointerValue("request", "ioctl request number")
			},
			new ErrnoResult()
		);
	case SYS_getdents:
		return new Call(nr, "getdents",
			{
				new FileDescriptorParameter(),
				new DirEntries(),
				new ValueInParameter("size", "dirent size in bytes")
			},
			new ErrnoResult(-1, "size of dirent")
		);
	case SYS_getuid:
	case SYS_geteuid:
	{
		return new Call(
			nr,
			nr == SYS_getuid ? "getuid" : "geteuid",
			{},
			new ValueOutParameter("id", nr == SYS_getuid ? "real user ID" : "effective user ID")
		);
	}
	case SYS_set_tid_address:
		return new Call(nr, "set_tid_address",
			{
				new GenericPointerValue("thread ID location")
			},
			new ValueOutParameter("tid", "caller thread ID")
		);
	case SYS_get_robust_list:
		return new Call(nr, "get_robust_list",
			{
				new ValueInParameter("tid", "thread id"),
				new GenericPointerValue("robust_list_head"),
				// TODO: new parameter type that also prints
				// the size value at the pointed to address
				new GenericPointerValue("len_ptr")
			},
			new ErrnoResult()
		);
	case SYS_set_robust_list:
		return new Call(nr, "set_robust_list",
			{
				new GenericPointerValue("robust_list_head"),
				new ValueInParameter("len")
			},
			new ErrnoResult()
		);
	case SYS_futex:
		return new Call(nr, "futex",
			// TODO: requires context-sensitive interpr. of the
			// non-error returns (the FutexOperation is the
			// necessary context)
			// TODO: allows for a number of additional operations
			// that aren't well documented
			{
				new GenericPointerValue("futex_int"),
				new FutexOperation(),
				new ValueInParameter("val"),
				new TimespecParameter("timeout"),
				new GenericPointerValue("requeue_futex"),
				new ValueInParameter("requeue_check_val")
			},
			new ErrnoResult(-1, "nwokenup", "processes woken up")
		);
	default:
		return new Call(nr, "unknown",
			{},
			new ValueOutParameter("result", nullptr)
		);
	}
}

} // end ns

