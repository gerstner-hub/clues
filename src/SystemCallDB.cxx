// clues
#include "clues/SystemCallDB.hxx"
#include "clues/Parameters.hxx"

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
		std::pair<iterator, bool> res;
		res = insert(
			std::make_pair(
				nr,
				createSysCall(nr)
			)
		);

		it = res.first;
	}

	return *(it->second);
}

SystemCall* SystemCallDB::createSysCall(
	const SystemCallNr nr)
{
	typedef SystemCall Call;

	switch( nr )
	{
	case SYS_write:
		return new Call(nr, "write",
			new ValueOutParameter("bytes written"),
			{
				new FileDescriptorParameter(),
				new GenericPointerParameter("source buffer"),
				new ValueInParameter("buffer length")
			}
		);
	case SYS_read:
		return new Call(nr, "read",
			new ValueOutParameter("bytes read"),
			{
				new FileDescriptorParameter(),
				new GenericPointerParameter("target buffer", GenericPointerParameter::OUT),
				new ValueInParameter("buffer length")
			}
		);
	case SYS_brk:
		return new Call(nr, "brk",
			new GenericPointerParameter("actual data segment end"),
			{
				new GenericPointerParameter("requested data segment end")
			}
		);
	case SYS_nanosleep:
		return new Call(nr, "nanosleep",
			new ErrnoResult(),
			{
				new TimespecParameter("requested"),
				new TimespecParameter("remaining", TimespecParameter::OUT)
			}
		);
	case SYS_alarm:
		return new Call(nr, "alarm",
			new ValueOutParameter("prev_remaining_seconds"),
			{
				new ValueInParameter("seconds")
			}
		);
	case SYS_access:
		return new Call(nr, "access",
			new ErrnoResult(),
			{
				new StringParameter("filename"),
				new ValueInParameter("mode")
			}
		);
	case SYS_fcntl:
		return new Call(nr, "fcntl",
			new ErrnoResult(),
			{
				new FileDescriptorParameter(),
				new ValueInParameter("command")
			}
		);
	case SYS_fstat:
		return new Call(nr, "fstat",
			new ErrnoResult(),
			{
				new FileDescriptorParameter(),
				new StatParameter()
			}
		);
	case SYS_lstat:
	case SYS_stat:
		return new Call(nr, nr == SYS_stat ? "stat" : "lstat",
			new ErrnoResult(),
			{
				new StringParameter("pathname"),
				new StatParameter()
			}
		);
	case SYS_mmap:
		return new Call(nr, "mmap",
			new GenericPointerParameter("new_memory", GenericPointerParameter::OUT),
			{
				new GenericPointerParameter("hint"),
				new ValueInParameter("length"),
				new ValueInParameter("protocol"),
				new ValueInParameter("flags"),
				new FileDescriptorParameter(),
				new ValueInParameter("offset")
			}
		);
	case SYS_munmap:
		return new Call(nr, "munmap",
			new ErrnoResult(),
			{
				new GenericPointerParameter("memory"),
				new ValueInParameter("length")
			}
		);
	case SYS_mprotect:
		return new Call(nr, "mprotect",
			new ErrnoResult(),
			{
				new GenericPointerParameter("addr"),
				new ValueInParameter("length"),
				new MemoryProtectionParameter()
			}
		);
	case SYS_arch_prctl:
		return new Call(nr, "arch_prctl",
			new ErrnoResult(),
			{
				new ArchCodeParameter(),
				new GenericPointerParameter("addr")
			}
		);
	case SYS_open:
		return new Call(nr, "open",
			new FileDescriptorParameter(
				FileDescriptorParameter::OUT,
				false /* at semantics */,
				true /* error semantics */),
			{
				new StringParameter("filename"),
				new OpenFlagsParameter(),
				new FileModeParameter()
			},
			0 // number of parameter that is the to-be-opened ID
		);
	case SYS_openat:
		return new Call(nr, "openat",
			new FileDescriptorParameter(
				FileDescriptorParameter::OUT,
				false /* at semantics */,
				true /* error semantics */),
			{
				new FileDescriptorParameter(
					FileDescriptorParameter::IN,
					true /* at semantics */),
				new StringParameter("filename"),
				new OpenFlagsParameter(),
				new FileModeParameter()
			}
		);
	case SYS_close:
		return new Call(nr, "close",
			new ErrnoResult(),
			{
				new FileDescriptorParameter()
			},
			SIZE_MAX,
			0 // number of parameter that is the to-be-closed fd
		);
	case SYS_rt_sigaction:
		return new Call(nr, "rt_sigaction",
			new ErrnoResult(),
			{
				new SignalParameter(),
				new SigactionParameter(),
				new SigactionParameter("old_action")
			}
		);
	case SYS_rt_sigprocmask:
		return new Call(nr, "rt_sigprocmask",
			new ErrnoResult(),
			{
				new SigSetOperation(),
				new SigSetParameter("new_mask"),
				new SigSetParameter("old_mask"),
				new ValueInParameter("sigset_t size")
			}
		);
	case SYS_clone:
		/*
		 * NOTE: the order of parameters for clone differs between
		 * architectures
		 */
		return new Call(nr, "clone",
			new ErrnoResult(-1, "child PID"),
			{
				new ValueInParameter("flags"),
				new GenericPointerParameter("stack address", SystemCallParameter::IN),
				new GenericPointerParameter("parent thread ID", SystemCallParameter::OUT),
				new GenericPointerParameter("child thread ID", SystemCallParameter::OUT),
				new GenericPointerParameter("regs", SystemCallParameter::IN)
			}
		);
	case SYS_fork:
		return new Call(nr, "fork",
			new ErrnoResult(-1, "child PID"),
			{}
		);
	case SYS_execve:
		return new Call(nr, "execve",
			new ErrnoResult(),
			{
				new StringParameter("filename"),
				new StringArrayParameter("argv"),
				new StringArrayParameter("envp")
			}
		);
	case SYS_ioctl:
		return new Call(nr, "ioctl",
			new ErrnoResult(),
			{
				new FileDescriptorParameter(),
				new GenericPointerParameter("request")
			}
		);
	case SYS_getdents:
		return new Call(nr, "getdents",
			new ErrnoResult(-1, "size of dirent"),
			{
				new FileDescriptorParameter(),
				new DirEntries(),
				new ValueInParameter("dirent_size")
			}
		);
	case SYS_getuid:
	case SYS_geteuid:
	{
		return new Call(
			nr,
			nr == SYS_getuid ? "getuid" : "geteuid",
			new ValueOutParameter("id"),
			{}
		);
	}
	case SYS_set_tid_address:
		return new Call(nr, "set_tid_address",
			new ValueOutParameter("thread id"),
			{
				new GenericPointerParameter("thread ID location")
			}
		);
	case SYS_get_robust_list:
		return new Call(nr, "get_robust_list",
			new ErrnoResult(),
			{
				new ValueInParameter("thread id"),
				new GenericPointerParameter("robust_list_head"),
				// TODO: new parameter type that also prints
				// the size value at the pointed to address
				new GenericPointerParameter("len_ptr")
			}
		);
	case SYS_set_robust_list:
		return new Call(nr, "set_robust_list",
			new ErrnoResult(),
			{
				new GenericPointerParameter("robust_list_head"),
				new ValueInParameter("len")
			}
		);
	case SYS_futex:
		return new Call(nr, "futex",
			// TODO: requires context-sensitive interpr. of the
			// non-error returns (the FutexOperation is the
			// necessary context)
			// TODO: allows for a number of additional operations
			// that aren't well documented
			new ErrnoResult(-1, "processes woken up"),
			{
				new GenericPointerParameter("futex_int"),
				new FutexOperation(),
				new ValueInParameter("val"),
				new TimespecParameter("timeout"),
				new GenericPointerParameter("requeue_futex"),
				new ValueInParameter("requeue_check_val")
			}
		);
	case SYS_getrlimit:
		return new Call(nr, "getrlimit",
			new ErrnoResult(),
			{
				new ResourceType(),
				new ResourceLimit()
			}
		);
	default:
		return new Call(nr, "unknown",
			new ValueOutParameter("result"),
			{} );
	}
}

} // end ns

